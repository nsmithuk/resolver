package dnssec

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"slices"
)

func NewAuth(ctx context.Context, question dns.Question) *Authenticator {
	// Function map. Allows overriding for testing.
	v := &verifier{
		verifyDNSKEYs:              verifyDNSKEYs,
		verifyRRSETs:               verifyRRSETs,
		validateDelegatingResponse: validateDelegatingResponse,
		validatePositiveResponse:   validatePositiveResponse,
		validateNegativeResponse:   validateNegativeResponse,
	}

	return &Authenticator{
		ctx:      ctx,
		question: question,
		results:  make([]*result, 0, 5),
		verify:   v.verify,
	}
}

func (a *Authenticator) AddResponse(zone Zone, msg *dns.Msg) error {

	// The zone name must be an ancestor of the QName.
	if !dns.IsSubDomain(zone.Name(), a.question.Name) {
		return fmt.Errorf("%w: current zone:[%s] target qname:[%s]", ErrNotSubdomain, zone.Name(), a.question.Name)
	}

	// The current QName must be an ancestor of the target QName (or likely equal to).
	if !dns.IsSubDomain(msg.Question[0].Name, a.question.Name) {
		return fmt.Errorf("%w: current qname:[%s] target qname:[%s]", ErrNotSubdomain, zone.Name(), a.question.Name)
	}

	var last *result
	if len(a.results) == 0 {
		last = &result{dsRecords: RootTrustAnchors}
	} else {
		last = a.results[len(a.results)-1]

		if !dns.IsSubDomain(last.zone.Name(), zone.Name()) {
			return fmt.Errorf("%w: last zone:[%s] current zone:[%s]", ErrNotSubdomain, last.zone.Name(), zone.Name())
		}

		if namesEqual(last.zone.Name(), zone.Name()) {
			return fmt.Errorf("%w: last result must be a child of the previous result; they cannot be the same. both are %s", ErrSameName, zone.Name())
		}
	}

	rrsigs := extractRecords[*dns.RRSIG](slices.Concat(msg.Answer, msg.Ns))

	if len(rrsigs) > 0 && len(last.dsRecords) > 0 {
		// TODO: Sense check that all values match?
		signerName := dns.CanonicalName(rrsigs[0].SignerName)
		lastDSOwner := dns.CanonicalName(last.dsRecords[0].Header().Name)

		if lastDSOwner != signerName {
			// The signer name must be an ancestor of the QName.
			if !dns.IsSubDomain(signerName, a.question.Name) {
				return fmt.Errorf("%w: signerName:[%s] target qname:[%s]", ErrNotSubdomain, signerName, a.question.Name)
			}

			/*
				If we encounter an error whereby a msg's SignerName is different to the zone we were expecting, it's
				*possible* that we encountered a situation where multiple zones are hosted on the same nameserver, resulting
				in one or more delegation response being 'skipped'. In that situation we need to get the missing DS records
				and see if we can stitch the chain back together.

				An example of this happening is with the co.uk. TLD.
				When we query uk. for example.co.uk, it does not delegate to co.uk., it goes straight to the nameservers for example.co.uk.
				But uk. and co.uk. both have their own DS records that make up the trust chain.
				So we need to go get the DS records for co.uk. ourselves.

			*/

			// We expect the SignerName of the latest RRSIG to be the Owner Name of the last DS record.
			// If it's not, we're missing a DS record.
			// We return a MissingDSRecordError error, which includes the next expect record name.
			// The caller should endeavour to find and pass in the missing records. Then re-try this record.
			return &MissingDSRecordError{signerName}
		}
	}

	state, r, err := a.verify(a.ctx, zone, msg, last.dsRecords)

	if err != nil {
		// Any errors here are for debugging only.
		Debug(fmt.Errorf("error processing response: %w", err).Error())
		if r != nil {
			r.err = err
		}
	}

	if r != nil {
		a.results = append(a.results, r)

		if state == Unknown {
			// If we don't know by now, we fail-safe to Bogus.
			state = Bogus
		}
		r.state = state

	} else {
		return ErrUnknown
	}

	return nil
}
