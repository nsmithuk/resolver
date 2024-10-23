package dnssec

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"slices"
	"sync"
)

func NewAuth(ctx context.Context, question dns.Question) *Authenticator {
	auth := &Authenticator{
		ctx:        ctx,
		question:   question,
		processing: &sync.WaitGroup{},
		queue:      make(chan input, 8),
		results:    make([]*result, 0, 5),
	}

	//go auth.start()

	return auth
}

type MissingDSRecord struct {
	name string
}

func (e *MissingDSRecord) RName() string {
	return e.name
}

func (e *MissingDSRecord) Error() string {
	return fmt.Sprintf("missing DS record: %s", e.name)
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

			// We expect the SignerName of the latest RRSIG to be the Owner Name of the last DS record.
			// If it's not, we're missing a DS record.
			// We return a MissingDSRecord error, which includes the next expect record name.
			// The caller should endeavour to find and pass in the missing records. Then re-try this record.
			return &MissingDSRecord{signerName}
		}
	}

	r, err := a.validateChainAndProcess(input{zone, msg}, last, 0)
	if err != nil {
		// Any errors here are for debugging only.
		go Debug(fmt.Errorf("error processing response: %w", err).Error())
		if r != nil {
			r.err = err
		}
	}

	return nil
}

//func (a *Authenticator) AddResponse(zone Zone, msg *dns.Msg) {
//	if a.finished.Load() {
//		return
//	}
//	if msg == nil {
//		return
//	}
//
//	a.processing.Add(1)
//	a.queue <- input{zone, msg}
//}
//
//func (a *Authenticator) Close() {
//	a.close.Do(func() {
//		a.finished.Store(true)
//		close(a.queue)
//		a.queue = nil
//	})
//}
//
//func (a *Authenticator) start() {
//
//	var err error
//
//	last := &result{
//		dsRecords: RootTrustAnchors,
//	}
//
//	for in := range a.queue {
//
//		if last != nil {
//			last, err = a.validateChainAndProcess(in, last, 0)
//			if err != nil {
//				// Any errors here are for debugging only.
//				go Debug(fmt.Errorf("error processing response: %w", err).Error())
//				if last != nil {
//					last.err = err
//				}
//			}
//		}
//
//		a.processing.Done()
//	}
//
//}

func (a *Authenticator) validateChainAndProcess(in input, last *result, iteration uint8) (*result, error) {
	if iteration > 4 {
		return nil, fmt.Errorf("%w: iterations: %d. max allowed: %d", ErrDSLookupLoop, iteration, 5)
	}

	rrsigs := extractRecords[*dns.RRSIG](slices.Concat(in.msg.Answer, in.msg.Ns))

	missmatchSignerName := ""
	for _, rrsig := range rrsigs {
		if len(missmatchSignerName) != 0 && rrsig.SignerName != missmatchSignerName {
			return nil, fmt.Errorf("%w: both %s and %s seen", ErrMultipleVaryingSignerNames, missmatchSignerName, rrsig.SignerName)
		}
		if rrsig.SignerName != in.zone.Name() {
			missmatchSignerName = rrsig.SignerName
		}
	}

	if len(missmatchSignerName) != 0 {
		if !dns.IsSubDomain(missmatchSignerName, a.question.Name) {
			return nil, fmt.Errorf("%w: signer name:[%s] qname:[%s]", ErrSignerNameNotParentOfQName, missmatchSignerName, a.question.Name)
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

			Also note: https://datatracker.ietf.org/doc/html/rfc4035#section-4.2
				"When attempting to retrieve missing NSEC RRs that reside on the
				parental side at a zone cut, a security-aware iterative-mode resolver
				MUST query the name servers for the parent zone, not the child zone."
		*/

		// Get the missing DS records. Note that `zone` here still represents the parent of the name, so we're pointing this at the correct nameservers.
		ds, err := in.zone.LookupDS(missmatchSignerName)
		if err != nil {
			return nil, fmt.Errorf("%w for %s (%w)", ErrUnableToFetchDSRecord, missmatchSignerName, err)
		}
		if ds == nil {
			return nil, fmt.Errorf("%w for %s", ErrUnableToFetchDSRecord, missmatchSignerName)
		}

		last, err = a.validateChainAndProcess(input{
			msg:  ds,
			zone: in.zone,
		}, last, iteration+1)

		// check for errors and no returned DS records...
		if err != nil || last == nil {
			// We've finished
			return nil, err
		}

		// We wrap the parent zone with the new signer name, and pass that along with the original message.
		in.zone = &wrappedZone{
			name:   missmatchSignerName,
			parent: in.zone,
		}
	}

	//---------------------------------------------------

	state, r, err := a.process(in, last.dsRecords)
	if state == Unknown {
		// If we don't know by now, we fail-safe to Bogus.
		state = Bogus
	}
	r.state = state
	return r, err
}
