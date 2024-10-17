package dnssec

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"slices"
	"sync"
)

func NewAuth(ctx context.Context, question *dns.Question) *Authenticator {
	auth := &Authenticator{
		ctx:        ctx,
		question:   question,
		processing: &sync.WaitGroup{},
		queue:      make(chan input, 8),
		results:    make([]*result, 0, 5),
	}

	go auth.start()

	return auth
}

func (a *Authenticator) AddResponse(zone Zone, msg *dns.Msg) {
	if a.finished.Load() {
		return
	}
	if msg == nil {
		return
	}

	a.processing.Add(1)
	a.queue <- input{zone, msg}
}

func (a *Authenticator) Close() {
	a.close.Do(func() {
		a.finished.Store(true)
		close(a.queue)
		a.queue = nil
	})
}

func (a *Authenticator) start() {

	var err error

	last := &result{
		dsRecords: RootTrustAnchors,
	}

	for in := range a.queue {

		if last != nil {
			last, err = a.validateChainAndProcess(in, last, 0)
			if err != nil {
				// Any errors here are for debugging only.
				go Debug(fmt.Errorf("error processing response: %w", err).Error())
				if last != nil {
					last.err = err
				}
			}
		}

		a.processing.Done()
	}

}

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

		// Get the missing DS records. Note that `zone` here still represents the parent of the missmatchSignerName, so we're pointing this at the correct nameservers.
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
