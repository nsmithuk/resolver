package resolver

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/resolver/dnssec"
	"sync/atomic"
	"time"
)

// We have a public Exchange(), so people can call it.
// And a private exchange(), to meet the exchanger interface.

func (resolver *Resolver) Exchange(ctx context.Context, qmsg *dns.Msg) *Response {
	if !qmsg.RecursionDesired {
		return ResponseError(ErrNotRecursionDesired)
	}

	// We'll copy the message as we'll want to amend some headers.
	return resolver.exchange(ctx, qmsg.Copy())
}

func (resolver *Resolver) exchange(ctx context.Context, qmsg *dns.Msg) *Response {

	//----------------------------------------------------------------------------
	// We setup our context

	start := time.Now()
	if v := ctx.Value(ctxStartTime); v == nil {
		ctx = context.WithValue(ctx, ctxStartTime, start)
	}

	//---

	trace, ok := ctx.Value(CtxTrace).(*Trace)
	if !ok {
		trace = newTraceWithStart(start)
		ctx = context.WithValue(ctx, CtxTrace, trace)
		Debug(fmt.Sprintf("New query started with Trace ID: %s", trace.SortID()))
	}

	trace.Iterations.Add(1)

	//---

	// counter tracts the number of iterations we've seen of the main query loop - the one at the end of this function.
	// Its value persists across all call to resolver.exchange(), for a given query.
	// Its job is to detect/prevent infinite loops.
	counter, ok := ctx.Value(ctxSessionQueries).(*atomic.Uint32)
	if !ok {
		counter = new(atomic.Uint32)
		ctx = context.WithValue(ctx, ctxSessionQueries, counter)
	}

	//----------------------------------------------------------------------------
	// We setup the DNSSEC Authenticator

	// If the DO flag is set, we create a DNSSEC Authenticator.
	var auth *authenticator
	if isSetDO(qmsg) {
		auth = newAuthenticator(ctx, qmsg.Question[0])
		defer auth.close()
	}

	//----------------------------------------------------------------------------
	// We determine what zones we already know about for the QName

	// Returns a list zones that make up the QName that we already have nameservers for.
	// Items are only included is we have a valid chain from leaf to root.
	// They are ordered most specific (i.e. longest FQDN), to shortest.
	// The last element will always be the root (.).
	knownZones := resolver.zones.getZoneList(qmsg.Question[0].Name)

	if auth != nil {
		// Lookup the DNSSEC details for these zones.
		// We don't do this lookup for the root, thus len()-1.
		for i := 0; i < len(knownZones)-1; i++ {
			// We never look directly at the first zone.
			z := knownZones[i+1]
			dsName := knownZones[i].name
			auth.addDelegationSignerLink(z, dsName)
		}
	}

	//----------------------------------------------------------------------------
	// We iterate through the QName labels, exchanging the question with each zone.

	d := newDomain(qmsg.Question[0].Name)

	// Wind past all the zones that we already know about (if any).
	if err := d.windTo(knownZones[0].name); err != nil {
		return ResponseError(err)
	}

	var response *Response

	// We track the last zone, as that's were we pass the query for the next label.
	last := knownZones[0]

	for ; !d.end(); d.next() {
		if counter.Add(1) > MaxQueriesPerRequest {
			return ResponseError(fmt.Errorf("too many iterations"))
		}

		last, response = resolver.funcs.resolveLabel(ctx, &d, last, qmsg, auth)
		if response != nil {
			return response
		}
	}

	return ResponseError(ErrUnableToResolveAnswer)
}

func (resolver *Resolver) resolveLabel(ctx context.Context, d *domain, z *zone, qmsg *dns.Msg, auth *authenticator) (*zone, *Response) {
	c := d.current()

	if next := resolver.zones.get(c); next != nil {
		// If we already know of the zone for the current name, and there are still more labels in teh QName
		// to check, then we can return where.
		// Note that the DS records will already have been requested in Step 1.
		if d.more() {
			return next, nil
		}
	}

	if z == nil {
		// This is a sense check; it _should_ never happen.
		return nil, ResponseError(fmt.Errorf("%w: zone cannot be nil at this point", ErrInternalError))
	}

	if auth != nil {
		// If we're going to need the DNSKEY, we can pre-fetch it.
		go z.dnsKeys(ctx)
	}

	response := z.Exchange(ctx, qmsg)

	if !response.Empty() {
		response.Msg.RecursionAvailable = true
	}

	if response.Error() {
		return nil, response
	}

	if response.Empty() {
		return nil, ResponseError(fmt.Errorf("nil was returned from the exchange, without an error. mysterious"))
	}

	//---

	records := append(response.Msg.Ns, response.Msg.Answer...)
	if len(records) == 0 {
		return nil, &Response{
			Err: fmt.Errorf("no records found. we don't know where to go next"),
		}
	}

	nextRecordsOwner := canonicalName(records[0].Header().Name)

	// We expect the zone name to be a subdomain of the current zone (and also not the same as the current zone).
	if !dns.IsSubDomain(z.name, nextRecordsOwner) {
		return nil, &Response{
			Err: fmt.Errorf("unexpected next zone name [%s] after [%s]", nextRecordsOwner, z.name),
		}
	}

	missingZoneNames := d.gap(nextRecordsOwner)
	for _, missingDomain := range missingZoneNames {

		soa, err := z.soa(ctx, missingDomain)

		// If a SOA was found, then the missingDomain is its own zone.
		if err == nil && soa != nil {

			newZone := z.clone(missingDomain)
			newZone.parent = z.name

			if auth != nil {
				auth.addDelegationSignerLink(z, newZone.name)
			}

			resolver.zones.add(newZone)
			z = newZone

		}

		// We skip over these missing domains in our lookup loop.
		d.next()
	}

	//---

	if auth != nil {
		auth.addResponse(z, response.Msg)
	}

	if response.Msg.Authoritative || recordsOfTypeExist(response.Msg.Ns, dns.TypeSOA) || !recordsOfTypeExist(response.Msg.Ns, dns.TypeNS) {
		response = resolver.funcs.finaliseResponse(ctx, auth, qmsg, response)
		return nil, response
	}

	//---

	// Otherwise - onwards to the next zone...
	nameservers := extractRecords[*dns.NS](response.Msg.Ns)

	if len(nameservers) == 0 {
		return nil, &Response{
			Err: fmt.Errorf("no delegation nameservers found. we don't know where to go next"),
		}
	}

	nextZoneName := canonicalName(nameservers[0].Header().Name)

	newZone, err := resolver.funcs.createZone(ctx, nextZoneName, nameservers, response.Msg.Extra, resolver.funcs.getExchanger())
	if err != nil {
		return nil, ResponseError(err)
	}
	newZone.parent = z.name
	resolver.zones.add(newZone)

	return newZone, nil
}

func (resolver *Resolver) finaliseResponse(ctx context.Context, auth *authenticator, qmsg *dns.Msg, response *Response) *Response {
	if auth != nil {
		authTime := time.Now()
		response.Auth, response.Deo, response.Err = auth.result()
		Info(fmt.Sprintf("DNSSEC took %s to return an answer of %s and DOE %s", time.Since(authTime), response.Auth.String(), response.Deo.String()))
	}

	//---

	// Follow any CNAME, if needed.
	if qmsg.Question[0].Qtype != dns.TypeCNAME && recordsOfTypeExist(response.Msg.Answer, dns.TypeCNAME) {
		// The results from this are added to `response.Msg`.
		err := resolver.funcs.cname(ctx, qmsg, response, resolver.funcs.getExchanger())
		if err != nil {
			return &Response{
				Err: err,
			}
		}
	}

	// We'll consider both of these 'normal' responses.
	if !(response.Msg.Rcode == dns.RcodeSuccess || response.Msg.Rcode == dns.RcodeNameError) {
		response.Err = fmt.Errorf("unsuccessful response code %s (%d)", RcodeToString(response.Msg.Rcode), response.Msg.Rcode)
	}

	//---

	if RemoveAuthoritySectionForPositiveAnswers && len(response.Msg.Answer) > 0 && !recordsOfTypeExist(response.Msg.Ns, dns.TypeSOA) {
		response.Msg.Ns = []dns.RR{}
	}

	if RemoveAdditionalSectionForPositiveAnswers && len(response.Msg.Answer) > 0 && !recordsOfTypeExist(response.Msg.Ns, dns.TypeSOA) {
		var opt *dns.OPT
		for _, extra := range response.Msg.Extra {
			opt, _ = extra.(*dns.OPT)
		}

		if opt != nil {
			response.Msg.Extra = []dns.RR{opt}
		} else {
			response.Msg.Extra = []dns.RR{}
		}
	}

	dedup := make(map[string]dns.RR)
	if len(response.Msg.Answer) > 0 {
		response.Msg.Answer = dns.Dedup(response.Msg.Answer, dedup)
	}
	if len(response.Msg.Ns) > 0 {
		clear(dedup)
		response.Msg.Ns = dns.Dedup(response.Msg.Ns, dedup)
	}
	if len(response.Msg.Extra) > 0 {
		clear(dedup)
		response.Msg.Extra = dns.Dedup(response.Msg.Extra, dedup)
	}

	if auth != nil {
		/*
			TODO
			   If the resolver accepts the RRset as authentic, the validator MUST
			   set the TTL of the RRSIG RR and each RR in the authenticated RRset to
			   a value no greater than the minimum of:
			   o  the RRset's TTL as received in the response;
			   o  the RRSIG RR's TTL as received in the response;
			   o  the value in the RRSIG RR's Original TTL field; and
			   o  the difference of the RRSIG RR's Signature Expiration time and the
			      current time.
		*/

		if !qmsg.CheckingDisabled {
			response.Msg.AuthenticatedData = response.Auth == dnssec.Secure

			// If a response is Bogus, we return a Server Failure with all the response removed.
			if response.Auth == dnssec.Bogus {
				response.Msg.Rcode = dns.RcodeServerFailure
				if SuppressBogusResponseSections {
					response.Msg.Answer = []dns.RR{}
					response.Msg.Ns = []dns.RR{}
					response.Msg.Extra = []dns.RR{}
				}
			}
		}
	}

	start, _ := ctx.Value(ctxStartTime).(time.Time)
	response.Duration = time.Since(start)
	return response
}
