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

func (resolver *Resolver) Exchange(ctx context.Context, qmsg *dns.Msg) Response {
	if !qmsg.RecursionDesired {
		return ResponseError(ErrNotRecursionDesired)
	}

	// We'll copy the message as we'll want to amend some headers.
	return resolver.exchange(ctx, qmsg.Copy())
}

func (resolver *Resolver) exchange(ctx context.Context, qmsg *dns.Msg) Response {
	start := time.Now()

	// We never expect/want our own queries to be recursive.
	qmsg.RecursionDesired = false

	// iteration counts the number of times this context has been passed into this exchange(). Mostly helpful for logging.
	iteration, _ := ctx.Value(ctxIteration).(uint32)
	ctx = context.WithValue(ctx, ctxIteration, iteration+1)

	//---

	// counter tracks the number of times the loop in this method has iterated, across all calls to exchange(), for this context.
	// Its job is preventing infinite loops.
	counter, ok := ctx.Value(ctxSessionQueries).(*atomic.Uint32)
	if !ok {
		counter = new(atomic.Uint32)
		ctx = context.WithValue(ctx, ctxSessionQueries, counter)
	}

	//---

	// channel onto which response are placed as they come in.
	channel := make(chan Response)

	// If the DO flag is set, we create a DNSSEC Authenticator.
	var auth *authenticator
	if !qmsg.CheckingDisabled && isSetDO(qmsg) {
		auth = newAuthenticator(ctx, qmsg.Question[0])
	}

	// Start from the root
	z := resolver.zones.get(".")

	// Only all n lookups before we give up...
	for counter.Add(1) <= MaxQueriesPerRequest {

		if auth != nil {
			// If we're going to need the DNSKEY, we can pre-fetch it.
			go z.dnsKeys(ctx)
		}

		// lookup in the current zone
		go func(q *dns.Msg) {
			channel <- z.Exchange(ctx, q)
		}(qmsg)

		select {
		case response := <-channel:
			if !response.Empty() {
				response.Msg.RecursionAvailable = true
			}

			if response.Error() {
				return response
			}

			if response.Empty() {
				return Response{
					Err: fmt.Errorf("nil was returned from the exchange, without an error. mysterious"),
				}
			}

			if auth != nil {
				err := auth.addResponse(z, response.Msg)
				if err != nil {
					return Response{
						Err: fmt.Errorf("error passing response to dnssec authenticator: %w", err),
					}
				}
			}

			//---

			// If an answer claims to be authoritative, of if we're given a SOA in the Authority, then we can return it.
			if response.Msg.Authoritative || recordsOfTypeExist(response.Msg.Ns, dns.TypeSOA) {
				if auth != nil {

					authTime := time.Now()
					response.Auth, _, response.Err = auth.result()
					go Info(fmt.Sprintf("Wait time for DNSSEC result: %s", time.Since(authTime)))

					response.Msg.AuthenticatedData = response.Auth == dnssec.Secure

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

				// We'll consider both of these 'normal' responses.
				if !(response.Msg.Rcode == dns.RcodeSuccess || response.Msg.Rcode == dns.RcodeNameError) {
					response.Err = fmt.Errorf("unsuccessful response code %s (%d)", RcodeToString(response.Msg.Rcode), response.Msg.Rcode)
				}

				response.Duration = time.Since(start)
				return response
			}

			// Otherwise - onwards to the next zone...
			nameservers := extractRecords[*dns.NS](response.Msg.Ns)

			if len(nameservers) == 0 {
				return Response{
					Err: fmt.Errorf("no delegation nameservers found. we don't know where to go next"),
				}
			}

			zoneName := canonicalName(nameservers[0].Header().Name)

			// We expect the zone name to be a subdomain of the current zone (and also not the same as the current zone).
			if zoneName == z.name || !dns.IsSubDomain(z.name, zoneName) {
				return Response{
					Err: fmt.Errorf("unexpected next zone name [%s] after [%s]", zoneName, z.name),
				}
			}

			z = resolver.zones.get(zoneName)

			if z == nil {
				var err error
				z, err = createZone(ctx, zoneName, nameservers, response.Msg.Extra, resolver)
				if err != nil {
					return Response{
						Err: err,
					}
				}
				resolver.zones.add(z)
			}

			if z == nil {
				return Response{
					Err: fmt.Errorf("cannot find next zone in the chain"),
				}
			}

		case <-ctx.Done():
			return Response{
				Err: fmt.Errorf("cancelled"),
			}
		}

	} // for

	return Response{
		Err: fmt.Errorf("too many iterations"),
	}
}
