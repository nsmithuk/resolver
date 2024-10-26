package resolver

import (
	"context"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/resolver/dnssec"
)

type authenticator struct {
	ctx  context.Context
	auth *dnssec.Authenticator
}

func newAuthenticator(ctx context.Context, question dns.Question) *authenticator {
	a := dnssec.NewAuth(ctx, question)
	return &authenticator{
		ctx:  ctx,
		auth: a,
	}
}

func (a *authenticator) addResponse(z *zone, msg *dns.Msg) error {
	return a.addResponseWhilstFixingMissingRecords(z, msg, 0)
}

func (a *authenticator) addResponseWhilstFixingMissingRecords(z *zone, msg *dns.Msg, iteration uint8) error {
	if iteration > 5 {
		return errors.New("iteration too big")
	}

	err := a.auth.AddResponse(&authZoneWrapper{ctx: a.ctx, zone: z}, msg)

	if err != nil {
		var missing *dnssec.MissingDSRecordError
		if errors.As(err, &missing) {
			name := missing.RName()
			return a.lookupDSRecordAndRetry(z, name, msg, iteration)
		}
	}

	return err
}

func (a *authenticator) lookupDSRecordAndRetry(z *zone, missingDSZone string, original *dns.Msg, iteration uint8) error {
	zoneForRetriedMsg := z.clone(missingDSZone)

	// We can prefetch this DNSKEY whilst we're looking up the missing DS record.
	go zoneForRetriedMsg.dnsKeys(a.ctx)

	/*
		Note that we retain the parent nameserver pool because:
		Also note: https://datatracker.ietf.org/doc/html/rfc4035#section-4.2
		"When attempting to retrieve missing NSEC RRs that reside on the
		parental side at a zone cut, a security-aware iterative-mode resolver
		MUST query the name servers for the parent zone, not the child zone."
	*/

	qmsg := new(dns.Msg)
	qmsg.SetQuestion(dns.Fqdn(missingDSZone), dns.TypeDS)
	qmsg.SetEdns0(4096, true)
	qmsg.RecursionDesired = false
	response := z.Exchange(a.ctx, qmsg)
	if response.Error() {
		return response.Err
	}
	if response.Empty() {
		return fmt.Errorf("no answers retured for DS lookup [%s]", missingDSZone)
	}

	// Add the new response from the DS lookup.
	err := a.addResponseWhilstFixingMissingRecords(z, response.Msg, iteration)
	if err != nil {
		return err
	}

	// Retry the original message.
	return a.addResponseWhilstFixingMissingRecords(zoneForRetriedMsg, original, iteration+1)
}

func (a *authenticator) result() (dnssec.AuthenticationResult, dnssec.DenialOfExistenceState, error) {
	return a.auth.Result()
}

// authZoneWrapper wraps our zone such that is supports the dnssec.Zone interface.
// Note that the dnssec package only needs querying support against this zone's nameservers.
// i.e. We do not need to try these queries recursively. If the nameservers for this zone do not return
// an authoritative answer themselves, we can assume that's an error.
type authZoneWrapper struct {
	ctx  context.Context
	zone *zone
}

// Name returns the zone's apex domain name.
func (wrapper *authZoneWrapper) Name() string {
	return wrapper.zone.name
}

// GetDNSKEYRecords Looks up the DNSKEY records for the given QName, in the zone.
func (wrapper *authZoneWrapper) GetDNSKEYRecords() ([]dns.RR, error) {
	return wrapper.zone.dnsKeys(wrapper.ctx)
}
