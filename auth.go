package resolver

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
)

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

// LookupDS Looks up DS records for the given QName, in the zone.
// Note that it's the call's responsibility to ensure they're call this against the correct (i.e. parent) zone.
func (wrapper *authZoneWrapper) LookupDS(qname string) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(qname), dns.TypeDS)
	msg.SetEdns0(4096, true)
	msg.RecursionDesired = false
	response := wrapper.zone.Exchange(wrapper.ctx, msg)
	if response.Error() {
		return nil, response.Err
	}
	if response.Empty() {
		return nil, fmt.Errorf("no answers")
	}
	return response.Msg, nil
}

// LookupDNSKEY Looks up the DNSKEY records for the given QName, in the zone.
func (wrapper *authZoneWrapper) LookupDNSKEY(qname string) ([]dns.RR, error) {

	// If the QName matches the zone's apex, we can use our helper function. Hopefully the result is already cached.
	if dns.CanonicalName(wrapper.zone.name) == dns.CanonicalName(qname) {
		return wrapper.zone.dnsKeys(wrapper.ctx)
	}

	// Otherwise we'll do the exchange ourselves.
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(qname), dns.TypeDNSKEY)
	msg.SetEdns0(4096, true)
	msg.RecursionDesired = false
	response := wrapper.zone.Exchange(wrapper.ctx, msg)
	if response.Error() {
		return nil, response.Err
	}
	if response.Empty() || len(response.Msg.Answer) == 0 {
		return nil, fmt.Errorf("no answers")
	}

	return response.Msg.Answer, nil
}
