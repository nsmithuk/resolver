package dnssec

import "github.com/miekg/dns"

func (z *wrappedZone) Name() string {
	return z.name
}

func (z *wrappedZone) LookupDS(qname string) (*dns.Msg, error) {
	return z.parent.LookupDS(qname)
}

func (z *wrappedZone) LookupDNSKEY(qname string) ([]dns.RR, error) {
	return z.parent.LookupDNSKEY(qname)
}
