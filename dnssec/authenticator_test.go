package dnssec

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"testing"
)

func TestAuthenticator_NotSubdomainOfQName(t *testing.T) {

	q := dns.Question{Name: "test.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	a := NewAuth(context.Background(), q)

	err := a.AddResponse(&mockZone{name: "test.example.net."}, &dns.Msg{})
	if !errors.Is(err, ErrNotSubdomain) {
		t.Errorf("expected ErrNotSubdomain as the TLD of the zone does not match the original qname, got %v", err)
	}

	//---

	err = a.AddResponse(&mockZone{name: "example.com."}, &dns.Msg{
		Question: []dns.Question{{Name: "test.example.net.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}},
	)
	if !errors.Is(err, ErrNotSubdomain) {
		t.Errorf("expected ErrNotSubdomain as the TLD of the response question does not match the original qname, got %v", err)
	}

	//---

	q = dns.Question{Name: "a.b.c.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	a = NewAuth(context.Background(), q)
	a.results = append(a.results, &result{
		zone: &mockZone{name: "b.c.example.com."},
	})

	err = a.AddResponse(&mockZone{name: "c.example.com."}, &dns.Msg{
		Question: []dns.Question{{Name: "c.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}},
	)

	// We're expecting an error here as the last result seen was from zone `b.c.example.com.`, but we're not trying to add
	// `c.example.com.`
	if !errors.Is(err, ErrNotSubdomain) {
		t.Errorf("expected ErrNotSubdomain as this response should come before the last result in the chain, got %v", err)
	}

	err = a.AddResponse(&mockZone{name: "b.c.example.com."}, &dns.Msg{
		Question: []dns.Question{{Name: "b.c.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}},
	)
	if !errors.Is(err, ErrSameName) {
		t.Errorf("expected ErrSameName as the zone names cannot be equal, got %v", err)
	}
}
