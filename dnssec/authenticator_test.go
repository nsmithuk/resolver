package dnssec

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"testing"
)

func TestAuthenticator_NotSubdomain(t *testing.T) {

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

func TestAuthenticator_StateSet(t *testing.T) {

	q := dns.Question{Name: "test.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	// Test secure with no error.

	a := NewAuth(context.Background(), q)
	a.verify = func(ctx context.Context, zone Zone, msg *dns.Msg, dsRecordsFromParent []*dns.DS) (AuthenticationResult, *result, error) {
		return Secure, &result{}, nil
	}

	err := a.AddResponse(&mockZone{name: "example.com."}, &dns.Msg{
		Question: []dns.Question{{Name: "test.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}},
	)
	if err != nil {
		t.Errorf("expected err to be nil, got %v", err)
	}
	if len(a.results) != 1 {
		t.Errorf("expected len(a.results) to be 1, got %v", len(a.results))
	}
	if a.results[0].err != nil {
		t.Errorf("expected err to be nil, got %v", a.results[0].err)
	}
	if a.results[0].state != Secure {
		t.Errorf("expected state to be Secure, got %v", a.results[0].state)
	}

	//---

	// Test Insecure with no error.

	a = NewAuth(context.Background(), q)
	a.verify = func(ctx context.Context, zone Zone, msg *dns.Msg, dsRecordsFromParent []*dns.DS) (AuthenticationResult, *result, error) {
		return Insecure, &result{}, nil
	}

	err = a.AddResponse(&mockZone{name: "example.com."}, &dns.Msg{
		Question: []dns.Question{{Name: "test.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}},
	)
	if err != nil {
		t.Errorf("expected err to be nil, got %v", err)
	}
	if len(a.results) != 1 {
		t.Errorf("expected len(a.results) to be 1, got %v", len(a.results))
	}
	if a.results[0].err != nil {
		t.Errorf("expected err to be nil, got %v", a.results[0].err)
	}
	if a.results[0].state != Insecure {
		t.Errorf("expected state to be Insecure, got %v", a.results[0].state)
	}

	//---

	// If the state is unknown, we fail-safe to Bogus.

	a = NewAuth(context.Background(), q)
	a.verify = func(ctx context.Context, zone Zone, msg *dns.Msg, dsRecordsFromParent []*dns.DS) (AuthenticationResult, *result, error) {
		return Unknown, &result{}, nil
	}

	err = a.AddResponse(&mockZone{name: "example.com."}, &dns.Msg{
		Question: []dns.Question{{Name: "test.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}},
	)
	if err != nil {
		t.Errorf("expected err to be nil, got %v", err)
	}
	if len(a.results) != 1 {
		t.Errorf("expected len(a.results) to be 1, got %v", len(a.results))
	}
	if a.results[0].err != nil {
		t.Errorf("expected err to be nil, got %v", a.results[0].err)
	}
	if a.results[0].state != Bogus {
		t.Errorf("expected state to be Bogus, got %v", a.results[0].state)
	}

}

func TestAuthenticator_ErrorSet(t *testing.T) {

	q := dns.Question{Name: "test.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	// If an error is returned from verify, we expect it to be set on the result.

	expected := errors.New("mock error")

	a := NewAuth(context.Background(), q)
	a.verify = func(ctx context.Context, zone Zone, msg *dns.Msg, dsRecordsFromParent []*dns.DS) (AuthenticationResult, *result, error) {
		return Secure, &result{}, expected
	}

	err := a.AddResponse(&mockZone{name: "example.com."}, &dns.Msg{
		Question: []dns.Question{{Name: "test.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}},
	)
	if err != nil {
		t.Errorf("expected err to be nil, got %v", err)
	}
	if len(a.results) != 1 {
		t.Errorf("expected len(a.results) to be 1, got %v", len(a.results))
	}
	if !errors.Is(a.results[0].err, expected) {
		t.Errorf("expected err to be %v, got %v", expected, a.results[0].err)
	}
	if a.results[0].state != Secure {
		t.Errorf("expected state to be Secure, got %v", a.results[0].state)
	}

	//---

	// If a nil result is returned, something unexpected has happened.

	a = NewAuth(context.Background(), q)
	a.verify = func(ctx context.Context, zone Zone, msg *dns.Msg, dsRecordsFromParent []*dns.DS) (AuthenticationResult, *result, error) {
		return Secure, nil, nil
	}

	err = a.AddResponse(&mockZone{name: "example.com."}, &dns.Msg{
		Question: []dns.Question{{Name: "test.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}},
	)
	if !errors.Is(err, ErrUnknown) {
		t.Errorf("expected err to be ErrUnknown, got %v", err)
	}

}

func TestAuthenticator_MissingDSRecordError(t *testing.T) {

	// Here we test for detecting missing DS records.

	q := dns.Question{Name: "test.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	a := NewAuth(context.Background(), q)
	a.verify = func(ctx context.Context, zone Zone, msg *dns.Msg, dsRecordsFromParent []*dns.DS) (AuthenticationResult, *result, error) {
		return Secure, &result{}, nil
	}

	// We setup so the last DS records is for `example.com.`, thus we're expecting the next response to have a RRSIG with
	// a signerName of `example.com.`.

	r := result{
		zone: &mockZone{name: "com."},
		dsRecords: []*dns.DS{
			newRR("example.com. 54775 IN DS 370 13 2 BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A8 6764247C").(*dns.DS),
		},
	}
	a.results = append(a.results, &r)

	//---

	// Unexpected next RRSIG - missmatch on signerName
	case1 := newRR("test.example.com. 955 IN RRSIG A 13 2 3600 20241102170341 20241012065317 19367 test.example.com. XMyTWC8y9WecF5ST67DyRUK3Ptvfpy/+Oetha9r6ZU0RJ4aclvY32uKCojUsjCUHaejma032va/7Z4Yd3Krq8Q==").(*dns.RRSIG)

	err := a.AddResponse(&mockZone{name: "example.com."}, &dns.Msg{
		Question: []dns.Question{q},
		Answer:   []dns.RR{case1},
	})

	var missing *MissingDSRecordError
	if !errors.As(err, &missing) {
		t.Errorf("expected err to be MissingDSRecordError, got %v", err)
	}
	if errors.As(err, &missing) && missing.RName() != "test.example.com." {
		t.Errorf("expected rname to be  test.example.com., got %v", missing.RName())
	}

	//---

	// Unexpected next RRSIG - signerName is not a subdomain of the question.
	case2 := newRR("test.example.com. 955 IN RRSIG A 13 2 3600 20241102170341 20241012065317 19367 example.net. XMyTWC8y9WecF5ST67DyRUK3Ptvfpy/+Oetha9r6ZU0RJ4aclvY32uKCojUsjCUHaejma032va/7Z4Yd3Krq8Q==").(*dns.RRSIG)

	err = a.AddResponse(&mockZone{name: "example.com."}, &dns.Msg{
		Question: []dns.Question{q},
		Answer:   []dns.RR{case2},
	})
	if !errors.Is(err, ErrNotSubdomain) {
		t.Errorf("expected err to be ErrNotSubdomain, got %v", err)
	}

	// Expected next RRSIG
	case3 := newRR("test.example.com. 955 IN RRSIG A 13 2 3600 20241102170341 20241012065317 19367 example.com. XMyTWC8y9WecF5ST67DyRUK3Ptvfpy/+Oetha9r6ZU0RJ4aclvY32uKCojUsjCUHaejma032va/7Z4Yd3Krq8Q==").(*dns.RRSIG)

	err = a.AddResponse(&mockZone{name: "example.com."}, &dns.Msg{
		Question: []dns.Question{q},
		Answer:   []dns.RR{case3},
	})
	if err != nil {
		t.Errorf("expected err to be nil, got %v", err)
	}
}
