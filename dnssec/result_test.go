package dnssec

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"testing"
)

func TestResult_NoRecords(t *testing.T) {

	// If we call Result() when no response have been passed to the authenticator.
	// Then we cannot off a conclusion.

	a := NewAuth(context.Background(), &dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

	state, doe, err := a.Result()

	if doe != NotFound {
		t.Error("unexpected doe")
	}
	if state != Unknown {
		t.Error("unexpected state")
	}
	if err == nil {
		t.Error("we expected an error")
	}
	if !errors.Is(err, ErrNoResults) {
		t.Error("expected ErrNoResults")
	}

}

func TestResult_BogusRecords(t *testing.T) {

	// If any one of the results was Bogus, then the overall conclusion is also Bogus.

	a := NewAuth(context.Background(), &dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Bogus})
	a.results = append(a.results, &result{state: Secure})

	state, doe, err := a.Result()
	if err != nil {
		t.Error("unexpected error")
	}
	if doe != NotFound {
		t.Error("unexpected doe")
	}
	if state != Bogus {
		t.Error("unexpected state")
	}

}

func TestResult_DoeMidChain(t *testing.T) {

	// We test when a DOE record is found mid-chain. i.e. in a result that's not the last result.
	// Mid-chain DOE records are linked to missing DS records.

	a := NewAuth(context.Background(), &dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

	// When the state moves from Secure to Insecure, we need a DOE result on the last Secure result.
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure, denialOfExistence: Nsec3OptOut})
	a.results = append(a.results, &result{state: Insecure})
	a.results = append(a.results, &result{state: Insecure})

	state, doe, err := a.Result()
	if err != nil {
		t.Error("unexpected error")
	}
	if doe != Nsec3OptOut {
		t.Error("unexpected doe")
	}
	if state != Insecure {
		t.Error("unexpected state")
	}

	//---

	a = NewAuth(context.Background(), &dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

	// When the state moves from Secure to Insecure, we need a DOE result on the last Secure result.
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure, denialOfExistence: NsecMissingDS})
	a.results = append(a.results, &result{state: Insecure})
	a.results = append(a.results, &result{state: Insecure})

	state, doe, err = a.Result()
	if err != nil {
		t.Error("unexpected error")
	}
	if doe != NsecMissingDS {
		t.Error("unexpected doe")
	}
	if state != Insecure {
		t.Error("unexpected state")
	}

	//---

	a = NewAuth(context.Background(), &dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

	// When the state moves from Secure to Insecure, we need a DOE result on the last Secure result.
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure, denialOfExistence: Nsec3MissingDS})
	a.results = append(a.results, &result{state: Insecure})
	a.results = append(a.results, &result{state: Insecure})

	state, doe, err = a.Result()
	if err != nil {
		t.Error("unexpected error")
	}
	if doe != Nsec3MissingDS {
		t.Error("unexpected doe")
	}
	if state != Insecure {
		t.Error("unexpected state")
	}

	//---

	a = NewAuth(context.Background(), &dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

	// NXDOMAIN and NODATA DOE is not valid mid-chain.
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure, denialOfExistence: NsecNoData})
	a.results = append(a.results, &result{state: Insecure})
	a.results = append(a.results, &result{state: Insecure})

	state, doe, err = a.Result()
	if err != nil {
		t.Error("unexpected error")
	}
	if doe != NsecNoData {
		t.Error("unexpected doe")
	}
	if state != Bogus {
		t.Error("unexpected state")
	}

	//---

	a = NewAuth(context.Background(), &dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

	// NXDOMAIN and NODATA DOE is not valid mid-chain.
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure, denialOfExistence: Nsec3NoData})
	a.results = append(a.results, &result{state: Insecure})
	a.results = append(a.results, &result{state: Insecure})

	state, doe, err = a.Result()
	if err != nil {
		t.Error("unexpected error")
	}
	if doe != Nsec3NoData {
		t.Error("unexpected doe")
	}
	if state != Bogus {
		t.Error("unexpected state")
	}

	//---

	a = NewAuth(context.Background(), &dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

	// NXDOMAIN and NODATA DOE is not valid mid-chain.
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure, denialOfExistence: Nsec3NxDomain})
	a.results = append(a.results, &result{state: Insecure})
	a.results = append(a.results, &result{state: Insecure})

	state, doe, err = a.Result()
	if err != nil {
		t.Error("unexpected error")
	}
	if doe != Nsec3NxDomain {
		t.Error("unexpected doe")
	}
	if state != Bogus {
		t.Error("unexpected state")
	}

	//---

	a = NewAuth(context.Background(), &dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

	// When the state moves from Secure to Insecure, we need a DOE result on the last Secure result.
	// When this isn't the case, we expect the result to be Bogus.
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Insecure})
	a.results = append(a.results, &result{state: Insecure})

	state, doe, err = a.Result()
	if err != nil {
		t.Error("unexpected error")
	}
	if doe != NotFound {
		t.Error("unexpected doe")
	}
	if state != Bogus {
		t.Error("unexpected state")
	}

	//---

	a = NewAuth(context.Background(), &dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

	// If the first result is not Secure, we expect the overall conclusion to be whatever
	// the first result is, regardless of what comes after it (except if any result is Bogus).
	a.results = append(a.results, &result{state: Insecure})
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure})

	state, doe, err = a.Result()
	if err != nil {
		t.Error("unexpected error")
	}
	if doe != NotFound {
		t.Error("unexpected doe")
	}
	if state != Insecure {
		t.Error("unexpected state")
	}
}
