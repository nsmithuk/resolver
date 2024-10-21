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

func TestResult_BreakInChainExpected(t *testing.T) {

	// These tests focus on what happens when a result state moves from Secure to Insecure part way through a chain.
	// We need to ensure that DOE exists for the DS records, for that to be valid.

	// These three states show that valid DOE was found at the delegation point.

	for _, expectedDOE := range []DenialOfExistenceState{Nsec3OptOut, NsecMissingDS, Nsec3MissingDS} {
		a := NewAuth(context.Background(), &dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

		// When the state moves from Secure to Insecure, we need a DOE result on the last Secure result.
		a.results = append(a.results, &result{state: Secure})
		a.results = append(a.results, &result{state: Secure, denialOfExistence: expectedDOE})
		a.results = append(a.results, &result{state: Insecure})

		state, doe, err := a.Result()
		if err != nil {
			t.Error("unexpected error")
		}
		if doe != expectedDOE {
			t.Error("unexpected doe")
		}
		if state != Insecure {
			t.Error("unexpected state")
		}
	}

}

func TestResult_BreakInChainValidated(t *testing.T) {

	// These tests focus on what happens when a result state moves from Secure to Insecure part way through a chain.
	// We need to ensure that DOE exists for the DS records, for that to be valid.

	// These two DOE states are only accepted if we'd explicitly queried for the DS records at the parent zone.

	for _, expectedDOE := range []DenialOfExistenceState{NsecNoData, Nsec3NoData} {
		a := NewAuth(context.Background(), &dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

		// Used to return the zone apex of the Insecure Result.
		zone := &wrappedZone{name: "EXAMPLE.COM."}

		// Used to lookup the question details of the last Secure result.
		msg := &dns.Msg{Question: []dns.Question{{Name: "example.com.", Qtype: dns.TypeDS}}}

		// When the state moves from Secure to Insecure, we need a DOE result on the last Secure result.
		a.results = append(a.results, &result{state: Secure})
		a.results = append(a.results, &result{state: Secure})
		a.results = append(a.results, &result{state: Secure, denialOfExistence: expectedDOE, msg: msg})
		a.results = append(a.results, &result{state: Insecure, zone: zone})
		a.results = append(a.results, &result{state: Insecure})

		state, doe, err := a.Result()
		if err != nil {
			t.Error("unexpected error")
		}
		if doe != expectedDOE {
			t.Error("unexpected doe")
		}
		if state != Insecure {
			t.Error("unexpected state")
		}

		//---

		// If the query was not for a DS record, it should be Bogus.
		// We've changed it to an A record.

		a = NewAuth(context.Background(), &dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

		// Used to return the zone apex of the Insecure Result.
		zone = &wrappedZone{name: "example.com."}

		// Used to lookup the question details of the last Secure result.
		msg = &dns.Msg{Question: []dns.Question{{Name: "example.com.", Qtype: dns.TypeA}}}

		// When the state moves from Secure to Insecure, we need a DOE result on the last Secure result.
		a.results = append(a.results, &result{state: Secure})
		a.results = append(a.results, &result{state: Secure})
		a.results = append(a.results, &result{state: Secure, denialOfExistence: expectedDOE, msg: msg})
		a.results = append(a.results, &result{state: Insecure, zone: zone})
		a.results = append(a.results, &result{state: Insecure})

		state, doe, err = a.Result()
		if err != nil {
			t.Error("unexpected error")
		}
		if doe != expectedDOE {
			t.Error("unexpected doe")
		}
		if state != Bogus {
			t.Error("unexpected state")
		}

		//---

		// If the Insure zone's apex does not match the QName of the previous question, it should be Bogus.
		// We've changed the question domain to `.net`.

		a = NewAuth(context.Background(), &dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

		// Used to return the zone apex of the Insecure Result.
		zone = &wrappedZone{name: "example.com."}

		// Used to lookup the question details of the last Secure result.
		msg = &dns.Msg{Question: []dns.Question{{Name: "example.net.", Qtype: dns.TypeDS}}}

		// When the state moves from Secure to Insecure, we need a DOE result on the last Secure result.
		a.results = append(a.results, &result{state: Secure})
		a.results = append(a.results, &result{state: Secure})
		a.results = append(a.results, &result{state: Secure, denialOfExistence: expectedDOE, msg: msg})
		a.results = append(a.results, &result{state: Insecure, zone: zone})
		a.results = append(a.results, &result{state: Insecure})

		state, doe, err = a.Result()
		if err != nil {
			t.Error("unexpected error")
		}
		if doe != expectedDOE {
			t.Error("unexpected doe")
		}
		if state != Bogus {
			t.Error("unexpected state")
		}
	}

}

func TestResult_BreakInChaiInvalid(t *testing.T) {

	// These three DOE states are never valid in this situation.
	// NotFound as that means we have no evidence that the Secure chain should have stopped.
	// NsecNxDomain & Nsec3NxDomain don't make sense as they must exist if we've been delegated to its ancestor.

	for _, expectedDOE := range []DenialOfExistenceState{NotFound, NsecNxDomain, Nsec3NxDomain} {
		a := NewAuth(context.Background(), &dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

		// When the state moves from Secure to Insecure, we need a DOE result on the last Secure result.
		a.results = append(a.results, &result{state: Secure})
		a.results = append(a.results, &result{state: Secure})
		a.results = append(a.results, &result{state: Secure, denialOfExistence: expectedDOE})
		a.results = append(a.results, &result{state: Insecure})
		a.results = append(a.results, &result{state: Insecure})

		state, doe, err := a.Result()
		if err != nil {
			t.Error("unexpected error")
		}
		if doe != expectedDOE {
			t.Error("unexpected doe")
		}
		if state != Bogus {
			t.Error("unexpected state")
		}
	}

	//---

	// The default denialOfExistence is NotFound, but we'll sense check that here.

	a := NewAuth(context.Background(), &dns.Question{Name: "test.example.com.", Qtype: dns.TypeA})

	// When the state moves from Secure to Insecure, we need a DOE result on the last Secure result.
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Secure})
	a.results = append(a.results, &result{state: Insecure})
	a.results = append(a.results, &result{state: Insecure})

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
