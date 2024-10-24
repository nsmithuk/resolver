package dnssec

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"slices"
	"testing"
)

func TestVerify_DNSKEYs(t *testing.T) {

	// Tests verifyDNSKEYs(). This method:
	//	- Checks we have one or more DNSKEYs, with an aligning Delegation Signer.
	//	- If yes, we check that the DNSKEY RRSet is signed by one of these keys.

	k := testEcKey()

	// When no zone keys are passed, the answer must be insecure.

	ctx := context.Background()
	r := &result{
		zone: &mockZone{name: zoneName},
	}
	keys := []dns.RR{}
	dsRecordsFromParent := []*dns.DS{}

	state, err := verifyDNSKEYs(ctx, r, keys, dsRecordsFromParent)
	if err == nil {
		t.Errorf("verifyDNSKEYs returned no error. expected ErrKeysNotFound")
	}
	if state != Insecure {
		t.Errorf("verifyDNSKEYs returned incorrect state. expected %v, got %v", Insecure, state)
	}

	//---

	// If keys are passed in, but none of them have an associated DS record from the parent, the answer must be insecure.

	keys = []dns.RR{k.key}

	// This DS record does not match the key.
	dsRecordsFromParent = []*dns.DS{
		newRR("example.com. 54775 IN DS 370 13 2 BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A8 6764247C").(*dns.DS),
	}

	state, err = verifyDNSKEYs(ctx, r, keys, dsRecordsFromParent)
	if err == nil {
		t.Errorf("verifyDNSKEYs returned no error. expected ErrKeysNotFound")
	}
	if state != Insecure {
		t.Errorf("verifyDNSKEYs returned incorrect state. expected %v, got %v", Insecure, state)
	}

	//---

	// We'll pass in a valid DNSKEY/DS pair, but without any RRSIG. We therefore expect authentication to fail.

	// DS record is now correct
	dsRecordsFromParent = []*dns.DS{k.ds}

	// This should now be valid
	state, err = verifyDNSKEYs(ctx, r, keys, dsRecordsFromParent)
	if !errors.Is(err, ErrBogusResultFound) {
		t.Errorf("verifyDNSKEYs returned unexpected error. expected ErrBogusResultFound, got %v", err)
	}
	if !errors.Is(err, ErrUnexpectedSignatureCount) {
		t.Errorf("verifyDNSKEYs returned unexpected error. expected ErrUnexpectedSignatureCount, got %v", err)
	}
	if state != Bogus {
		t.Errorf("verifyDNSKEYs returned incorrect state. expected %v, got %v", Bogus, state)
	}

	//---

	// We'll sign the key now, so we expect the result to be valid...

	keys = append(keys, k.sign(keys, 0, 0))

	// This should now be valid
	state, err = verifyDNSKEYs(ctx, r, keys, dsRecordsFromParent)
	if err != nil {
		t.Errorf("verifyDNSKEYs returned unexpected error: %v", err)
	}
	if state != Unknown {
		t.Errorf("verifyDNSKEYs returned incorrect state. expected %v, got %v", Unknown, state)
	}
	if len(r.keys) != 1 {
		t.Errorf("verifyDNSKEYs returned incorrect number of keys. expected 1, got %v", len(r.keys))
	}

	//---

	// If we "break" the signature, it should revert back to being Bogus.
	keys[1].(*dns.RRSIG).Labels = 0

	// This should now be valid
	state, err = verifyDNSKEYs(ctx, r, keys, dsRecordsFromParent)
	if !errors.Is(err, ErrBogusResultFound) {
		t.Errorf("verifyDNSKEYs returned unexpected error. expected ErrBogusResultFound, got %v", err)
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("verifyDNSKEYs returned unexpected error. expected ErrInvalidSignature, got %v", err)
	}
	if state != Bogus {
		t.Errorf("verifyDNSKEYs returned incorrect state. expected %v, got %v", Bogus, state)
	}

}

func TestVerify_RRSETs(t *testing.T) {

	// Tests verifyRRSETs(). This method:
	//	- Checks any RRSigs in the Answer section are valid.
	//	- Checks any RRSigs in the Authority section are valid.
	//	- If we're at this function, we're expecting the response to be signed. Thus if neither section containers
	//		valid signatures, we conclude Bogus.

	key := testEcKey()
	ctx := context.Background()
	r := &result{
		zone: &mockZone{name: zoneName},
		msg: &dns.Msg{
			Answer: []dns.RR{},
			Ns:     []dns.RR{},
		},
	}

	keys := []*dns.DNSKEY{key.key}

	// With no signatures passed, we expect a Bogus result, with ErrSignatureSetEmpty.

	state, err := verifyRRSETs(ctx, r, keys)
	if !errors.Is(err, ErrBogusResultFound) {
		t.Errorf("verifyDNSKEYs returned unexpected error. expected ErrBogusResultFound, got %v", err)
	}
	if !errors.Is(err, ErrSignatureSetEmpty) {
		t.Errorf("verifyDNSKEYs returned unexpected error. expected ErrSignatureSetEmpty, got %v", err)
	}
	if state != Bogus {
		t.Errorf("verifyDNSKEYs returned incorrect state. expected %v, got %v", Bogus, state)
	}

	//---

	// When we have a signed Answer, then we expect Unknown back.

	rrset := []dns.RR{
		newRR("ns1.example.com. 3600 IN A 192.0.2.53"),
	}

	rrset = append(rrset, key.sign(rrset, 0, 0))
	r.msg.Answer = rrset
	state, err = verifyRRSETs(ctx, r, keys)
	if err != nil {
		t.Errorf("verifyRRSETs returned unexpected error: %v", err)
	}
	if state != Unknown {
		t.Errorf("verifyRRSETs returned incorrect state. expected %v, got %v", Unknown, state)
	}
	if len(r.answer) != 1 {
		t.Errorf("expected 1 answer signature, got %d", len(r.answer))
	}

	//---

	// When we have a signed Authority, then we expect Unknown back.

	r.msg.Answer = []dns.RR{}
	r.msg.Ns = rrset

	state, err = verifyRRSETs(ctx, r, keys)
	if err != nil {
		t.Errorf("verifyRRSETs returned unexpected error: %v", err)
	}
	if state != Unknown {
		t.Errorf("verifyRRSETs returned incorrect state. expected %v, got %v", Unknown, state)
	}
	if len(r.authority) != 1 {
		t.Errorf("expected 1 authority signature, got %d", len(r.authority))
	}

	//---

	// When the Answer signature is invalid, we expect Bogus back.

	rrset[1].(*dns.RRSIG).Labels = 0

	r.msg.Answer = rrset
	r.msg.Ns = []dns.RR{}

	state, err = verifyRRSETs(ctx, r, keys)
	if !errors.Is(err, ErrBogusResultFound) {
		t.Errorf("verifyDNSKEYs returned unexpected error. expected ErrBogusResultFound, got %v", err)
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("verifyDNSKEYs returned unexpected error. expected ErrInvalidSignature, got %v", err)
	}
	if state != Bogus {
		t.Errorf("verifyDNSKEYs returned incorrect state. expected %v, got %v", Bogus, state)
	}

	//---

	// When the Authority signature is invalid, we expect Bogus back.

	r.msg.Answer = []dns.RR{}
	r.msg.Ns = rrset

	state, err = verifyRRSETs(ctx, r, keys)
	if !errors.Is(err, ErrBogusResultFound) {
		t.Errorf("verifyDNSKEYs returned unexpected error. expected ErrBogusResultFound, got %v", err)
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("verifyDNSKEYs returned unexpected error. expected ErrInvalidSignature, got %v", err)
	}
	if state != Bogus {
		t.Errorf("verifyDNSKEYs returned incorrect state. expected %v, got %v", Bogus, state)
	}

	//---

	// When the Answer section containers records, but they're not signed, we expect Bogus

	r.msg.Answer = []dns.RR{rrset[0]}
	r.msg.Ns = []dns.RR{}

	state, err = verifyRRSETs(ctx, r, keys)
	if !errors.Is(err, ErrBogusResultFound) {
		t.Errorf("verifyDNSKEYs returned unexpected error. expected ErrBogusResultFound, got %v", err)
	}
	if !errors.Is(err, ErrUnexpectedSignatureCount) {
		t.Errorf("verifyDNSKEYs returned unexpected error. expected ErrUnexpectedSignatureCount, got %v", err)
	}
	if state != Bogus {
		t.Errorf("verifyDNSKEYs returned incorrect state. expected %v, got %v", Bogus, state)
	}

	//---

	// When the Authority section containers records, but they're not signed, we expect Bogus

	r.msg.Answer = []dns.RR{}
	r.msg.Ns = []dns.RR{rrset[0]}

	state, err = verifyRRSETs(ctx, r, keys)
	if !errors.Is(err, ErrBogusResultFound) {
		t.Errorf("verifyDNSKEYs returned unexpected error. expected ErrBogusResultFound, got %v", err)
	}
	if !errors.Is(err, ErrUnexpectedSignatureCount) {
		t.Errorf("verifyDNSKEYs returned unexpected error. expected ErrUnexpectedSignatureCount, got %v", err)
	}
	if state != Bogus {
		t.Errorf("verifyDNSKEYs returned incorrect state. expected %v, got %v", Bogus, state)
	}

}

func TestVerify_DelegatingResponse(t *testing.T) {

	// When NS and DS records are passed, we get the DS record set in the result, and no DOE set.

	ds := newRR("example.com. 54775 IN DS 370 13 2 BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A8 6764247C").(*dns.DS)

	ctx := context.Background()
	r := &result{
		zone: &mockZone{name: zoneName},
		msg: &dns.Msg{
			Ns: []dns.RR{
				ds,
				newRR("example.com. 3600 IN NS ns1.example.com."),
			},
		},
		authority: signatures{{
			rtype: dns.TypeDS,
			rrset: []dns.RR{ds},
		}},
	}

	err := validateDelegatingResponse(ctx, r)
	if err != nil {
		t.Errorf("validateDelegatingResponse returned unexpected error: %v", err)
	}
	if !slices.Equal(r.dsRecords, []*dns.DS{ds}) {
		t.Errorf("unexpected ds records set. expected %v, got %v", ds, r.dsRecords)
	}
	if r.denialOfExistence != NotFound {
		t.Errorf("unexpected denialOfExistence set. expected %v, got %v", NotFound, r.denialOfExistence)
	}

	//---

	// If no DS or NSEC(3) records are set, we expect no DS records in the result, and a DOE state of NotFound.

	r = &result{
		zone: &mockZone{name: zoneName},
		msg: &dns.Msg{
			Ns: []dns.RR{
				newRR("example.com. 3600 IN NS ns1.example.com."),
			},
		},
	}

	err = validateDelegatingResponse(ctx, r)
	if err != nil {
		t.Errorf("validateDelegatingResponse returned unexpected error: %v", err)
	}
	if len(r.dsRecords) != 0 {
		t.Errorf("unexpected ds records set. expected %v, got %v", 0, len(r.dsRecords))
	}
	if r.denialOfExistence != NotFound {
		t.Errorf("unexpected denialOfExistence set. expected %v, got %v", NotFound, r.denialOfExistence)
	}

	//---

	// If the owner names of the NS records don't match, we expect an error.

	r = &result{
		zone: &mockZone{name: zoneName},
		msg: &dns.Msg{
			Ns: []dns.RR{
				newRR("example.com. 3600 IN NS ns1.example.com."),
				newRR("a.example.com. 3600 IN NS ns1.example.com."),
				newRR("example.com. 3600 IN NSEC \000.example.com. A RRSIG NSEC"),
			},
		},
	}

	err = validateDelegatingResponse(ctx, r)
	if !errors.Is(err, ErrNSRecordsHaveMismatchingOwners) {
		t.Errorf("expecter error ErrNSRecordsHaveMismatchingOwners, got: %v", err)
	}

}
