package dnssec

import (
	"context"
	"github.com/miekg/dns"
	"slices"
	"testing"
)

type testNsec3RRSets struct {
	key []*dns.DNSKEY

	closestEncloser []dns.RR
	nextCloserName  []dns.RR
	wildcardCovers  []dns.RR
	wildcardMatches []dns.RR
	qnameMatches    []dns.RR
}

func getTestNsec3RRSets() testNsec3RRSets {
	/*
		hash(example.com.) = 111NOTAB271SNH4EA8ESDKBF1C2QINH1
		hash(*.example.com.) = 3MFPR9I7C49K59BM8VU2HM71CCR7BH0B
		hash(test.example.com.) = L72QU4B0R4USH96QN17VTCD8395QILEQ

		Generated with:
		digest := dns.HashName(domain, dns.SHA1, uint16(2), "abcdef")
	*/

	r := testNsec3RRSets{}

	// The ClosestEncloser
	r.closestEncloser = []dns.RR{
		// example.com (apex)
		newRR("111NOTAB271SNH4EA8ESDKBF1C2QINH1.example.com. 3600 IN NSEC3 1 0 2 ABCDEF 211NOTAB271SNH4EA8ESDKBF1C2QINH1 SOA RRSIG"),
	}

	// The Next Closer name
	r.nextCloserName = []dns.RR{
		// test. == L72QU4B0R4USH96QN17VTCD8395QILEQ
		// So we need two hashes that cover that hash.
		newRR("K72QU4B0R4USH96QN17VTCD8395QILEQ.example.com. 3600 IN NSEC3 1 0 2 ABCDEF M72QU4B0R4USH96QN17VTCD8395QILEQ A RRSIG"),
	}

	// The Wildcard (cover)
	r.wildcardCovers = []dns.RR{
		// *. == 3MFPR9I7C49K59BM8VU2HM71CCR7BH0B
		// So we need two hashes that cover that hash.
		newRR("2MFPR9I7C49K59BM8VU2HM71CCR7BH0B.example.com. 3600 IN NSEC3 1 0 2 ABCDEF 4MFPR9I7C49K59BM8VU2HM71CCR7BH0B A RRSIG"),
	}

	// The Wildcard (match)
	r.wildcardMatches = []dns.RR{
		// *.example.com
		newRR("3MFPR9I7C49K59BM8VU2HM71CCR7BH0B.example.com. 3600 IN NSEC3 1 0 2 ABCDEF 3NFPR9I7C49K59BM8VU2HM71CCR7BH0B A RRSIG"),
	}

	// The QName (match)
	r.qnameMatches = []dns.RR{
		// test.example.com
		newRR("L72QU4B0R4USH96QN17VTCD8395QILEQ.example.com. 3600 IN NSEC3 1 0 2 ABCDEF T0B6SHHJ0JQRI032RVVLMCGGNHCVF5UM A RRSIG"),
	}

	key := testEcKey()
	r.key = []*dns.DNSKEY{key.key}

	// Sign them all
	r.closestEncloser = append(r.closestEncloser, key.sign(r.closestEncloser, 0, 0))
	r.nextCloserName = append(r.nextCloserName, key.sign(r.nextCloserName, 0, 0))
	r.wildcardCovers = append(r.wildcardCovers, key.sign(r.wildcardCovers, 0, 0))
	r.wildcardMatches = append(r.wildcardMatches, key.sign(r.wildcardMatches, 0, 0))
	r.qnameMatches = append(r.qnameMatches, key.sign(r.qnameMatches, 0, 0))

	return r
}

func TestDenialOfExistenceNSEC3_BitMap(t *testing.T) {

	// NSEC3: Hash Algorithm, Flags (optout), Iterations, Salt Length, Salt, Next Hashed Owner name, Type Bit Maps

	rrset := []dns.RR{
		// test.example.com
		newRR("L72QU4B0R4USH96QN17VTCD8395QILEQ.example.com. 3600 IN NSEC3 1 0 2 ABCDEF T0B6SHHJ0JQRI032RVVLMCGGNHCVF5UM A RRSIG"),
	}

	key := testEcKey()
	rrset = append(rrset, key.sign(rrset, 0, 0))

	set, err := authenticate(zoneName, rrset, []*dns.DNSKEY{key.key}, answerSection)
	if err != nil || !set.Valid() {
		panic("cannot setup test")
	}

	nsec3 := newDenialOfExistenceNSEC3(context.Background(), zoneName, set)

	nameSeen, typeSeen := nsec3.typeBitMapContainsAnyOf("test.example.com.", []uint16{dns.TypeA})
	if !nameSeen || !typeSeen {
		t.Error("we expect both the name and type to be seen")
	}

	nameSeen, typeSeen = nsec3.typeBitMapContainsAnyOf("test.example.com.", []uint16{dns.TypeAAAA})
	if !nameSeen || typeSeen {
		t.Error("we expect the name to be seen, but not the type")
	}

	nameSeen, typeSeen = nsec3.typeBitMapContainsAnyOf("other.example.com.", []uint16{dns.TypeA})
	if nameSeen || typeSeen {
		// Note that we only expect a type to be seen if the name is also seen.
		// i.e. we only inspect a NSEC3 record's BitMap if it matches the name.
		t.Error("we expect neither the name or type to be seen")
	}

}

func TestDenialOfExistenceNSEC3_ClosestEncloserProof(t *testing.T) {

	r := getTestNsec3RRSets()

	set, err := authenticate(zoneName, slices.Concat(r.closestEncloser, r.nextCloserName, r.wildcardCovers), r.key, answerSection)
	if err != nil || !set.Valid() {
		panic("cannot setup test")
	}

	nsec3 := newDenialOfExistenceNSEC3(context.Background(), zoneName, set)

	// We expect no optout, and the other three proofs should be true.
	optedOut, closestEncloserProof, nextCloserNameProof, wildcardProof := nsec3.performClosestEncloserProof("test.example.com.")
	if optedOut || !closestEncloserProof || !nextCloserNameProof || !wildcardProof {
		t.Error("we expected all 3 proofs to be met")
	}

	//---

	set, err = authenticate(zoneName, slices.Concat(r.closestEncloser, r.nextCloserName, r.wildcardCovers, r.qnameMatches), r.key, answerSection)
	if err != nil || !set.Valid() {
		panic("cannot setup test")
	}

	nsec3 = newDenialOfExistenceNSEC3(context.Background(), zoneName, set)

	optedOut, closestEncloserProof, nextCloserNameProof, wildcardProof = nsec3.performClosestEncloserProof("test.example.com.")
	if optedOut || !closestEncloserProof || nextCloserNameProof || !wildcardProof {
		t.Error("if a nsec3 record was found to match the qname, we expect the nextCloserName proof to fail")
	}

	//---

	set, err = authenticate(zoneName, slices.Concat(r.closestEncloser, r.nextCloserName, r.wildcardCovers, r.wildcardMatches), r.key, answerSection)
	if err != nil || !set.Valid() {
		panic("cannot setup test")
	}

	nsec3 = newDenialOfExistenceNSEC3(context.Background(), zoneName, set)

	optedOut, closestEncloserProof, nextCloserNameProof, wildcardProof = nsec3.performClosestEncloserProof("test.example.com.")
	if optedOut || !closestEncloserProof || !nextCloserNameProof || wildcardProof {
		t.Error("if a nsec3 record was found to match the wildcard, we expect the wildcardProof proof to fail")
	}

	//---

	set, err = authenticate(zoneName, slices.Concat(r.closestEncloser, r.nextCloserName), r.key, answerSection)
	if err != nil || !set.Valid() {
		panic("cannot setup test")
	}

	nsec3 = newDenialOfExistenceNSEC3(context.Background(), zoneName, set)

	optedOut, closestEncloserProof, nextCloserNameProof, wildcardProof = nsec3.performClosestEncloserProof("test.example.com.")
	if optedOut || !closestEncloserProof || !nextCloserNameProof || wildcardProof {
		t.Error("we expected this to fail on the wildcard proof")
	}

	//---

	set, err = authenticate(zoneName, slices.Concat(r.closestEncloser, r.wildcardCovers), r.key, answerSection)
	if err != nil || !set.Valid() {
		panic("cannot setup test")
	}

	nsec3 = newDenialOfExistenceNSEC3(context.Background(), zoneName, set)

	optedOut, closestEncloserProof, nextCloserNameProof, wildcardProof = nsec3.performClosestEncloserProof("test.example.com.")
	if optedOut || !closestEncloserProof || nextCloserNameProof || !wildcardProof {
		t.Error("we expected this to fail on the next closer name proof")
	}

	//---

	set, err = authenticate(zoneName, slices.Concat(r.nextCloserName, r.wildcardCovers), r.key, answerSection)
	if err != nil || !set.Valid() {
		panic("cannot setup test")
	}

	nsec3 = newDenialOfExistenceNSEC3(context.Background(), zoneName, set)

	optedOut, closestEncloserProof, nextCloserNameProof, wildcardProof = nsec3.performClosestEncloserProof("test.example.com.")
	if optedOut || closestEncloserProof || nextCloserNameProof || wildcardProof {
		t.Error("when the closest enclose proof is not met, we expect everything to be false")
	}

	//---

	set = make(signatures, 0)
	nsec3 = newDenialOfExistenceNSEC3(context.Background(), zoneName, set)

	optedOut, closestEncloserProof, nextCloserNameProof, wildcardProof = nsec3.performClosestEncloserProof("test.example.com.")
	if optedOut || closestEncloserProof || nextCloserNameProof || wildcardProof {
		t.Error("when not signatures are set, we expect everything to be false")
	}

}

func TestDenialOfExistenceNSEC3_WildcardProof(t *testing.T) {

	r := getTestNsec3RRSets()

	wildcardRR := []dns.RR{newRR("*.example.com. 3600 IN A 192.0.2.53")} //

	key := testEcKey()
	wildcardRR = append(wildcardRR, key.sign(wildcardRR, 0, 0))

	wildcardRR[0].Header().Name = dns.Fqdn("test.example.com.")
	wildcardRR[1].Header().Name = dns.Fqdn("test.example.com.")

	//---

	set, err := authenticate(zoneName, slices.Concat(wildcardRR, r.nextCloserName), append(r.key, key.key), answerSection)
	if err != nil || !set.Valid() {
		panic("cannot setup test")
	}

	nsec3 := newDenialOfExistenceNSEC3(context.Background(), zoneName, set)

	// The first set contains the wildcard signature
	verified := nsec3.performExpandedWildcardProof(set[0])
	if !verified {
		t.Error("we expected this to be valid as there's doe for the next closer name, but not the wildcard")
	}

	//---

	set, err = authenticate(zoneName, slices.Concat(wildcardRR), append(r.key, key.key), answerSection)
	if err != nil || !set.Valid() {
		panic("cannot setup test")
	}

	nsec3 = newDenialOfExistenceNSEC3(context.Background(), zoneName, set)

	// The first set contains the wildcard signature
	verified = nsec3.performExpandedWildcardProof(set[0])
	if verified {
		t.Error("we expect this to fail as there's no next closer name")
	}

	//---

	set, err = authenticate(zoneName, slices.Concat(wildcardRR, r.nextCloserName, r.wildcardCovers), append(r.key, key.key), answerSection)
	if err != nil || !set.Valid() {
		panic("cannot setup test")
	}

	nsec3 = newDenialOfExistenceNSEC3(context.Background(), zoneName, set)

	// The first set contains the wildcard signature
	verified = nsec3.performExpandedWildcardProof(set[0])
	if verified {
		t.Error("we expect this to fail as there's doe for the wildcard record")
	}

	//---

	set, err = authenticate(zoneName, slices.Concat(wildcardRR, r.nextCloserName, r.wildcardMatches), append(r.key, key.key), answerSection)
	if err != nil || !set.Valid() {
		panic("cannot setup test")
	}

	nsec3 = newDenialOfExistenceNSEC3(context.Background(), zoneName, set)

	// The first set contains the wildcard signature
	verified = nsec3.performExpandedWildcardProof(set[0])
	if verified {
		t.Error("we expect this to fail as there's doe for the wildcard record")
	}
}

func TestDenialOfExistenceNSEC3_Optout(t *testing.T) {

	// NSEC3: Hash Algorithm, Flags (optout), Iterations, Salt Length, Salt, Next Hashed Owner name, Type Bit Maps

	// We set the OptOut flag to 1 on the below.

	// The ClosestEncloser
	closestEncloser := []dns.RR{
		// example.com (apex)
		newRR("111NOTAB271SNH4EA8ESDKBF1C2QINH1.example.com. 3600 IN NSEC3 1 1 2 ABCDEF 211NOTAB271SNH4EA8ESDKBF1C2QINH1 SOA RRSIG"),
	}

	// Covers `test.`
	nextCloserName := []dns.RR{
		// test. == L72QU4B0R4USH96QN17VTCD8395QILEQ
		// So we need two hashes that cover that hash.
		newRR("K72QU4B0R4USH96QN17VTCD8395QILEQ.example.com. 3600 IN NSEC3 1 1 2 ABCDEF M72QU4B0R4USH96QN17VTCD8395QILEQ A RRSIG"),
	}

	key := testEcKey()
	closestEncloser = append(closestEncloser, key.sign(closestEncloser, 0, 0))
	nextCloserName = append(nextCloserName, key.sign(nextCloserName, 0, 0))

	set, err := authenticate(zoneName, slices.Concat(nextCloserName, closestEncloser), []*dns.DNSKEY{key.key}, answerSection)
	if err != nil || !set.Valid() {
		panic("cannot setup test")
	}

	nsec3 := newDenialOfExistenceNSEC3(context.Background(), zoneName, set)

	optedOut, _, _, _ := nsec3.performClosestEncloserProof("test.example.com.")
	if !optedOut {
		t.Error("we expect the proof to to state that they're opted-out")
	}

}

func TestDenialOfExistenceNSEC3_InvalidValues(t *testing.T) {

	// NSEC3 records that have an invalid hash value, or an invalid Flags field, must be ignored.

	// NSEC3: Hash Algorithm, Flags (optout), Iterations, Salt Length, Salt, Next Hashed Owner name, Type Bit Maps

	// The only allowed Hash Algorithm value is 1. Here we change it to 5.
	closestEncloser := []dns.RR{
		// example.com (apex)
		newRR("111NOTAB271SNH4EA8ESDKBF1C2QINH1.example.com. 3600 IN NSEC3 5 0 2 ABCDEF 211NOTAB271SNH4EA8ESDKBF1C2QINH1 SOA RRSIG"),
	}

	// The only allowed Flags values are 0 or 1. Here we change it to 5. Note that we've already tested 0 and 1 o other tests.
	nextCloserName := []dns.RR{
		// test. == L72QU4B0R4USH96QN17VTCD8395QILEQ
		// So we need two hashes that cover that hash.
		newRR("K72QU4B0R4USH96QN17VTCD8395QILEQ.example.com. 3600 IN NSEC3 1 5 2 ABCDEF M72QU4B0R4USH96QN17VTCD8395QILEQ A RRSIG"),
	}

	key := testEcKey()
	closestEncloser = append(closestEncloser, key.sign(closestEncloser, 0, 0))
	nextCloserName = append(nextCloserName, key.sign(nextCloserName, 0, 0))

	set, err := authenticate(zoneName, slices.Concat(nextCloserName, closestEncloser), []*dns.DNSKEY{key.key}, answerSection)
	if err != nil || !set.Valid() {
		panic("cannot setup test")
	}

	nsec3 := newDenialOfExistenceNSEC3(context.Background(), zoneName, set)

	if !nsec3.empty() {
		t.Error("we expect there to be no nsec3 records to check as both that were passed should be ignored")
	}

	// We've tested in previous tests that proofs fail if nsec3.empty() is true.

}
