package dnssec

import (
	"github.com/miekg/dns"
	"slices"
	"strconv"
	"strings"
)

func (doe *denialOfExistenceNSEC) performQNameDoesNotExistProof(qname string) bool {
	return doe.verifyQNameCovered(qname) && doe.verifyWildcardCovered(qname)
}

func (doe *denialOfExistenceNSEC) performExpandedWildcardProof(qname string) bool {
	return doe.verifyQNameCovered(qname) && !doe.verifyWildcardCovered(qname)
}

func (doe *denialOfExistenceNSEC) verifyQNameCovered(qname string) bool {
	qname = dns.CanonicalName(qname)

	/*
		https://datatracker.ietf.org/doc/html/rfc3845#section-2.1.1
		The value of the Next Domain Name field in the last NSEC record in the zone is the name of the
		zone apex (the owner name of the zone's SOA RR).
	*/

	for _, nsec := range doe.records {
		qnameAfterNsecOwnerName := canonicalCmp(nsec.Header().Name, qname) < 0
		qnameBeforeNextDomain := dns.CanonicalName(nsec.NextDomain) == doe.zone || canonicalCmp(qname, nsec.NextDomain) < 0

		if qnameAfterNsecOwnerName && qnameBeforeNextDomain {
			return true
		}
	}

	return false
}

func (doe *denialOfExistenceNSEC) verifyWildcardCovered(qname string) bool {
	qname = dns.CanonicalName(qname)

	/*
		https://datatracker.ietf.org/doc/html/rfc3845#section-2.1.1
		The value of the Next Domain Name field in the last NSEC record in the zone is the name of the
		zone apex (the owner name of the zone's SOA RR).
	*/

	wildcard := wildcardName(qname)

	for _, nsec := range doe.records {
		wildcardAfterNsecOwnerName := canonicalCmp(nsec.Header().Name, wildcard) < 0
		wildcardBeforeNextDomain := dns.CanonicalName(nsec.NextDomain) == doe.zone || canonicalCmp(wildcard, nsec.NextDomain) < 0

		if wildcardAfterNsecOwnerName && wildcardBeforeNextDomain {
			return true
		}
	}

	return false
}

func (doe *denialOfExistenceNSEC) typeBitMapContainsAnyOf(name string, types []uint16) (nameSeen, typeSeen bool) {

	for _, nsec := range doe.records {
		if name != dns.CanonicalName(nsec.Header().Name) {
			continue
		}

		nameSeen = true

		for _, t := range types {
			if slices.Contains(nsec.TypeBitMap, t) {
				return nameSeen, true
			}
		}
	}

	return nameSeen, false
}

func canonicalCmp(a, b string) int {
	labelsA := dns.SplitDomainName(dns.CanonicalName(a))
	labelsB := dns.SplitDomainName(dns.CanonicalName(b))

	minLength := min(len(labelsA), len(labelsB))

	for i := 1; i <= minLength; i++ {
		labelA := labelsA[len(labelsA)-i]
		labelB := labelsB[len(labelsB)-i]

		// Convert labels to lowercase and decode escaped characters
		if strings.Contains(labelA, `\`) {
			labelA = canonicalDecodeEscaped(labelA)
		}
		if strings.Contains(labelB, `\`) {
			labelB = canonicalDecodeEscaped(labelB)
		}

		// Compare lexicographically
		if labelA != labelB {
			if labelA < labelB {
				return -1
			}
			return 1
		}
	}

	// If labels are identical so far, the shorter one sorts first
	if len(labelsA) < len(labelsB) {
		return -1
	} else if len(labelsA) > len(labelsB) {
		return 1
	}
	return 0
}

// Convert escaped octets (e.g., \001) to their byte values for comparison
func canonicalDecodeEscaped(label string) string {
	decoded := ""
	for i := 0; i < len(label); i++ {
		if label[i] == '\\' && i+3 < len(label) && canonicalIsDigit(label[i+1]) && canonicalIsDigit(label[i+2]) && canonicalIsDigit(label[i+3]) {
			// Decode escaped octet as a numeric value
			octetValue, err := strconv.Atoi(label[i+1 : i+4])
			if err == nil {
				decoded += string(rune(octetValue))
			}
			i += 3 // Skip the escaped characters
		} else {
			decoded += string(label[i])
		}
	}
	return decoded
}

// Check if a character is a digit
func canonicalIsDigit(b byte) bool {
	return b >= '0' && b <= '9'
}
