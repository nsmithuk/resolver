package resolver

import (
	"fmt"
	"github.com/miekg/dns"
	"slices"
)

type domain struct {
	name               string
	labelIndexes       []int
	currentIdxPosition int
}

func newDomain(d string) domain {
	d = dns.CanonicalName(d)
	labelIndexes := append(dns.Split(d), len(d)-1)
	slices.Reverse(labelIndexes)
	return domain{
		name:         d,
		labelIndexes: labelIndexes,
	}
}

func (d *domain) windTo(s string) error {
	s = dns.CanonicalName(s)
	for ; !d.end(); d.next() {
		if d.current() == s {
			return nil
		}
	}
	return fmt.Errorf("%s not found", s)
}

// Returns the domain segment starting from the current label position.
// This segment represents the current FQDN as seen from the current position in the label hierarchy.
func (d *domain) current() string {
	idx := d.currentIdxPosition
	if d.currentIdxPosition >= len(d.labelIndexes) {
		idx = len(d.labelIndexes) - 1
	}
	return d.name[d.labelIndexes[idx]:]
}

// Retrieves the next domain segment in the hierarchy without moving the position.
// Returns a boolean indicating if a next label exists to ensure safe retrieval.
//func (d *domain) next() (string, bool) {
//	if !d.more() {
//		return "", false
//	}
//	return d.name[d.labelIndexes[d.currentIdxPosition+1]:], true
//}

func (d *domain) next() bool {
	d.currentIdxPosition++
	return true
}

// Checks if there are additional labels remaining in the domain hierarchy to traverse.
func (d *domain) more() bool {
	return d.currentIdxPosition+1 < len(d.labelIndexes)
}

func (d *domain) end() bool {
	return d.currentIdxPosition > len(d.labelIndexes)
}

// Advances the current label position to the next label in the domain hierarchy.
// Does nothing if no more labels are available, allowing safe iteration.
//func (d *domain) advance() {
//	if d.more() {
//		d.currentIdxPosition++
//	}
//}
//
//func (d *domain) isLast() bool {
//	return !d.more()
//}

// Computes and returns any intermediate domain segments between the current position
// and a target domain with more labels. Each segment is an FQDN derived from the original domain,
// enabling traversal up the hierarchy to the target.
func (d *domain) gap(s string) []string {
	missing := dns.CountLabel(s) - dns.CountLabel(d.current())
	if missing < 1 {
		return []string{}
	}

	results := make([]string, 0, missing)
	for i := d.currentIdxPosition; i < missing+d.currentIdxPosition; i++ {
		results = append(results, d.name[d.labelIndexes[i]:])
	}
	return results
}
