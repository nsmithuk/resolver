package dnssec

import (
	"fmt"
	"github.com/miekg/dns"
)

func (ss signatures) filterOnType(rtype uint16) signatures {
	set := make(signatures, 0, len(ss))
	for _, sig := range ss {
		if sig.rtype == rtype {
			set = append(set, sig)
		}
	}
	return set
}

func (ss signatures) countNameTypeCombinations() int {
	type combination struct {
		name   string
		rrtype uint16
	}
	combinations := make(map[combination]bool, len(ss))
	for _, sig := range ss {
		combinations[combination{
			name:   sig.name,
			rrtype: sig.rtype,
		}] = true
	}
	return len(combinations)
}

// Verify a signature set. For a set to be valid, all signatures within it must be valid. A nil error will be returned in this case.
// If one or more errors are found, we make the local policy decision to conclude the whole response is invalid.
// All errors will be returns, wrapped into a single error.
//
// https://datatracker.ietf.org/doc/html/rfc4035#section-5.3.3
//
//	If other RRSIG RRs also cover this RRset, the local resolver security
//	policy determines whether the resolver also has to test these RRSIG
//	RRs and how to resolve conflicts if these RRSIG RRs lead to differing
//	results.
//
// TODO: It seems the norm is to accept one or more valid RRSIG per RRSET.
func (ss signatures) Verify() error {
	if len(ss) == 0 {
		return ErrSignatureSetEmpty
	}

	var err error
	for _, s := range ss {
		if !s.verified {
			if err == nil {
				// This should always be the first error in the stack
				err = ErrVerifyFailed
			}

			// We then nest the more specific errors
			if s.err != nil {
				err = fmt.Errorf("%w / %w", err, s.err)
			} else {
				err = fmt.Errorf("%w / %w", err, ErrUnableToVerify)
			}
		}
	}

	return err
}

// Valid returns if all signatures in the have been successfully verified.
func (ss signatures) Valid() bool {
	return ss.Verify() == nil
}

// extractDSRecords returns all DS records from signatures with a rrtype of DS.
func (ss signatures) extractDSRecords() []*dns.DS {
	parentDSRecords := make([]*dns.DS, 0)
	for _, s := range ss.filterOnType(dns.TypeDS) {
		parentDSRecords = append(parentDSRecords, extractRecords[*dns.DS](s.rrset)...)
	}
	return parentDSRecords
}

func (ss signatures) extractNSECRecords() []*dns.NSEC {
	parentDSRecords := make([]*dns.NSEC, 0)
	for _, s := range ss.filterOnType(dns.TypeNSEC) {
		parentDSRecords = append(parentDSRecords, extractRecords[*dns.NSEC](s.rrset)...)
	}
	return parentDSRecords
}

func (ss signatures) extractNSEC3Records() []*dns.NSEC3 {
	parentDSRecords := make([]*dns.NSEC3, 0)
	for _, s := range ss.filterOnType(dns.TypeNSEC3) {
		parentDSRecords = append(parentDSRecords, extractRecords[*dns.NSEC3](s.rrset)...)
	}
	return parentDSRecords
}
