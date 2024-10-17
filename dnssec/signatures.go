package dnssec

import "github.com/miekg/dns"

func (ss signatures) filterOnType(rtype uint16) signatures {
	set := make(signatures, 0, len(ss))
	for _, sig := range ss {
		if sig.rtype == rtype {
			set = append(set, sig)
		}
	}
	return set
}

// Verify a signature set. For a set to be valid, all signatures within it must be valid.
// returns nil if valid; the error as to why it's not valid otherwise.
// Note - if multiple signatures are invalid, only the error for the first is returned.
// https://datatracker.ietf.org/doc/html/rfc4035#section-5.3.3
//
//	If other RRSIG RRs also cover this RRset, the local resolver security
//	policy determines whether the resolver also has to test these RRSIG
//	RRs and how to resolve conflicts if these RRSIG RRs lead to differing
//	results.
//
// TODO: is this the policy we want to use?
func (ss signatures) Verify() error {
	if len(ss) == 0 {
		return ErrSignatureSetEmpty
	}
	for _, s := range ss {
		if !s.verified {
			if s.err != nil {
				return s.err
			}
			return ErrUnableToVerify
		}
	}
	return nil
}

// Valid returns if all signatures in the have been successfully verified.
func (ss signatures) Valid() bool {
	return ss.Verify() == nil
}

// extractDSRecords returns all DS records from within a signature set.
func (ss signatures) extractDSRecords() []*dns.DS {
	parentDSRecords := make([]*dns.DS, 0)
	for _, s := range ss {
		parentDSRecords = append(parentDSRecords, extractRecords[*dns.DS](s.rrset)...)
	}
	return parentDSRecords
}
