package dnssec

import "github.com/nsmithuk/dnssec-root-anchors-go/anchors"

const (
	DefaultRequireAllSignaturesValid = false
)

var (
	RootTrustAnchors = anchors.GetValid()

	// RequireAllSignaturesValid
	// If false (default), then one or more RRSIG per RRSET must be valid for the overall state to be valid.
	// If true, _all_ RRSIGs returned must be valid for the overall state to be valid.
	//
	// Note:
	//  https://datatracker.ietf.org/doc/html/rfc4035#section-5.3.3
	//	If other RRSIG RRs also cover this RRset, the local resolver security
	//	policy determines whether the resolver also has to test these RRSIG
	//	RRs and how to resolve conflicts if these RRSIG RRs lead to differing
	//	results.
	RequireAllSignaturesValid = DefaultRequireAllSignaturesValid
)

type Logger func(string)

// Default logging functions just black-hole the input.

var Debug Logger = func(s string) {}
var Info Logger = func(s string) {}
var Warn Logger = func(s string) {}
