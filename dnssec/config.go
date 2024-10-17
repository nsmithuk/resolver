package dnssec

import "github.com/nsmithuk/dnssec-root-anchors-go/anchors"

var (
	RootTrustAnchors = anchors.GetValid()
)

type Logger func(string)

// Default logging functions just black-hole the input.

var Debug Logger = func(s string) {}
var Info Logger = func(s string) {}
var Warn Logger = func(s string) {}
