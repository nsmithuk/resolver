package dnssec

import (
	"context"
	"github.com/miekg/dns"
	"sync"
	"sync/atomic"
)

type Zone interface {
	Name() string
	LookupDS(qname string) (*dns.Msg, error)
	LookupDNSKEY(qname string) ([]dns.RR, error)
}

// wrappedZone retains access to the parent lookup methods, but allows the zone name to be overridden.
type wrappedZone struct {
	name   string
	parent Zone
}

type Lookup func(zone string, msg *dns.Msg) (*dns.Msg, error)

type DsLookup func(zone, signer string) (*dns.Msg, error)

type Authenticator struct {
	ctx context.Context

	question *dns.Question

	close    sync.Once
	finished atomic.Bool

	queue      chan input
	processing *sync.WaitGroup

	results []*result
}

type input struct {
	zone Zone
	msg  *dns.Msg
}

type result struct {
	name string
	zone Zone
	msg  *dns.Msg

	keys      signatures
	answer    signatures
	authority signatures

	err error

	dsRecords []*dns.DS

	state             AuthenticationResult
	denialOfExistence DenialOfExistenceState
}

type signatures []*signature

// Represents a single signature (rrsig), along with its key, and the records is signs.
type signature struct {
	zone string

	name  string
	rtype uint16

	key   *dns.DNSKEY
	rrsig *dns.RRSIG
	rrset []dns.RR

	wildcard bool

	verified bool
	err      error

	dsSha256 string // For debugging
}
