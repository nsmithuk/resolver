package dnssec

import (
	"context"
	"github.com/miekg/dns"
)

type verifier struct {
	verifyDNSKEYs              func(ctx context.Context, r *result, keys []dns.RR, dsRecordsFromParent []*dns.DS) (AuthenticationResult, error)
	verifyRRSETs               func(ctx context.Context, r *result, keys []*dns.DNSKEY) (AuthenticationResult, error)
	validateDelegatingResponse func(ctx context.Context, r *result) (status AuthenticationResult, err error)
	validatePositiveResponse   func(ctx context.Context, r *result) (status AuthenticationResult, err error)
	validateNegativeResponse   func(ctx context.Context, r *result) (AuthenticationResult, error)
}
