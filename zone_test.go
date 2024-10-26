package resolver

import (
	"context"
	"github.com/stretchr/testify/mock"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

// Test cases for zone

func TestZone_Exchange_NilPool(t *testing.T) {
	// Setup
	z := &zone{name: "example.com."}

	// Prepare a DNS message
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	ctx := context.TODO()

	// Execute
	response := z.Exchange(ctx, msg)

	// Assertions: Should return an error since the pool is nil
	assert.ErrorIs(t, response.Err, ErrNoPoolConfiguredForZone)
}

func TestZone_Exchange_WithPool(t *testing.T) {
	// Setup
	z := &zone{name: "example.com."}
	mockPool := new(MockExpiringExchanger)
	z.pool = mockPool

	// Prepare a DNS message
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	ctx := context.TODO()

	expectedResponse := &Response{Msg: msg, Duration: 10 * time.Millisecond}

	ctxMatcher := mock.MatchedBy(func(c context.Context) bool {
		return true // Always returns true because we are just checking that it implements context.Context
	})

	// Mock the exchange function to accept any context and return the expected response
	mockPool.On("exchange", ctxMatcher, msg).Return(expectedResponse)

	// Execute
	response := z.Exchange(ctx, msg)

	// Assertions: Should return the result from the pool
	assert.NoError(t, response.Err)
	assert.Equal(t, expectedResponse, response)

	ctxMatcher = mock.MatchedBy(func(c context.Context) bool {
		// We text the expected ctx was passed in the `AssertCalled` below.
		return c.Value(ctxZoneName).(string) == "example.com."
	})
	mockPool.AssertCalled(t, "exchange", ctxMatcher, msg)
}

func TestZone_Clone(t *testing.T) {
	// Setup
	originalZone := &zone{name: "example.com."}
	mockPool := new(MockExpiringExchanger)
	originalZone.pool = mockPool

	// Execute: Clone the zone with a new name
	clonedZone := originalZone.clone("newzone.com.")

	// Assertions: The new zone should have a new name but share the same pool
	assert.Equal(t, "newzone.com.", clonedZone.name)
	assert.Equal(t, originalZone.pool, clonedZone.pool)

	assert.Empty(t, clonedZone.dnskeys)
	assert.Empty(t, clonedZone.dnskeyExpiry)
}

func TestZone_DNSKeys_CachedAndValid(t *testing.T) {
	// Setup
	z := &zone{name: "example.com."}
	mockRR := []dns.RR{&dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300}}}
	z.dnskeys = mockRR
	z.dnskeyExpiry = time.Now().Add(time.Hour) // Keys are still valid

	// Execute
	ctx := context.TODO()
	keys, err := z.dnsKeys(ctx)

	// Assertions: Should return the cached keys and no error
	assert.NoError(t, err)
	assert.Equal(t, mockRR, keys)
}

func TestZone_DNSKeys_Expired(t *testing.T) {
	// Setup
	z := &zone{name: "example.com."}
	mockPool := new(MockExpiringExchanger)
	z.pool = mockPool

	// Prepare an expired DNS key
	z.dnskeyExpiry = time.Now().Add(-time.Hour) // Keys are expired

	expectedResponse := &Response{
		Msg: &dns.Msg{
			Answer: []dns.RR{&dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300}}},
		},
	}

	// Mock the exchange function
	mockPool.On("exchange", mock.Anything, mock.AnythingOfType("*dns.Msg")).Return(expectedResponse)

	// Execute
	ctx := context.TODO()
	keys, err := z.dnsKeys(ctx)

	// Assertions: Should return the new keys and no error
	assert.NoError(t, err)
	assert.Equal(t, expectedResponse.Msg.Answer, keys)
	mockPool.AssertCalled(t, "exchange", mock.Anything, mock.AnythingOfType("*dns.Msg"))
}
