package resolver

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestNewNameserverPool_Success(t *testing.T) {
	// Setup: Define valid nameservers (NS) and A/AAAA records
	nsRecords := []*dns.NS{
		{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.com."},
		{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS}, Ns: "ns2.example.com."},
	}

	// A (IPv4) and AAAA (IPv6) records for the nameservers
	extraRecords := []dns.RR{
		// ns1.example.com IPv4 and IPv6
		&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA}, A: net.IPv4(192, 0, 2, 1)},
		&dns.AAAA{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeAAAA}, AAAA: net.IP{0x20, 0x01, 0xdb, 0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}},

		// ns2.example.com IPv4 and IPv6
		&dns.A{Hdr: dns.RR_Header{Name: "ns2.example.com.", Rrtype: dns.TypeA}, A: net.IPv4(192, 0, 2, 2)},
		&dns.AAAA{Hdr: dns.RR_Header{Name: "ns2.example.com.", Rrtype: dns.TypeAAAA}, AAAA: net.IP{0x20, 0x01, 0xdb, 0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2}},
	}

	// Execute: Create the nameserver pool
	pool := newNameserverPool(nsRecords, extraRecords)

	// Assertions: Ensure the pool contains the expected nameservers with correct addresses
	assert.NotNil(t, pool)

	assert.Len(t, pool.hostsWithoutAddresses, 0)
	assert.Len(t, pool.ipv4, 2)
	assert.Len(t, pool.ipv6, 2)

	ips := make([]string, 4)
	for i, ip := range append(pool.ipv4, pool.ipv6...) {
		ips[i] = ip.(*nameserver).addr
	}

	assert.Contains(t, ips, "192.0.2.1")
	assert.Contains(t, ips, "192.0.2.2")
	assert.Contains(t, ips, "2001:db08::1")
	assert.Contains(t, ips, "2001:db08::2")
}
