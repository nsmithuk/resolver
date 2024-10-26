package resolver

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

type NameserverPoolStatus uint8

const (
	PoolEmpty NameserverPoolStatus = iota
	PoolExpired
	PoolHasHostnamesButNoIpAddresses
	PrimedButNeedsEnhancing
	PoolPrimed
)

type nameserverPool struct {
	hostsWithoutAddresses []string

	ipv4     []exchanger
	ipv4Next atomic.Uint32

	ipv6     []exchanger
	ipv6Next atomic.Uint32

	updating sync.RWMutex
	enriched sync.Once

	expires time.Time
}

func (pool *nameserverPool) hasIPv4() bool {
	return pool.countIPv4() > 0
}

func (pool *nameserverPool) hasIPv6() bool {
	return pool.countIPv6() > 0
}

func (pool *nameserverPool) countIPv4() int {
	pool.updating.RLock()
	c := len(pool.ipv4)
	pool.updating.RUnlock()
	return c
}

func (pool *nameserverPool) countIPv6() int {
	pool.updating.RLock()
	c := len(pool.ipv6)
	pool.updating.RUnlock()
	return c
}

func (pool *nameserverPool) getIPv4() exchanger {
	pool.updating.RLock()
	defer pool.updating.RUnlock()

	if pool.hasIPv4() {
		// Increments to the next server each time.
		// There's a race condition here, but the outcome isn't "important" enough to warrant locking.
		ipv4Next := pool.ipv4Next.Load() % uint32(len(pool.ipv4))
		pool.ipv4Next.Store(ipv4Next + 1)
		return pool.ipv4[ipv4Next]
	}
	return nil
}

func (pool *nameserverPool) getIPv6() exchanger {
	pool.updating.RLock()
	defer pool.updating.RUnlock()

	if pool.hasIPv6() {
		// Increments to the next server each time.
		// There's a race condition here, but the outcome isn't "important" enough to warrant locking.
		ipv6Next := pool.ipv6Next.Load() % uint32(len(pool.ipv6))
		pool.ipv6Next.Store(ipv6Next + 1)
		return pool.ipv6[ipv6Next]
	}
	return nil
}

//---

func (pool *nameserverPool) expired() bool {
	pool.updating.RLock()
	b := !pool.expires.IsZero() && pool.expires.Before(time.Now())
	pool.updating.RUnlock()
	return b
}

func (pool *nameserverPool) status() NameserverPoolStatus {
	pool.updating.RLock()
	defer pool.updating.RUnlock()

	ipv4Count := pool.countIPv4()
	ipv6Count := pool.countIPv6()

	if ipv4Count == 0 && ipv6Count == 0 && len(pool.hostsWithoutAddresses) == 0 {
		return PoolEmpty
	}

	total := ipv4Count
	if IPv6Available() {
		total = total + ipv6Count
	}

	if total == 0 {
		return PoolHasHostnamesButNoIpAddresses
	}

	// If there are unknown addresses, and we have less than x IPs, then we want to enrich.
	if total < DesireNumberOfNameserversPerZone && len(pool.hostsWithoutAddresses) > 0 {
		return PrimedButNeedsEnhancing
	}

	return PoolPrimed
}

func newNameserverPool(nameservers []*dns.NS, extra []dns.RR) *nameserverPool {
	pool := &nameserverPool{}

	var ttl = MaxTTLAllowed
	pool.hostsWithoutAddresses = make([]string, 0, len(nameservers))

	for _, rr := range nameservers {
		hostname := canonicalName(rr.Ns)

		if hostname == "b.gtld-servers.net." {
			// I don't like this server.
			continue
		}

		ttl = min(rr.Header().Ttl, ttl)

		//---

		a, aaaa, minTtlSeen := findAddressesForHostname(hostname, extra)

		if len(a) == 0 && len(aaaa) == 0 {
			pool.hostsWithoutAddresses = append(pool.hostsWithoutAddresses, hostname)
			continue
		}

		//---

		ttl = min(minTtlSeen, ttl)

		for _, addr := range a {
			pool.ipv4 = append(pool.ipv4, &nameserver{
				hostname: addr.Header().Name,
				addr:     addr.A.String(),
			})
		}

		for _, addr := range aaaa {
			pool.ipv6 = append(pool.ipv6, &nameserver{
				hostname: addr.Header().Name,
				addr:     addr.AAAA.String(),
			})
		}

	}

	pool.hostsWithoutAddresses = slices.Clip(pool.hostsWithoutAddresses)

	pool.expires = time.Now().Add(time.Duration(ttl) * time.Second)

	return pool
}

func findAddressesForHostname(hostname string, records []dns.RR) ([]*dns.A, []*dns.AAAA, uint32) {
	a := make([]*dns.A, 0, len(records))
	aaaa := make([]*dns.AAAA, 0, len(records))

	var ttl = MaxTTLAllowed

	for _, rr := range records {
		if canonicalName(rr.Header().Name) != hostname {
			continue
		}
		switch addr := rr.(type) {
		case *dns.A:
			a = append(a, addr)
			ttl = min(rr.Header().Ttl, ttl)
		case *dns.AAAA:
			aaaa = append(aaaa, addr)
			ttl = min(rr.Header().Ttl, ttl)
		}
	}

	return a, aaaa, ttl
}

func (pool *nameserverPool) enrich(records []dns.RR) {
	if len(records) == 0 {
		return
	}

	pool.updating.Lock()
	defer pool.updating.Unlock()

	var ttl = MaxTTLAllowed
	hostnamesStillWithoutAddresses := make([]string, 0, len(pool.hostsWithoutAddresses))

	for _, hostname := range pool.hostsWithoutAddresses {

		a, aaaa, minTtlSeen := findAddressesForHostname(hostname, records)

		if len(a) == 0 && len(aaaa) == 0 {
			hostnamesStillWithoutAddresses = append(hostnamesStillWithoutAddresses, hostname)
			continue
		}

		//---

		ttl = min(minTtlSeen, ttl)

		for _, addr := range a {
			pool.ipv4 = append(pool.ipv4, &nameserver{
				hostname: addr.Header().Name,
				addr:     addr.A.String(),
			})
		}

		for _, addr := range aaaa {
			pool.ipv6 = append(pool.ipv6, &nameserver{
				hostname: addr.Header().Name,
				addr:     addr.AAAA.String(),
			})
		}
	}

	if !pool.expires.IsZero() {
		expires := time.Now().Add(time.Duration(ttl) * time.Second)
		if expires.Before(pool.expires) {
			pool.expires = expires
		}
	}

	pool.hostsWithoutAddresses = slices.Clip(hostnamesStillWithoutAddresses)
}

func (pool *nameserverPool) exchange(ctx context.Context, m *dns.Msg) *Response {
	switch pool.status() {
	case PoolPrimed:
	case PrimedButNeedsEnhancing:
	default:
		return ResponseError(fmt.Errorf("server pool not setup"))
	}

	var response *Response

	if pool.hasIPv6() && IPv6Available() {
		server := pool.getIPv6()
		response = server.exchange(ctx, m)
	} else {
		server := pool.getIPv4()
		response = server.exchange(ctx, m)
	}

	if response.Empty() || response.Error() || response.truncated() {
		// If there was an issue, we give it one more try.
		// If we have more than one nameserver, this will try a different one.
		if pool.hasIPv4() {
			server := pool.getIPv4()
			response = server.exchange(ctx, m)
		} else if pool.hasIPv6() {
			server := pool.getIPv6()
			response = server.exchange(ctx, m)
		}
	}

	if response.Empty() && !response.Error() {
		// If we get an empty response without an error, we'll add an error.
		response.Err = fmt.Errorf("no nameserver setup for %s", m.Question[0].Name)
	}

	return response
}
