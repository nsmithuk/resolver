package resolver

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"sync"
	"time"
)

// dnsClientFactory defines a factory function for creating a DNS client.
type dnsClientFactory func(string) dnsClient

type dnsClient interface {
	ExchangeContext(context.Context, *dns.Msg, string) (*dns.Msg, time.Duration, error)
}

type nameserver struct {
	hostname string
	addr     string

	metricsLock         sync.Mutex
	numberOfRequests    uint32
	totalResponseTime   time.Duration
	averageResponseTime time.Duration
	numberOfTcpRequests uint32
	protocolRatio       float32
}

// The factory pattern here is to facilitate `exchangeWithClientFactory` being tested with a mock client.

func (nameserver *nameserver) exchange(ctx context.Context, m *dns.Msg) Response {
	factory := func(protocol string) dnsClient {
		return &dns.Client{Net: protocol, Timeout: 600 * time.Millisecond}
	}
	return nameserver.exchangeWithClientFactory(ctx, m, factory)
}

func (nameserver *nameserver) exchangeWithClientFactory(ctx context.Context, m *dns.Msg, factory dnsClientFactory) Response {
	zoneName := "unknown"
	if z, ok := ctx.Value(ctxZoneName).(string); ok {
		zoneName = z
	}

	if m == nil {
		return ResponseError(fmt.Errorf("%w in zone [%s]", ErrNilMessageSentToExchange, zoneName))
	}

	// Formats correctly for both ipv4 and ipv6.
	addr := net.JoinHostPort(nameserver.addr, "53")

	r := Response{}
	for _, protocol := range []string{"udp", "tcp"} {
		client := factory(protocol)

		r.Msg, r.Duration, r.Err = client.ExchangeContext(ctx, m, addr)

		// Logging and metric; in their own go routine.
		go func(r Response, protocol string) {
			iteration, _ := ctx.Value(ctxIteration).(uint32)

			Query(fmt.Sprintf(
				"%d: %s taken querying [%s] %s in zone [%s] on %s://%s (%s)",
				iteration,
				r.Duration,
				m.Question[0].Name,
				TypeToString(m.Question[0].Qtype),
				zoneName,
				protocol,
				nameserver.hostname,
				addr,
			))

			nameserver.metricsLock.Lock()
			nameserver.numberOfRequests++
			nameserver.totalResponseTime = nameserver.totalResponseTime + r.Duration
			nameserver.averageResponseTime = nameserver.totalResponseTime / time.Duration(nameserver.numberOfRequests)
			if protocol == "tcp" {
				nameserver.numberOfTcpRequests++
			}
			nameserver.protocolRatio = float32(nameserver.numberOfTcpRequests) / float32(nameserver.numberOfRequests)
			nameserver.metricsLock.Unlock()
		}(r, protocol)

		// If we got an error back, we'll continue to maybe try again.
		if r.Error() {
			continue
		}

		// Then we can return straight away.
		if !r.Msg.Truncated {
			return r
		}
	}

	// r here may have an error. It might be Truncated. But it's the best we've got.
	return r
}
