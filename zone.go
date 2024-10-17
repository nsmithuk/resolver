package resolver

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"sync"
	"sync/atomic"
	"time"
)

//---------------------------------------------------------------------------------

type zone struct {
	// An entry point to exchange with a specific zone.
	name  string
	pool  expiringExchanger
	calls atomic.Uint64

	dnskeys      []dns.RR
	dnskeyExpiry time.Time
	dnskeyLock   sync.Mutex
}

func (z *zone) Exchange(ctx context.Context, m *dns.Msg) Response {

	z.calls.Add(1)

	if Cache != nil {
		if msg, err := Cache.Get(z.name, m.Question[0]); err != nil {
			go Warn(fmt.Errorf("error trying to perform a cache lookup for zone [%s]: %w", z.name, err).Error())
		} else if msg != nil {
			go func() {
				iteration, _ := ctx.Value(ctxIteration).(uint32)
				Query(fmt.Sprintf(
					"%d: response for [%s] %s in zone [%s] found in cache",
					iteration,
					m.Question[0].Name,
					TypeToString(m.Question[0].Qtype),
					z.name,
				))
			}()
			return Response{Msg: msg.Copy()}
		}
	}

	//---

	if z.pool == nil {
		return ResponseError(fmt.Errorf("%w [%s]", ErrNoPoolConfiguredForZone, z.name))
	}

	ctx = context.WithValue(ctx, ctxZoneName, z.name)
	response := z.pool.exchange(ctx, m)

	//---

	if Cache != nil && !response.Empty() && !response.Error() {
		go func(zone string, question dns.Question, msg *dns.Msg) {
			if err := Cache.Update(zone, question, msg); err != nil {
				Warn(fmt.Errorf("error trying to perform a cache update for zone [%s]: %w", z.name, err).Error())
			}
		}(z.name, m.Question[0], response.Msg.Copy())
	}

	//---

	return response
}

// TODO: I suspect this can go. It was confusing anyway.
//func (z *zone) clone(name string) *zone {
//	return &zone{
//		name: canonicalName(name),
//		pool: z.pool,
//	}
//}

func (z *zone) dnsKeys(ctx context.Context) ([]dns.RR, error) {
	z.dnskeyLock.Lock()

	// We base this check on the expiry only, as `z.dnskeys` can be both nil and valid.
	if !z.dnskeyExpiry.IsZero() && !z.dnskeyExpiry.Before(time.Now()) {
		keys := z.dnskeys
		z.dnskeyLock.Unlock()
		return keys, nil
	}
	defer z.dnskeyLock.Unlock()

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(z.name), dns.TypeDNSKEY)
	msg.SetEdns0(4096, true)
	msg.RecursionDesired = false
	response := z.Exchange(ctx, msg)
	if response.Error() {
		return nil, fmt.Errorf("%w for %s: %w", ErrFailedToGetDNSKEYs, z.name, response.Err)
	}
	if response.Empty() {
		return nil, fmt.Errorf("%w for %s: reponse is empty", ErrFailedToGetDNSKEYs, z.name)
	}

	if len(response.Msg.Answer) == 0 {
		// If we got no answer, we'll put a short cache on that, rather than the MaxTTLAllowed.
		z.dnskeyExpiry = time.Now().Add(time.Second * 60)
		return nil, nil
	}

	z.dnskeys = response.Msg.Answer

	var ttl = MaxTTLAllowed
	for _, rr := range z.dnskeys {
		ttl = min(ttl, rr.Header().Ttl)
	}
	z.dnskeyExpiry = time.Now().Add(time.Duration(ttl) * time.Second)

	return z.dnskeys, nil
}
