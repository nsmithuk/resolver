package resolver

import (
	"github.com/miekg/dns"
	"strings"
)

type Resolver struct {
	zones *zones
}

func NewResolver() *Resolver {
	pool, err := buildRootServerPool()
	if err != nil {
		// Everything is technically static at this point.
		panic(err)
	}

	z := new(zones)
	z.add(&zone{
		name: ".",
		pool: pool,
	})

	return &Resolver{
		zones: z,
	}
}

//-----------------------------------------------------------------------------

func buildRootServerPool() (*nameserverPool, error) {
	zp := dns.NewZoneParser(strings.NewReader(rootZone), ".", "local")

	pool := &nameserverPool{hostsWithoutAddresses: make([]string, 0)}

	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		switch rr := rr.(type) {
		case *dns.A:
			pool.ipv4 = append(pool.ipv4, &nameserver{
				hostname: canonicalName(rr.Header().Name),
				addr:     rr.A.String(),
			})
		case *dns.AAAA:
			pool.ipv6 = append(pool.ipv6, &nameserver{
				hostname: canonicalName(rr.Header().Name),
				addr:     rr.AAAA.String(),
			})
		default:
			// Continue
		}
	}

	if err := zp.Err(); err != nil {
		return nil, err
	}

	return pool, nil
}
