package resolver

import (
	"github.com/miekg/dns"
	"sync"
)

type zoneStore interface {
	getZoneList(name string) []*zone
	get(name string) *zone
	add(z *zone)
	count() int
}

// zones is a thread-safe map of <zone name> -> zone.
type zones struct {
	lock  sync.RWMutex
	zones map[string]*zone
}

// getZoneList returns a list of zones needed to answer the query for qname.
func (zones *zones) getZoneList(name string) []*zone {
	name = canonicalName(name)
	zones.lock.RLock()
	defer zones.lock.RUnlock()

	if zones.zones == nil {
		return nil
	}

	indexes := append(dns.Split(name), len(name)-1)

	for i, idx := range indexes {
		zname := name[idx:]
		z, _ := zones.zones[zname]
		if z == nil || z.pool.expired() {
			continue
		}

		if z.name == "." {
			return []*zone{z}
		}

		result := make([]*zone, 0, len(indexes)-i)
		result = append(result, z)
		for len(z.parent) > 0 {
			z, _ = zones.zones[z.parent]
			if z == nil || z.pool.expired() {
				break
			}

			result = append(result, z)
			if z.name == "." {
				return result
			}
		}

	}

	// If we get here, we just return the root.
	z, _ := zones.zones["."]
	return []*zone{z}
}

func (zones *zones) get(name string) *zone {
	name = canonicalName(name)
	zones.lock.RLock()
	defer zones.lock.RUnlock()

	if zones.zones == nil {
		return nil
	}

	z, _ := zones.zones[name]

	if z != nil && z.pool.expired() {
		// We could remove the expired zone from the map here, but realistically it's about to be replaced,
		// so we'll opt to keep things simple here (keeping get() read-only) and just return the result.
		return nil
	}

	return z
}

func (zones *zones) add(z *zone) {
	name := canonicalName(z.name)
	zones.lock.Lock()
	if zones.zones == nil {
		zones.zones = make(map[string]*zone)
	}
	zones.zones[name] = z
	zones.lock.Unlock()
}

func (zones *zones) count() int {
	zones.lock.RLock()
	c := len(zones.zones)
	zones.lock.RUnlock()
	return c
}
