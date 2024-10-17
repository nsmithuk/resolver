package resolver

import "sync"

// zones is a thread-safe map of <zone name> -> zone.
type zones struct {
	lock  sync.RWMutex
	zones map[string]*zone
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
