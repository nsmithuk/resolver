package resolver

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var ipv6Check sync.Once

var ipv6Answered atomic.Bool
var ipv6Available atomic.Bool

// IPv6Available return true if IPv6 Internet connectivity is found.
// If the check has not been performed, it won't block, and (initially) will return false.
func IPv6Available() bool {
	if ipv6Answered.Load() {
		return ipv6Available.Load()
	}
	if ipv6Available.Load() {
		return true
	}
	go ipv6Check.Do(UpdateIPv6Availability)
	return false
}

func UpdateIPv6Availability() {
	defer ipv6Answered.Store(true)

	// Tries:
	// 	k.root-servers.net
	// 	e.root-servers.net.
	// 	a.root-servers.net.
	for _, address := range []string{"2001:7fd::1", "2001:500:a8::e", "2001:503:ba3e::2:30"} {
		ipv6Address := fmt.Sprintf("[%s]:53", address)
		timeout := 1 * time.Second

		conn, err := net.DialTimeout("udp6", ipv6Address, timeout)
		ipv6Available.Store(err == nil)
		if err == nil {
			conn.Close()
			return
		}
	}
}
