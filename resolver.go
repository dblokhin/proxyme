package proxyme

import (
	"context"
	"fmt"
	"net"
)

const maxCacheSize = 3000 // todo: parametrize

var defaultResolver = resolver{
	cache: newSyncCache[string, []net.IP](maxCacheSize),
}

type resolver struct {
	net.Resolver
	cache *syncLRU[string, []net.IP]
}

// LookupIP resolves domain name
func (r *resolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	key := network + host
	if ips, ok := r.cache.Get(key); ok {
		return ips, nil
	}

	ips, err := r.Resolver.LookupIP(ctx, network, host)
	if err != nil {
		return nil, err
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("failed to resolve %q", host)
	}

	r.cache.Add(key, ips)

	return ips, nil
}
