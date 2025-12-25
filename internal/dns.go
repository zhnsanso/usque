package internal

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// TunnelDNSResolver implements a DNS resolver that uses the provided DNS servers
// either inside a MASQUE tunnel (if TunNet is set) or over the system network (if TunNet is nil).
type TunnelDNSResolver struct {
	TunNet   *netstack.Net
	DNSAddrs []netip.Addr
	Timeout  time.Duration
}

// Resolve performs a DNS lookup using the provided DNS resolvers.
func (r TunnelDNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	if len(r.DNSAddrs) == 0 {
		return ctx, nil, fmt.Errorf("no DNS servers configured")
	}

	var queryCtx context.Context = ctx
	var cancel context.CancelFunc
	if r.Timeout > 0 {
		queryCtx, cancel = context.WithTimeout(ctx, r.Timeout)
		defer cancel()
	}

	type result struct {
		ip  net.IP
		err error
	}
	results := make(chan result, len(r.DNSAddrs))

	for _, dnsAddr := range r.DNSAddrs {
		dnsHost := net.JoinHostPort(dnsAddr.String(), "53")

		go func(dnsHost string) {
			var dialFunc func(context.Context, string, string) (net.Conn, error)
			if r.TunNet != nil {
				dialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
					return r.TunNet.DialContext(ctx, "udp", dnsHost)
				}
			} else {
				dialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
					return net.Dial("udp", dnsHost)
				}
			}

			resolver := &net.Resolver{
				PreferGo: true,
				Dial:     dialFunc,
			}
			ips, err := resolver.LookupIP(queryCtx, "ip", name)
			if err == nil && len(ips) > 0 {
				results <- result{ip: ips[0], err: nil}
			} else {
				results <- result{ip: nil, err: err}
			}
		}(dnsHost)
	}

	var lastErr error
	for i := 0; i < len(r.DNSAddrs); i++ {
		res := <-results
		if res.err == nil && res.ip != nil {
			if cancel != nil {
				cancel()
			}
			return ctx, res.ip, nil
		}
		lastErr = res.err
	}

	return ctx, nil, fmt.Errorf("all DNS servers failed: %v", lastErr)
}

func NewNetstackResolver(tunNet *netstack.Net, dnsAddrs []netip.Addr) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if len(dnsAddrs) == 0 {
				return nil, fmt.Errorf("no DNS servers configured")
			}
			dnsHost := net.JoinHostPort(dnsAddrs[0].String(), "53")
			return tunNet.DialContext(ctx, "udp", dnsHost)
		},
	}
}

func NewStaticResolver(dnsAddrs []netip.Addr) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if len(dnsAddrs) == 0 {
				return nil, fmt.Errorf("no DNS servers configured")
			}
			dnsHost := net.JoinHostPort(dnsAddrs[0].String(), "53")
			return net.Dial("udp", dnsHost)
		},
	}
}

// GetProxyResolver returns the appropriate *net.Resolver for proxy use.
func GetProxyResolver(localDNS bool, tunNet *netstack.Net, dnsAddrs []netip.Addr, timeout time.Duration) *net.Resolver {
	if localDNS {
		return NewStaticResolver(dnsAddrs)
	}
	return NewNetstackResolver(tunNet, dnsAddrs)
}

// GetSocksResolver returns the appropriate TunnelDNSResolver for SOCKS proxy use.
func GetSocksResolver(localDNS bool, tunNet *netstack.Net, dnsAddrs []netip.Addr, timeout time.Duration) TunnelDNSResolver {
	if localDNS {
		return TunnelDNSResolver{TunNet: nil, DNSAddrs: dnsAddrs, Timeout: timeout}
	}
	return TunnelDNSResolver{TunNet: tunNet, DNSAddrs: dnsAddrs, Timeout: timeout}
}
