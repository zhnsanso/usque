package router

import (
	"context"
	"errors"
	"net"
	"sync"
)

// Dialer defines the interface for dialing outbound connections.
// This is satisfied by `*netstack.Net`.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// DefaultRouter acts as a simple service registry and router.
type DefaultRouter struct {
	mu        sync.RWMutex
	netDialer Dialer
}

// New creates a new DefaultRouter.
func New() *DefaultRouter {
	return &DefaultRouter{}
}

// SetDefaultDialer sets the network dialer to be used by stream-based inbounds.
// This will be called by the `tun` inbound when it starts in `netstack` mode.
func (r *DefaultRouter) SetDefaultDialer(dialer Dialer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.netDialer = dialer
}

// GetDefaultDialer returns the configured network dialer.
func (r *DefaultRouter) GetDefaultDialer() (Dialer, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.netDialer == nil {
		return nil, errors.New("no default network dialer is available; a 'tun' inbound with 'netstack' must be configured")
	}
	return r.netDialer, nil
}
