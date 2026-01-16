package core

import "context"

// Transport is the interface for all outbound services.
// A transport is responsible for establishing a connection to a remote
// server, using a specific protocol like MASQUE.
type Transport interface {
	// StartTunnel establishes a packet-level tunnel to the remote.
	StartTunnel(ctx context.Context) (PacketConn, error)
	// Tag returns the unique tag for this transport.
	Tag() string
}
