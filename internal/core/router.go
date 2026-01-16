package core

import "context"

// Router is the interface for the routing engine.
// It decides which transport to use for a given connection.
type Router interface {
	// Route decides which transport should handle the connection based on
	// the inbound tag and destination address. It returns the tag of the
	// selected transport.
	Route(ctx context.Context, inboundTag string, destination string) (transportTag string, err error)
}
