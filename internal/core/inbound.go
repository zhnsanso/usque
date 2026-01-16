package core

// Inbound is the interface for all inbound services.
// An inbound listens for incoming connections, handles the specific
// proxy protocol (like SOCKS5 or HTTP), and then passes the connection
// to the router.
type Inbound interface {
	// Start begins the inbound service. It should be non-blocking.
	Start() error
	// Close gracefully shuts down the inbound service.
	Close() error
	// Tag returns the unique tag for this inbound.
	Tag() string
}
