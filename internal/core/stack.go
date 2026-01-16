package core

// PacketConn represents a packet-level connection, like a TUN device or a MASQUE tunnel.
type PacketConn interface {
	// ReadPacket reads a single packet.
	ReadPacket(buf []byte) (int, error)
	// WritePacket writes a single packet.
	WritePacket(pkt []byte) error
	// Close closes the connection.
	Close() error
}
