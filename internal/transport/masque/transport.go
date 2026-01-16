package masque

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal/core"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Transport implements the core.Transport interface for MASQUE.
type Transport struct {
	tag        string
	tlsConfig  *tls.Config
	quicConfig *quic.Config
	endpoint   *net.UDPAddr
}

// NewTransport creates a new MASQUE transport from the given options.
func NewTransport(tag string, options map[string]interface{}) (core.Transport, error) {
	// This is where we would parse the options from config.json.
	// For now, we will use the legacy global config for simplicity,
	// as we are refactoring incrementally.

	privKey, err := config.AppConfig.GetEcPrivateKey()
	if err != nil {
		return nil, err
	}
	peerPubKey, err := config.AppConfig.GetEcEndpointPublicKey()
	if err != nil {
		return nil, err
	}

	cert, err := GenerateCert(privKey, &privKey.PublicKey)
	if err != nil {
		return nil, err
	}

	// For now, we'll hardcode some values that used to be flags.
	// In the final version, these would come from `options`.
	sni := ConnectSNI
	keepalive := 30 * time.Second
	initialPacketSize := uint16(1242)
	connectPort := 443

	tlsConfig, err := PrepareTlsConfig(privKey, peerPubKey, cert, sni)
	if err != nil {
		return nil, err
	}

	endpoint := &net.UDPAddr{
		IP:   net.ParseIP(config.AppConfig.EndpointV4),
		Port: connectPort,
	}

	return &Transport{
		tag:        tag,
		tlsConfig:  tlsConfig,
		quicConfig: DefaultQuicConfig(keepalive, initialPacketSize),
		endpoint:   endpoint,
	}, nil
}

// StartTunnel establishes a packet-level tunnel to the remote.
func (t *Transport) StartTunnel(ctx context.Context) (core.PacketConn, error) {
	log.Printf("Establishing MASQUE tunnel via transport '%s'", t.tag)
	udpConn, tr, ipConn, rsp, err := ConnectTunnel(
		ctx,
		t.tlsConfig,
		t.quicConfig,
		ConnectURI,
		t.endpoint,
	)
	if err != nil {
		// Close the UDP conn if it was created, since the caller won't get it.
		if udpConn != nil {
			udpConn.Close()
		}
		return nil, err
	}
	if rsp.StatusCode != 200 {
		if ipConn != nil {
			ipConn.Close()
		}
		if tr != nil {
			tr.Close()
		}
		if udpConn != nil {
			udpConn.Close()
		}
		return nil, fmt.Errorf("tunnel connection failed with status: %s", rsp.Status)
	}

	return &masquePacketConn{
		Conn:    ipConn,
		udpConn: udpConn,
		h3tr:    tr,
	}, nil
}

// Tag returns the transport's tag.
func (t *Transport) Tag() string {
	return t.tag
}

// masquePacketConn wraps the connectip.Conn to adapt it to the core.PacketConn interface.
type masquePacketConn struct {
	Conn    *connectip.Conn
	udpConn *net.UDPConn
	h3tr    *http3.Transport
}

// ReadPacket reads a single IP packet from the tunnel.
func (c *masquePacketConn) ReadPacket(buf []byte) (int, error) {
	// The `connectip.Conn` reads a full IP packet. The `singlePacket` flag should be true.
	return c.Conn.ReadPacket(buf, true)
}

// WritePacket writes a single IP packet to the tunnel.
// It discards the ICMP reply for now to match the interface.
func (c *masquePacketConn) WritePacket(pkt []byte) error {
	_, err := c.Conn.WritePacket(pkt)
	return err
}

// Close closes the connectip.Conn and the underlying UDP connection and http3 transport.
func (c *masquePacketConn) Close() error {
	var errs []error
	if c.Conn != nil {
		errs = append(errs, c.Conn.Close())
	}
	// http3.Transport does not have a Close method. The underlying quic connection is closed by ipConn.Close().
	if c.udpConn != nil {
		errs = append(errs, c.udpConn.Close())
	}
	for _, err := range errs {
		if err != nil {
			return err // Return the first error
		}
	}
	return nil
}
