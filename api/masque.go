package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/Diniboy1123/usque/internal"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

// PrepareTlsConfig creates a TLS configuration using the provided certificate and SNI.
func PrepareTlsConfig(privKey *ecdsa.PrivateKey, peerPubKey *ecdsa.PublicKey, cert [][]byte, sni string) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: cert,
				PrivateKey:  privKey,
			},
		},
		ServerName: sni,
		NextProtos: []string{http3.NextProtoH3},
		// WARN: SNI is usually not for the endpoint, so we must skip verification
		InsecureSkipVerify: true,
		// we pin to the endpoint public key
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return nil
			}

			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}

			if _, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok {
				// we only support ECDSA
				return x509.ErrUnsupportedAlgorithm
			}

			if !cert.PublicKey.(*ecdsa.PublicKey).Equal(peerPubKey) {
				return x509.CertificateInvalidError{Cert: cert, Reason: 10, Detail: "remote endpoint has a different public key than what we trust in config.json"}
			}

			return nil
		},
	}

	return tlsConfig, nil
}

// ConnectTunnel establishes a QUIC connection and sets up a Connect-IP tunnel.
// Implements Happy Eyeballs (RFC 8305) to race IPv4 and IPv6 connections.
func ConnectTunnel(ctx context.Context, tlsConfig *tls.Config, quicConfig *quic.Config, connectUri string, endpointV4, endpointV6 *net.UDPAddr) (*net.UDPConn, *http3.Transport, *connectip.Conn, *http.Response, error) {
	type dialResult struct {
		udpConn *net.UDPConn
		qConn   *quic.Conn
		err     error
	}

	resultCh := make(chan dialResult)
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup

	dial := func(ep *net.UDPAddr, delay time.Duration) {
		defer wg.Done()

		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-dialCtx.Done():
				timer.Stop()
				return
			}
		}

		if dialCtx.Err() != nil {
			return
		}

		var udpConn *net.UDPConn
		var err error

		if ep.IP.To4() == nil {
			udpConn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6zero, Port: 0})
		} else {
			udpConn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		}

		if err != nil {
			return
		}

		qConn, err := quic.Dial(dialCtx, udpConn, ep, tlsConfig, quicConfig)
		if err != nil {
			udpConn.Close()
			return
		}

		select {
		case resultCh <- dialResult{udpConn: udpConn, qConn: qConn}:
		case <-dialCtx.Done():
			qConn.CloseWithError(0, "lost race")
			udpConn.Close()
		}
	}

	attempts := 0
	if endpointV6 != nil {
		attempts++
		wg.Add(1)
		go dial(endpointV6, 0)
	}

	if endpointV4 != nil {
		attempts++
		wg.Add(1)
		delay := 200 * time.Millisecond
		if endpointV6 == nil {
			delay = 0
		}
		go dial(endpointV4, delay)
	}

	if attempts == 0 {
		return nil, nil, nil, nil, errors.New("no endpoints provided")
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	res, ok := <-resultCh
	if !ok {
		return nil, nil, nil, nil, errors.New("all connection attempts failed")
	}

	udpConn := res.udpConn
	conn := res.qConn

	tr := &http3.Transport{
		EnableDatagrams:    true,
		AdditionalSettings: map[uint64]uint64{0x276: 1}, // SETTINGS_H3_DATAGRAM_00
		DisableCompression: true,
	}

	hconn := tr.NewClientConn(conn)
	additionalHeaders := http.Header{"User-Agent": []string{""}}
	template := uritemplate.MustNew(connectUri)

	ipConn, rsp, err := connectip.Dial(ctx, hconn, template, "cf-connect-ip", additionalHeaders, true)
	if err != nil {
		if err.Error() == "CRYPTO_ERROR 0x131 (remote): tls: access denied" {
			return udpConn, nil, nil, nil, errors.New("login failed! Please double-check if your tls key and cert is enrolled in the Cloudflare Access service")
		}
		return udpConn, nil, nil, nil, fmt.Errorf("failed to dial connect-ip: %v", err)
	}

	return udpConn, tr, ipConn, rsp, nil
}

// MaintainTunnel continuously connects to the MASQUE server and handles packet forwarding.
// It uses an atomic pointer to swap the active connection, ensuring a single TUN reader
// without complex channel orchestration.
func MaintainTunnel(ctx context.Context, tlsConfig *tls.Config, keepalivePeriod time.Duration, initialPacketSize uint16, endpointV4, endpointV6 *net.UDPAddr, device TunnelDevice, mtu int, reconnectDelay time.Duration) {
	packetBufferPool := NewNetBuffer(mtu)

	// Active connection holder. Atomic for thread-safe lock-free access.
	var activeConn atomic.Pointer[connectip.Conn]

	currentV4 := endpointV4
	currentV6 := endpointV6

	// Persistent TUN Reader Loop
	// This goroutine runs for the entire lifetime of the application.
	// It reads from the TUN device and attempts to write to the current active connection.
	go func() {
		buf := packetBufferPool.Get()
		defer packetBufferPool.Put(buf)

		for {
			n, err := device.ReadPacket(buf)
			if err != nil {
				log.Printf("Critical: failed to read from TUN device: %v", err)
				return
			}

			// Load the current active connection
			conn := activeConn.Load()
			if conn != nil {
				_, err := conn.WritePacket(buf[:n])
				if err != nil {
					// We don't panic here; the main loop handles reconnection.
					// Just log debug if needed, or ignore as packet loss.
				}
			}
			// If conn is nil, we simply drop the packet (mimics outage).
		}
	}()

	// Connection Maintenance Loop
	for {
		if ctx.Err() != nil {
			return
		}

		log.Printf("Establishing MASQUE connection (IPv4: %v, IPv6: %v)", currentV4, currentV6)
		udpConn, tr, ipConn, rsp, err := ConnectTunnel(
			ctx,
			tlsConfig,
			internal.DefaultQuicConfig(keepalivePeriod, initialPacketSize),
			internal.ConnectURI,
			currentV4,
			currentV6,
		)

		if err != nil {
			log.Printf("Failed to connect tunnel: %v", err)
			currentV4 = internal.GetNextEndpoint(currentV4)
			currentV6 = internal.GetNextEndpoint(currentV6)
			time.Sleep(reconnectDelay)
			continue
		}

		if rsp.StatusCode != 200 {
			log.Printf("Tunnel connection failed: %s", rsp.Status)
			ipConn.Close()
			if udpConn != nil {
				udpConn.Close()
			}
			if tr != nil {
				tr.Close()
			}
			time.Sleep(reconnectDelay)
			continue
		}

		log.Println("Connected to MASQUE server")

		// Publish the new connection to the reader
		activeConn.Store(ipConn)

		// IP -> TUN Reader Loop (Block until connection dies)
		// We use a separate buffer for this loop
		readBuf := packetBufferPool.Get()
		for {
			n, err := ipConn.ReadPacket(readBuf, true)
			if err != nil {
				log.Printf("Tunnel connection lost: %v. Reconnecting...", err)
				break
			}
			if err := device.WritePacket(readBuf[:n]); err != nil {
				log.Printf("Failed to write to TUN device: %v", err)
				break
			}
		}
		packetBufferPool.Put(readBuf)

		// Teardown
		activeConn.Store(nil) // Stop sending packets to dead connection
		ipConn.Close()
		if udpConn != nil {
			udpConn.Close()
		}
		if tr != nil {
			tr.Close()
		}

		currentV4 = internal.GetNextEndpoint(currentV4)
		currentV6 = internal.GetNextEndpoint(currentV6)
		time.Sleep(reconnectDelay)
	}
}
