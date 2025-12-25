package socks5

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/Diniboy1123/usque/internal"
)

// Resolver is the interface for DNS resolution.
type Resolver interface {
	Resolve(ctx context.Context, name string) (context.Context, net.IP, error)
}

// Server is a simple, high-performance SOCKS5 server.
type Server struct {
	Username string
	Password string
	Dialer   func(ctx context.Context, network, addr string) (net.Conn, error)
	Resolver Resolver
}

// ServeConn handles a new SOCKS5 connection.
func (s *Server) ServeConn(conn net.Conn) error {
	defer conn.Close()

	// Set handshake deadline to prevent Slowloris attacks.
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Negotiate Version
	buf := make([]byte, 258) // Max methods is 255 + 2 header

	// Read version and nmethods
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return fmt.Errorf("read header: %w", err)
	}

	if buf[0] != 5 {
		return fmt.Errorf("unsupported version: %d", buf[0])
	}

	nmethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
		return fmt.Errorf("read methods: %w", err)
	}

	// Select method
	useAuth := s.Username != "" && s.Password != ""
	method := byte(0xFF) // No acceptable methods

	for _, m := range buf[:nmethods] {
		if useAuth && m == 0x02 {
			method = 0x02
			break
		}
		if !useAuth && m == 0x00 {
			method = 0x00
			break
		}
	}

	if method == 0xFF {
		conn.Write([]byte{5, 0xFF})
		return errors.New("no acceptable authentication methods")
	}

	// Send selected method
	if _, err := conn.Write([]byte{5, method}); err != nil {
		return fmt.Errorf("write method: %w", err)
	}

	// Handle Auth
	if method == 0x02 {
		if err := s.handleAuth(conn); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}

	// Handle Request
	return s.handleRequest(conn)
}

func (s *Server) handleAuth(conn net.Conn) error {
	buf := make([]byte, 513) // Max user/pass len

	// Read version
	if _, err := io.ReadFull(conn, buf[:1]); err != nil {
		return err
	}
	if buf[0] != 1 {
		return fmt.Errorf("unsupported auth version: %d", buf[0])
	}

	// Read Username
	if _, err := io.ReadFull(conn, buf[:1]); err != nil {
		return err
	}
	ulen := int(buf[0])
	if _, err := io.ReadFull(conn, buf[:ulen]); err != nil {
		return err
	}
	user := string(buf[:ulen])

	// Read Password
	if _, err := io.ReadFull(conn, buf[:1]); err != nil {
		return err
	}
	plen := int(buf[0])
	if _, err := io.ReadFull(conn, buf[:plen]); err != nil {
		return err
	}
	pass := string(buf[:plen])

	// Constant time comparison to prevent timing attacks
	userMatch := subtle.ConstantTimeCompare([]byte(user), []byte(s.Username))
	passMatch := subtle.ConstantTimeCompare([]byte(pass), []byte(s.Password))

	if userMatch != 1 || passMatch != 1 {
		conn.Write([]byte{1, 1}) // Failure
		return errors.New("authentication failed")
	}

	if _, err := conn.Write([]byte{1, 0}); err != nil { // Success
		return err
	}

	return nil
}

func (s *Server) handleRequest(conn net.Conn) error {
	buf := make([]byte, 262) // Max domain len

	// Read header: ver, cmd, rsv, atyp
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return err
	}

	if buf[0] != 5 {
		return fmt.Errorf("bad version: %d", buf[0])
	}
	if buf[1] != 1 { // CONNECT only
		s.sendReply(conn, 0x07, nil) // Command not supported
		return fmt.Errorf("unsupported command: %d", buf[1])
	}

	var destAddr string
	var destPort int

	switch buf[3] {
	case 1: // IPv4
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return err
		}
		destAddr = net.IP(buf[:4]).String()
	case 3: // Domain
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return err
		}
		dlen := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:dlen]); err != nil {
			return err
		}
		destAddr = string(buf[:dlen])
	case 4: // IPv6
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return err
		}
		destAddr = net.IP(buf[:16]).String()
	default:
		s.sendReply(conn, 0x08, nil) // Address type not supported
		return fmt.Errorf("unsupported address type: %d", buf[3])
	}

	// Read Port
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return err
	}
	destPort = int(binary.BigEndian.Uint16(buf[:2]))

	// Clear deadline before relaying
	conn.SetDeadline(time.Time{})

	// Resolve if needed
	if net.ParseIP(destAddr) == nil && s.Resolver != nil {
		_, ip, err := s.Resolver.Resolve(context.Background(), destAddr)
		if err != nil {
			s.sendReply(conn, 0x04, nil) // Host unreachable
			return fmt.Errorf("resolve failed: %w", err)
		}
		destAddr = ip.String()
	}

	targetAddr := net.JoinHostPort(destAddr, strconv.Itoa(destPort))

	// Dial
	target, err := s.Dialer(context.Background(), "tcp", targetAddr)
	if err != nil {
		s.sendReply(conn, 0x05, nil) // Connection refused
		return fmt.Errorf("dial failed: %w", err)
	}
	defer target.Close()

	// Send Success Reply
	if err := s.sendReply(conn, 0x00, nil); err != nil {
		return err
	}

	// Relay using BufferPool
	errCh := make(chan error, 2)
	go func() {
		_, err := internal.CopyBuffer(target, conn)
		errCh <- err
	}()
	go func() {
		_, err := internal.CopyBuffer(conn, target)
		errCh <- err
	}()

	return <-errCh
}

func (s *Server) sendReply(conn net.Conn, rep byte, addr net.IP) error {
	// Format: VER REP RSV ATYP BND.ADDR BND.PORT
	// We just send 0.0.0.0:0 for simplicity
	_, err := conn.Write([]byte{5, rep, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}
