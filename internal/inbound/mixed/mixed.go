package mixed

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/Diniboy1123/usque/internal/config"
	"github.com/Diniboy1123/usque/internal/core"
	"github.com/Diniboy1123/usque/internal/router"
	"github.com/things-go/go-socks5"
)

type MixedInbound struct {
	tag      string
	config   config.InboundOptions
	router   *router.DefaultRouter // Changed to concrete type
	listener net.Listener
	server   *socks5.Server
	ctx      context.Context
	cancel   context.CancelFunc
}

func New(ctx context.Context, router *router.DefaultRouter, options config.InboundOptions) (core.Inbound, error) {
	ctx, cancel := context.WithCancel(ctx)
	return &MixedInbound{
		tag:    options.Tag,
		config: options,
		router: router,
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

func (m *MixedInbound) Start() error {
	log.Printf("Starting mixed inbound with tag: %s", m.tag)

	// Config parsing
	listenAddr, _ := m.config.Options["listen"].(string)
	if listenAddr == "" {
		listenAddr = "0.0.0.0"
	}
	listenPort, _ := m.config.Options["listen_port"].(float64)
	if listenPort == 0 {
		listenPort = 1080
	}
	addr := fmt.Sprintf("%s:%d", listenAddr, int(listenPort))

	// Create a listener
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	m.listener = listener

	log.Printf("Mixed inbound '%s' listening on %s", m.tag, addr)

	// Start accepting connections
	go m.acceptLoop()

	return nil
}

func (m *MixedInbound) acceptLoop() {
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			select {
			case <-m.ctx.Done():
				return // Graceful shutdown
			default:
				log.Printf("Error accepting connection: %v", err)
				return // End loop on accept error
			}
		}
		go m.handleConnection(conn)
	}
}

func (m *MixedInbound) handleConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	firstByte, err := reader.Peek(1)
	if err != nil {
		log.Printf("Failed to peek first byte: %v", err)
		return
	}

	// Protocol Sniffing
	if firstByte[0] == 5 { // SOCKS5 version
		log.Printf("Detected SOCKS5 connection from %s", conn.RemoteAddr())
		m.handleSocks5(conn, reader)
	} else {
		log.Printf("Detected HTTP connection from %s", conn.RemoteAddr())
		m.handleHttp(conn, reader)
	}
}

func (m *MixedInbound) Close() error {
	m.cancel()
	if m.listener != nil {
		return m.listener.Close()
	}
	return nil
}

func (m *MixedInbound) Tag() string {
	return m.tag
}

// --- SOCKS5 Handler Logic ---
func (m *MixedInbound) handleSocks5(conn net.Conn, reader *bufio.Reader) {
	dialer, err := m.router.GetDefaultDialer()
	if err != nil {
		log.Printf("Cannot handle SOCKS5: %v", err)
		return
	}

	server := socks5.NewServer(
		socks5.WithDial(dialer.DialContext),
	)

	if err := server.ServeConn(conn); err != nil {
		if !errors.Is(err, io.EOF) {
			log.Printf("SOCKS5 negotiation error: %v", err)
		}
	}
}

// --- HTTP Handler Logic ---

// peekingConn wraps a net.Conn and a bufio.Reader to resolve Read ambiguity.
type peekingConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *peekingConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (m *MixedInbound) handleHttp(conn net.Conn, reader *bufio.Reader) {
	httpConn := &peekingConn{
		Conn:   conn,
		reader: reader,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			m.handleHttpsConnect(w, r)
		} else {
			m.handleHttpProxy(w, r)
		}
	})

	http.Serve(oneShotListener{httpConn}, handler)
}

func (m *MixedInbound) handleHttpsConnect(w http.ResponseWriter, r *http.Request) {
	dialer, err := m.router.GetDefaultDialer()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	destConn, err := dialer.DialContext(r.Context(), "tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	go func() {
		defer destConn.Close()
		defer clientConn.Close()
		io.Copy(destConn, clientConn)
	}()
	go func() {
		defer destConn.Close()
		defer clientConn.Close()
		io.Copy(clientConn, destConn)
	}()
}

func (m *MixedInbound) handleHttpProxy(w http.ResponseWriter, r *http.Request) {
	dialer, err := m.router.GetDefaultDialer()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	transport := &http.Transport{
		DialContext: dialer.DialContext,
	}

	resp, err := transport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// oneShotListener is a helper to wrap a single net.Conn into a net.Listener
// that returns the connection once and then returns an error.
type oneShotListener struct {
	conn net.Conn
}

func (l oneShotListener) Accept() (net.Conn, error) {
	if l.conn == nil {
		return nil, io.EOF
	}
	c := l.conn
	l.conn = nil
	return c, nil
}

func (l oneShotListener) Close() error {
	return nil
}

func (l oneShotListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

// A helper function to replace strings.Cut, which is only available in Go 1.18+
func cut(s, sep string) (before, after string, found bool) {
	if i := strings.Index(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}
