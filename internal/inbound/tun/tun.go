package tun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"

	"github.com/Diniboy1123/usque/internal/config"
	"github.com/Diniboy1123/usque/internal/core"
	"github.com/Diniboy1123/usque/internal/router"
	"github.com/Diniboy1123/usque/internal/stack"
	"github.com/Diniboy1123/usque/internal/transport/masque"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type TunInbound struct {
	tag        string
	config     config.InboundOptions
	router     *router.DefaultRouter // Changed to concrete type for now
	ctx        context.Context
	cancel     context.CancelFunc
	localStack stack.Stack
	remoteConn core.PacketConn
}

func New(ctx context.Context, router *router.DefaultRouter, options config.InboundOptions) (core.Inbound, error) {
	ctx, cancel := context.WithCancel(ctx)
	return &TunInbound{
		tag:    options.Tag,
		config: options,
		router: router,
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

func (t *TunInbound) Start() error {
	log.Printf("Starting tun inbound with tag: %s", t.tag)

	// 1. Get Transport (outbound)
	// In a real scenario, this would be looked up via the router.
	// For now, we hardcode the creation of a MASQUE transport.
	transport, err := masque.NewTransport("masque-default", nil)
	if err != nil {
		return fmt.Errorf("failed to create default masque transport: %w", err)
	}

	// 2. Start the remote tunnel connection
	t.remoteConn, err = transport.StartTunnel(t.ctx)
	if err != nil {
		return fmt.Errorf("failed to start remote tunnel: %w", err)
	}

	// 3. Create the local stack (TUN device)
	stackType := "netstack" // Placeholder default
	if opts, ok := t.config.Options["stack"].(string); ok {
		stackType = opts
	}

	mtu := 1280 // Placeholder

	switch stackType {
	case "system":
		t.localStack, err = newNativeDevice(t.tag, mtu)
	case "netstack":
		// This part is taken from the old cmd/socks.go
		// We'll need to get addresses from config later.
		var tunNet *netstack.Net
		tunDev, tunNet, err := netstack.CreateNetTUN(nil, nil, mtu)
		if err != nil {
			return fmt.Errorf("failed to create netstack device: %w", err)
		}
		t.localStack = stack.NewNetstackAdapter(tunDev)
		// Register the netstack dialer with the router
		if t.router != nil {
			log.Printf("Registering netstack dialer for other inbounds to use.")
			t.router.SetDefaultDialer(tunNet)
		}
	default:
		return fmt.Errorf("unknown stack type: %s", stackType)
	}
	if err != nil {
		return fmt.Errorf("failed to create local stack: %w", err)
	}

	// 4. Start piping packets
	go t.pipe(t.localStack, t.remoteConn)
	go t.pipe(t.remoteConn, t.localStack)

	log.Printf("TUN inbound '%s' started successfully", t.tag)
	return nil
}

func (t *TunInbound) Close() error {
	t.cancel()
	var errs []error
	if t.localStack != nil {
		errs = append(errs, t.localStack.Close())
	}
	if t.remoteConn != nil {
		errs = append(errs, t.remoteConn.Close())
	}
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *TunInbound) Tag() string {
	return t.tag
}

// pipe copies packets from a source to a destination PacketConn.
// This is the core logic of the old MaintainTunnel function.
func (t *TunInbound) pipe(dst, src core.PacketConn) {
	buf := make([]byte, 1500) // A bit larger than MTU
	for {
		select {
		case <-t.ctx.Done():
			return
		default:
			n, err := src.ReadPacket(buf)
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
					log.Printf("Pipe closed from %T", src)
				} else {
					log.Printf("Error reading from %T: %v", src, err)
				}
				t.Close()
				return
			}

			if err := dst.WritePacket(buf[:n]); err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
					log.Printf("Pipe closed to %T", dst)
				} else {
					log.Printf("Error writing to %T: %v", dst, err)
				}
				t.Close()
				return
			}
		}
	}
}
