package stack

import (
	"github.com/Diniboy1123/usque/internal/core"
	"github.com/songgao/water"
	"golang.zx2c4.com/wireguard/tun"
)

// Stack is an alias for core.PacketConn, representing a TUN device
// that can read and write IP packets.
type Stack core.PacketConn

// --- Netstack Adapter ---

// NetstackAdapter wraps a tun.Device (from wireguard-go/tun's netstack)
// to satisfy the Stack interface.
type NetstackAdapter struct {
	dev tun.Device
}

func (n *NetstackAdapter) ReadPacket(buf []byte) (int, error) {
	// The netstack device's Read takes a slice of buffers and a slice of sizes.
	// We adapt it to work with a single buffer.
	bufs := [][]byte{buf}
	sizes := []int{0}
	_, err := n.dev.Read(bufs, sizes, 0)
	if err != nil {
		return 0, err
	}
	return sizes[0], nil
}

func (n *NetstackAdapter) WritePacket(pkt []byte) error {
	_, err := n.dev.Write([][]byte{pkt}, 0)
	return err
}

func (n *NetstackAdapter) Close() error {
	return n.dev.Close()
}

// NewNetstackAdapter creates a new NetstackAdapter.
func NewNetstackAdapter(dev tun.Device) Stack {
	return &NetstackAdapter{dev: dev}
}

// --- Water Adapter ---

// WaterAdapter wraps a *water.Interface to satisfy the Stack interface.
type WaterAdapter struct {
	iface *water.Interface
}

func (w *WaterAdapter) ReadPacket(buf []byte) (int, error) {
	return w.iface.Read(buf)
}

func (w *WaterAdapter) WritePacket(pkt []byte) error {
	_, err := w.iface.Write(pkt)
	return err
}

func (w *WaterAdapter) Close() error {
	return w.iface.Close()
}

// NewWaterAdapter creates a new WaterAdapter.
func NewWaterAdapter(iface *water.Interface) Stack {
	return &WaterAdapter{iface: iface}
}
