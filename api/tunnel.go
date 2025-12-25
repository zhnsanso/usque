package api

import (
	"sync"

	"github.com/songgao/water"
	"golang.zx2c4.com/wireguard/tun"
)

// NetBuffer is a pool of byte slices with a fixed capacity.
// Helps to reduce memory allocations and improve performance.
// It uses a sync.Pool to manage the byte slices.
// The capacity of the byte slices is set when the pool is created.
type NetBuffer struct {
	capacity int
	buf      sync.Pool
}

// Get returns a byte slice from the pool.
func (n *NetBuffer) Get() []byte {
	return *(n.buf.Get().(*[]byte))
}

// Put places a byte slice back into the pool.
// It checks if the capacity of the byte slice matches the pool's capacity.
// If it doesn't match, the byte slice is not returned to the pool.
func (n *NetBuffer) Put(buf []byte) {
	if cap(buf) != n.capacity {
		return
	}
	n.buf.Put(&buf)
}

// NewNetBuffer creates a new NetBuffer with the specified capacity.
// The capacity must be greater than 0.
func NewNetBuffer(capacity int) *NetBuffer {
	if capacity <= 0 {
		panic("capacity must be greater than 0")
	}
	return &NetBuffer{
		capacity: capacity,
		buf: sync.Pool{
			New: func() interface{} {
				b := make([]byte, capacity)
				return &b
			},
		},
	}
}

// TunnelDevice abstracts a TUN device so that we can use the same tunnel-maintenance code
// regardless of the underlying implementation.
type TunnelDevice interface {
	// ReadPacket reads a packet from the device (using the given mtu) and returns its contents.
	ReadPacket(buf []byte) (int, error)
	// WritePacket writes a packet to the device.
	WritePacket(pkt []byte) error
}

// NetstackAdapter wraps a tun.Device (e.g. from netstack) to satisfy TunnelDevice.
type NetstackAdapter struct {
	dev             tun.Device
	tunnelBufPool   sync.Pool
	tunnelSizesPool sync.Pool
}

func (n *NetstackAdapter) ReadPacket(buf []byte) (int, error) {
	packetBufsPtr := n.tunnelBufPool.Get().(*[][]byte)
	sizesPtr := n.tunnelSizesPool.Get().(*[]int)

	defer func() {
		(*packetBufsPtr)[0] = nil
		n.tunnelBufPool.Put(packetBufsPtr)
		n.tunnelSizesPool.Put(sizesPtr)
	}()

	(*packetBufsPtr)[0] = buf
	(*sizesPtr)[0] = 0

	_, err := n.dev.Read(*packetBufsPtr, *sizesPtr, 0)
	if err != nil {
		return 0, err
	}

	return (*sizesPtr)[0], nil
}

func (n *NetstackAdapter) WritePacket(pkt []byte) error {
	// Write expects a slice of packet buffers.
	_, err := n.dev.Write([][]byte{pkt}, 0)
	return err
}

// NewNetstackAdapter creates a new NetstackAdapter.
func NewNetstackAdapter(dev tun.Device) TunnelDevice {
	return &NetstackAdapter{
		dev: dev,
		tunnelBufPool: sync.Pool{
			New: func() interface{} {
				buf := make([][]byte, 1)
				return &buf
			},
		},
		tunnelSizesPool: sync.Pool{
			New: func() interface{} {
				sizes := make([]int, 1)
				return &sizes
			},
		},
	}
}

// WaterAdapter wraps a *water.Interface so it satisfies TunnelDevice.
type WaterAdapter struct {
	iface *water.Interface
}

func (w *WaterAdapter) ReadPacket(buf []byte) (int, error) {
	n, err := w.iface.Read(buf)
	if err != nil {
		return 0, err
	}

	return n, nil
}

func (w *WaterAdapter) WritePacket(pkt []byte) error {
	_, err := w.iface.Write(pkt)
	return err
}

// NewWaterAdapter creates a new WaterAdapter.
func NewWaterAdapter(iface *water.Interface) TunnelDevice {
	return &WaterAdapter{iface: iface}
}
