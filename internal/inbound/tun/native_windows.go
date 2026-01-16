//go:build windows

package tun

import (
	"fmt"

	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/Diniboy1123/usque/internal/stack"
	"golang.zx2c4.com/wireguard/tun"
)

// newNativeDevice creates a new native TUN device on Windows using wintun.
func newNativeDevice(ifaceName string, mtu int) (stack.Stack, error) {
	if ifaceName == "" {
		ifaceName = "usque"
	}

	dev, err := tun.CreateTUN(ifaceName, mtu)
	if err != nil {
		return nil, err
	}

	ifaceName, err = dev.Name()
	if err != nil {
		return nil, err
	}

	// In the future, these would come from config.
	enableIPv4 := true
	enableIPv6 := true

	if enableIPv4 {
		err = internal.SetIPv4Address(ifaceName, config.AppConfig.IPv4, "255.255.255.255")
		if err != nil {
			return nil, fmt.Errorf("failed to set IPv4 address: %v", err)
		}

		err = internal.SetIPv4MTU(ifaceName, mtu)
		if err != nil {
			return nil, fmt.Errorf("failed to set IPv4 MTU: %v", err)
		}
	}

	if enableIPv6 {
		err = internal.SetIPv6Address(ifaceName, config.AppConfig.IPv6, "128")
		if err != nil {
			return nil, fmt.Errorf("failed to set IPv6 address: %v", err)
		}

		err = internal.SetIPv6MTU(ifaceName, mtu)
		if err != nil {
			return nil, fmt.Errorf("failed to set IPv6 MTU: %v", err)
		}
	}

	return stack.NewNetstackAdapter(dev), nil
}
