//go:build linux

package tun

import (
	"fmt"
	"log"
	"net"

	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal/stack"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

// newNativeDevice creates a new native TUN device on Linux.
func newNativeDevice(ifaceName string, mtu int) (stack.Stack, error) {
	platformSpecificParams := water.PlatformSpecificParams{
		Name: ifaceName,
	}

	dev, err := water.New(water.Config{DeviceType: water.TUN, PlatformSpecificParams: platformSpecificParams})
	if err != nil {
		return nil, err
	}

	ifaceName = dev.Name()

	// In the future, these would come from config.
	useIproute2 := true
	enableIPv4 := true
	enableIPv6 := true

	if useIproute2 {
		link, err := netlink.LinkByName(ifaceName)
		if err != nil {
			return nil, fmt.Errorf("failed to get link: %v", err)
		}

		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			return nil, fmt.Errorf("failed to set MTU: %v", err)
		}
		if enableIPv4 {
			if err := netlink.AddrAdd(link, &netlink.Addr{
				IPNet: &net.IPNet{
					IP:   net.ParseIP(config.AppConfig.IPv4),
					Mask: net.CIDRMask(32, 32),
				}}); err != nil {
				return nil, fmt.Errorf("failed to add IPv4 address: %v", err)
			}
		}
		if enableIPv6 {
			if err := netlink.AddrAdd(link, &netlink.Addr{
				IPNet: &net.IPNet{
					IP:   net.ParseIP(config.AppConfig.IPv6),
					Mask: net.CIDRMask(128, 128),
				}}); err != nil {
				return nil, fmt.Errorf("failed to add IPv6 address: %v", err)
			}
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return nil, fmt.Errorf("failed to set link up: %v", err)
		}
	} else {
		log.Println("Skipping IP address and link setup. You should set the link up manually.")
		log.Println("Config has the following IP addresses:")
		log.Printf("IPv4: %s", config.AppConfig.IPv4)
		log.Printf("IPv6: %s", config.AppConfig.IPv6)
	}

	return stack.NewWaterAdapter(dev), nil
}
