//go:build !linux && !windows

package tun

import (
	"errors"

	"github.com/Diniboy1123/usque/internal/stack"
)

// newNativeDevice is a placeholder for unsupported platforms.
func newNativeDevice(ifaceName string, mtu int) (stack.Stack, error) {
	return nil, errors.New("native tun is not supported on this platform")
}
