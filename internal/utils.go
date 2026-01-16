package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

// PortMapping represents a network port forwarding rule.
type PortMapping struct {
	BindAddress string // The address to bind the local port.
	LocalPort   int    // The local port number.
	RemoteIP    string // The remote destination IP address.
	RemotePort  int    // The remote destination port number.
}

// GenerateRandomAndroidSerial generates a random 8-byte Android-like device identifier
// and returns it as a hexadecimal string.
func GenerateRandomAndroidSerial() (string, error) {
	serial := make([]byte, 8)
	if _, err := rand.Read(serial); err != nil {
		return "", err
	}
	return hex.EncodeToString(serial), nil
}

// GenerateRandomWgPubkey generates a random 32-byte WireGuard like public key
// and returns it as a base64-encoded string.
func GenerateRandomWgPubkey() (string, error) {
	publicKey := make([]byte, 32)
	if _, err := rand.Read(publicKey); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(publicKey), nil
}

// TimeAsCfString formats a given time.Time into a Cloudflare-compatible string format.
func TimeAsCfString(t time.Time) string {
	return t.Format("2006-01-02T15:04:05.000-07:00")
}

// GenerateEcKeyPair generates a new ECDSA key pair using the P-256 curve.
func GenerateEcKeyPair() ([]byte, []byte, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	marshalledPrivKey, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, nil, err
	}

	marshalledPubKey, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	return marshalledPrivKey, marshalledPubKey, nil
}

// parsePortMapping is an internal helper function that parses a port mapping string into its components.
func parsePortMapping(port string) (bindAddress string, localPort int, remoteHost string, remotePort int, err error) {
	parts := strings.Split(port, ":")

	if len(parts) >= 4 && strings.HasPrefix(parts[0], "[") && strings.Contains(parts[0], "]") {
		bindAddress = parts[0]
		parts = parts[1:]
	} else if len(parts) == 3 {
		bindAddress = "localhost"
	} else if len(parts) == 4 {
		bindAddress = parts[0]
		parts = parts[1:]
	} else {
		return "", 0, "", 0, errors.New("invalid port mapping format (expected format: [bind_address:]local_port:remote_host:remote_port)")
	}

	localPort, err = strconv.Atoi(parts[0])
	if err != nil || localPort <= 0 || localPort > 65535 {
		return "", 0, "", 0, errors.New("invalid local port")
	}

	remoteHost = parts[1]
	if net.ParseIP(remoteHost) == nil && !isValidHostname(remoteHost) {
		return "", 0, "", 0, errors.New("invalid remote hostname/IP")
	}

	remotePort, err = strconv.Atoi(parts[2])
	if err != nil || remotePort <= 0 || remotePort > 65535 {
		return "", 0, "", 0, errors.New("invalid remote port")
	}

	if strings.HasPrefix(bindAddress, "[") && strings.HasSuffix(bindAddress, "]") {
		bindAddress = strings.Trim(bindAddress, "[]")
	}

	if bindAddress == "*" {
		bindAddress = "0.0.0.0"
	}

	bindAddress, err = resolveBindAddress(bindAddress)
	if err != nil {
		return "", 0, "", 0, errors.New("invalid local address: " + err.Error())
	}

	remoteHost, err = resolveBindAddress(remoteHost)
	if err != nil {
		return "", 0, "", 0, errors.New("invalid remote address: " + err.Error())
	}

	return bindAddress, localPort, remoteHost, remotePort, nil
}

// ParsePortMapping parses a port mapping string into a structured PortMapping.
func ParsePortMapping(port string) (PortMapping, error) {
	bindAddress, localPort, remoteHost, remotePort, err := parsePortMapping(port)
	if err != nil {
		return PortMapping{}, err
	}

	return PortMapping{
		BindAddress: bindAddress,
		LocalPort:   localPort,
		RemoteIP:    remoteHost,
		RemotePort:  remotePort,
	}, nil
}

// resolveBindAddress resolves a hostname or IP to its string representation.
func resolveBindAddress(addr string) (string, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr+":0")
	if err != nil {
		return "", err
	}
	return tcpAddr.IP.String(), nil
}

// isValidHostname checks if a given hostname is valid.
func isValidHostname(hostname string) bool {
	if hostname == "localhost" {
		return true
	}
	return strings.Contains(hostname, ".")
}

// LoginToBase64 encodes a username and password into a base64-encoded string in "username:password" format.
func LoginToBase64(username, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}

// CheckIfname validates a network interface name.
func CheckIfname(name string) error {
	if name == "" {
		return errors.New("interface name cannot be empty")
	}

	if len(name) >= 16 {
		log.Printf("Warning: interface name '%s' is longer than %d characters", name, 16-1)
	}

	var invalidChar bool
	var hasWhitespace bool

	for _, r := range name {
		if r > 127 {
			invalidChar = true
			break
		}
		if r == '/' || r == ' ' || strings.ContainsRune("\t\n\v\f\r", r) {
			hasWhitespace = true
			break
		}
	}

	if invalidChar {
		log.Printf("Warning: interface name contains non-ASCII character")
	}

	if hasWhitespace {
		return errors.New("interface name contains invalid character: '/' or whitespace")
	}

	return nil
}
