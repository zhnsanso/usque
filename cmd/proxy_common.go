package cmd

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// ProxyConfig holds the common configuration for proxy commands.
type ProxyConfig struct {
	BindAddress       string
	Port              string
	ConnectPort       int
	EndpointV4        *net.UDPAddr
	EndpointV6        *net.UDPAddr
	LocalAddresses    []netip.Addr
	DNSAddrs          []netip.Addr
	DNSTimeout        time.Duration
	LocalDNS          bool
	MTU               int
	Username          string
	Password          string
	ReconnectDelay    time.Duration
	KeepalivePeriod   time.Duration
	InitialPacketSize uint16
	TLSConfig         *tls.Config
}

// LoadProxyConfig loads the common configuration from command flags.
func LoadProxyConfig(cmd *cobra.Command) (*ProxyConfig, error) {
	if !config.ConfigLoaded {
		return nil, nil // Caller should handle this
	}

	sni, err := cmd.Flags().GetString("sni-address")
	if err != nil {
		return nil, err
	}

	privKey, err := config.AppConfig.GetEcPrivateKey()
	if err != nil {
		return nil, err
	}
	peerPubKey, err := config.AppConfig.GetEcEndpointPublicKey()
	if err != nil {
		return nil, err
	}

	cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
	if err != nil {
		return nil, err
	}

	tlsConfig, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, sni)
	if err != nil {
		return nil, err
	}

	keepalivePeriod, err := cmd.Flags().GetDuration("keepalive-period")
	if err != nil {
		return nil, err
	}
	initialPacketSize, err := cmd.Flags().GetUint16("initial-packet-size")
	if err != nil {
		return nil, err
	}

	bindAddress, err := cmd.Flags().GetString("bind")
	if err != nil {
		return nil, err
	}

	port, err := cmd.Flags().GetString("port")
	if err != nil {
		return nil, err
	}

	connectPort, err := cmd.Flags().GetInt("connect-port")
	if err != nil {
		return nil, err
	}

	var endpointV4, endpointV6 *net.UDPAddr
	if ip := net.ParseIP(config.AppConfig.EndpointV4); ip != nil {
		endpointV4 = &net.UDPAddr{IP: ip, Port: connectPort}
	}
	if ip := net.ParseIP(config.AppConfig.EndpointV6); ip != nil {
		endpointV6 = &net.UDPAddr{IP: ip, Port: connectPort}
	}

	if cmd.Flags().Changed("ipv6") {
		ipv6, _ := cmd.Flags().GetBool("ipv6")
		if ipv6 {
			endpointV4 = nil
		} else {
			endpointV6 = nil
		}
	}

	tunnelIPv4, err := cmd.Flags().GetBool("no-tunnel-ipv4")
	if err != nil {
		return nil, err
	}

	tunnelIPv6, err := cmd.Flags().GetBool("no-tunnel-ipv6")
	if err != nil {
		return nil, err
	}

	var localAddresses []netip.Addr
	if !tunnelIPv4 {
		v4, err := netip.ParseAddr(config.AppConfig.IPv4)
		if err == nil {
			localAddresses = append(localAddresses, v4)
		}
	}
	if !tunnelIPv6 {
		v6, err := netip.ParseAddr(config.AppConfig.IPv6)
		if err == nil {
			localAddresses = append(localAddresses, v6)
		}
	}

	dnsServers, err := cmd.Flags().GetStringArray("dns")
	if err != nil {
		return nil, err
	}

	var dnsAddrs []netip.Addr
	for _, dns := range dnsServers {
		addr, err := netip.ParseAddr(dns)
		if err == nil {
			dnsAddrs = append(dnsAddrs, addr)
		}
	}

	dnsTimeout, err := cmd.Flags().GetDuration("dns-timeout")
	if err != nil {
		return nil, err
	}

	localDNS, err := cmd.Flags().GetBool("local-dns")
	if err != nil {
		return nil, err
	}

	mtu, err := cmd.Flags().GetInt("mtu")
	if err != nil {
		return nil, err
	}
	if mtu != 1280 {
		log.Println("Warning: MTU is not the default 1280. Packet loss may occur.")
	}

	username, _ := cmd.Flags().GetString("username")
	password, _ := cmd.Flags().GetString("password")

	reconnectDelay, err := cmd.Flags().GetDuration("reconnect-delay")
	if err != nil {
		return nil, err
	}

	return &ProxyConfig{
		BindAddress:       bindAddress,
		Port:              port,
		ConnectPort:       connectPort,
		EndpointV4:        endpointV4,
		EndpointV6:        endpointV6,
		LocalAddresses:    localAddresses,
		DNSAddrs:          dnsAddrs,
		DNSTimeout:        dnsTimeout,
		LocalDNS:          localDNS,
		MTU:               mtu,
		Username:          username,
		Password:          password,
		ReconnectDelay:    reconnectDelay,
		KeepalivePeriod:   keepalivePeriod,
		InitialPacketSize: initialPacketSize,
		TLSConfig:         tlsConfig,
	}, nil
}

// StartTunnel initializes the TUN device and starts the tunnel maintenance.
func StartTunnel(ctx context.Context, cfg *ProxyConfig) (*netstack.Net, error) {
	tunDev, tunNet, err := netstack.CreateNetTUN(cfg.LocalAddresses, cfg.DNSAddrs, cfg.MTU)
	if err != nil {
		return nil, err
	}
	// Note: tunDev.Close() is leaked here as in original code, runs until exit.

	go api.MaintainTunnel(ctx, cfg.TLSConfig, cfg.KeepalivePeriod, cfg.InitialPacketSize, cfg.EndpointV4, cfg.EndpointV6, api.NewNetstackAdapter(tunDev), cfg.MTU, cfg.ReconnectDelay)

	return tunNet, nil
}

// AddProxyFlags adds common proxy flags to a command.
func AddProxyFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("bind", "b", "0.0.0.0", "Address to bind the proxy to")
	cmd.Flags().StringP("port", "p", "1080", "Port to listen on")
	cmd.Flags().StringP("username", "u", "", "Username for proxy authentication")
	cmd.Flags().StringP("password", "w", "", "Password for proxy authentication")
	cmd.Flags().IntP("connect-port", "P", 443, "Used port for MASQUE connection")
	cmd.Flags().StringArrayP("dns", "d", []string{"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"}, "DNS servers to use")
	cmd.Flags().DurationP("dns-timeout", "t", 2*time.Second, "Timeout for DNS queries")
	cmd.Flags().BoolP("ipv6", "6", false, "Use IPv6 for MASQUE connection")
	cmd.Flags().BoolP("no-tunnel-ipv4", "F", false, "Disable IPv4 inside the MASQUE tunnel")
	cmd.Flags().BoolP("no-tunnel-ipv6", "S", false, "Disable IPv6 inside the MASQUE tunnel")
	cmd.Flags().StringP("sni-address", "s", internal.ConnectSNI, "SNI address to use")
	cmd.Flags().DurationP("keepalive-period", "k", 10*time.Second, "Keepalive period")
	cmd.Flags().IntP("mtu", "m", 1280, "MTU")
	cmd.Flags().Uint16P("initial-packet-size", "i", 1242, "Initial packet size")
	cmd.Flags().DurationP("reconnect-delay", "r", 200*time.Millisecond, "Delay between reconnect attempts")
	cmd.Flags().BoolP("local-dns", "l", false, "Don't use the tunnel for DNS queries")
}

func authenticate(r *http.Request, expectedAuth string) bool {
	if expectedAuth == "" {
		return true
	}
	authHeader := r.Header.Get("Proxy-Authorization")
	return authHeader == expectedAuth
}
