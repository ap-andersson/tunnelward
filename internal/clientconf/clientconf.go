// Package clientconf renders WireGuard client configuration files.
package clientconf

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ap-andersson/tunnelward/internal/model"
)

// Params is everything a client config is built from.
type Params struct {
	Settings        model.Settings
	Device          model.Device
	PrivateKey      wgtypes.Key // the device's, never stored
	ServerPublicKey wgtypes.Key
}

// Render returns the client's wg-quick style configuration.
func Render(p Params) (string, error) {
	if p.Settings.EndpointHost == "" {
		return "", fmt.Errorf("the server's endpoint host is not set (Settings)")
	}
	var b strings.Builder
	line := func(k, v string) { fmt.Fprintf(&b, "%s = %s\n", k, v) }

	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "# %s\n", strings.Map(printableOnly, p.Device.Name))
	line("PrivateKey", p.PrivateKey.String())
	line("Address", p.Device.IP.String()+"/32")
	if len(p.Settings.ClientDNS) > 0 {
		dns := make([]string, len(p.Settings.ClientDNS))
		for i, a := range p.Settings.ClientDNS {
			dns[i] = a.String()
		}
		line("DNS", strings.Join(dns, ", "))
	}
	if p.Settings.MTU != 0 {
		line("MTU", strconv.Itoa(p.Settings.MTU))
	}

	b.WriteString("\n[Peer]\n")
	line("PublicKey", p.ServerPublicKey.String())
	allowed := make([]string, len(p.Device.ClientAllowedIPs))
	for i, a := range p.Device.ClientAllowedIPs {
		allowed[i] = a.String()
	}
	line("AllowedIPs", strings.Join(allowed, ", "))
	line("Endpoint", net.JoinHostPort(p.Settings.EndpointHost, strconv.Itoa(p.Settings.EndpointPort)))
	if p.Settings.Keepalive != 0 {
		line("PersistentKeepalive", strconv.Itoa(p.Settings.Keepalive))
	}
	return b.String(), nil
}

// FileName returns a file name for the device's config. Many clients use
// the file name as the tunnel name, which must be at most 15 characters of
// [A-Za-z0-9_=+.-].
func FileName(deviceName string) string {
	name := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-', r == '.':
			return r
		case r == ' ':
			return '-'
		}
		return -1
	}, deviceName)
	name = strings.Trim(name, ".-")
	if len(name) > 15 {
		name = name[:15]
	}
	if name == "" {
		name = "tunnelward"
	}
	return name + ".conf"
}

func printableOnly(r rune) rune {
	if r < ' ' || r == 0x7f {
		return -1
	}
	return r
}
