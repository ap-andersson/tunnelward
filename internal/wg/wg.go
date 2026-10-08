// Package wg manages the server's WireGuard interface and its peers through
// netlink, in the current network namespace.
package wg

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// DefaultMTU is used when no MTU is configured. It is WireGuard's own default.
const DefaultMTU = 1420

// LoadOrCreatePrivateKey reads the server's private key from path, creating
// it (mode 0600) if the file doesn't exist.
func LoadOrCreatePrivateKey(path string) (wgtypes.Key, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		return wgtypes.ParseKey(strings.TrimSpace(string(b)))
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return wgtypes.Key{}, err
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, err
	}
	// O_EXCL: never overwrite a key that appeared in the meantime.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return wgtypes.Key{}, err
	}
	if _, err := f.WriteString(key.String() + "\n"); err != nil {
		f.Close()
		return wgtypes.Key{}, err
	}
	return key, f.Close()
}

// NewKeyPair generates a key pair for a client device.
func NewKeyPair() (private, public wgtypes.Key, err error) {
	private, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		return private, public, err
	}
	return private, private.PublicKey(), nil
}

// Interface is the desired state of the server interface.
type Interface struct {
	Name       string
	PrivateKey wgtypes.Key
	ListenPort int
	Address    netip.Prefix // server IP with the tunnel's prefix length, e.g. 10.8.0.1/24
	MTU        int          // 0 means DefaultMTU
}

// EnsureInterface creates the interface if needed and brings its key, port,
// address and MTU in line with iface. Existing peers are left alone.
func EnsureInterface(iface Interface) error {
	link, err := netlink.LinkByName(iface.Name)
	var notFound netlink.LinkNotFoundError
	switch {
	case errors.As(err, &notFound):
		attrs := netlink.NewLinkAttrs()
		attrs.Name = iface.Name
		if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: attrs}); err != nil {
			return fmt.Errorf("create interface %s: %w", iface.Name, err)
		}
		if link, err = netlink.LinkByName(iface.Name); err != nil {
			return err
		}
	case err != nil:
		return fmt.Errorf("look up interface %s: %w", iface.Name, err)
	case link.Type() != "wireguard":
		return fmt.Errorf("interface %s exists but is a %s interface, not wireguard", iface.Name, link.Type())
	}

	mtu := cmp.Or(iface.MTU, DefaultMTU)
	if link.Attrs().MTU != mtu {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			return fmt.Errorf("set MTU: %w", err)
		}
	}
	if err := setOnlyAddress(link, iface.Address); err != nil {
		return err
	}

	c, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer c.Close()
	err = c.ConfigureDevice(iface.Name, wgtypes.Config{
		PrivateKey: &iface.PrivateKey,
		ListenPort: &iface.ListenPort,
	})
	if err != nil {
		return fmt.Errorf("configure %s: %w", iface.Name, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring up %s: %w", iface.Name, err)
	}
	return nil
}

// setOnlyAddress makes want the interface's only IPv4 address.
func setOnlyAddress(link netlink.Link, want netip.Prefix) error {
	wantNet := toIPNet(want)
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	found := false
	for _, a := range addrs {
		if a.IPNet.String() == wantNet.String() {
			found = true
			continue
		}
		if err := netlink.AddrDel(link, &a); err != nil {
			return fmt.Errorf("remove address %s: %w", a.IPNet, err)
		}
	}
	if !found {
		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: &wantNet}); err != nil {
			return fmt.Errorf("add address %s: %w", want, err)
		}
	}
	return nil
}

// Peer is the server-side view of a device.
type Peer struct {
	PublicKey wgtypes.Key
	IP        netip.Addr // the peer's only allowed IP (as /32)
}

// SyncPeers makes the interface's peers exactly peers. Peers that are
// already correct are not touched, so their sessions are not interrupted.
func SyncPeers(name string, peers []Peer) error {
	c, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer c.Close()
	dev, err := c.Device(name)
	if err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}

	want := make(map[wgtypes.Key]netip.Prefix, len(peers))
	for _, p := range peers {
		if !p.IP.Is4() {
			return fmt.Errorf("peer %s: %s is not an IPv4 address", p.PublicKey, p.IP)
		}
		want[p.PublicKey] = netip.PrefixFrom(p.IP, 32)
	}

	var changes []wgtypes.PeerConfig
	have := map[wgtypes.Key]bool{}
	for _, p := range dev.Peers {
		have[p.PublicKey] = true
		prefix, ok := want[p.PublicKey]
		switch {
		case !ok:
			changes = append(changes, wgtypes.PeerConfig{PublicKey: p.PublicKey, Remove: true})
		case !sameAllowedIPs(p.AllowedIPs, prefix):
			changes = append(changes, peerConfig(p.PublicKey, prefix))
		}
	}
	for _, p := range peers {
		if !have[p.PublicKey] {
			changes = append(changes, peerConfig(p.PublicKey, want[p.PublicKey]))
		}
	}
	if len(changes) == 0 {
		return nil
	}
	// Removals first, so an IP moving from a removed peer to a new one
	// isn't briefly claimed by both.
	slices.SortStableFunc(changes, func(a, b wgtypes.PeerConfig) int {
		switch {
		case a.Remove == b.Remove:
			return 0
		case a.Remove:
			return -1
		}
		return 1
	})
	if err := c.ConfigureDevice(name, wgtypes.Config{Peers: changes}); err != nil {
		return fmt.Errorf("configure peers on %s: %w", name, err)
	}
	return nil
}

// PeerKeys returns the public keys of the interface's current peers.
func PeerKeys(name string) ([]wgtypes.Key, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	dev, err := c.Device(name)
	if err != nil {
		return nil, err
	}
	keys := make([]wgtypes.Key, len(dev.Peers))
	for i, p := range dev.Peers {
		keys[i] = p.PublicKey
	}
	return keys, nil
}

func peerConfig(key wgtypes.Key, prefix netip.Prefix) wgtypes.PeerConfig {
	return wgtypes.PeerConfig{
		PublicKey:         key,
		ReplaceAllowedIPs: true,
		AllowedIPs:        []net.IPNet{toIPNet(prefix)},
	}
}

func sameAllowedIPs(have []net.IPNet, want netip.Prefix) bool {
	return len(have) == 1 && have[0].String() == want.String()
}

func toIPNet(p netip.Prefix) net.IPNet {
	return net.IPNet{
		IP:   p.Addr().AsSlice(),
		Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen()),
	}
}
