// Package model holds the core types shared by the store, the firewall
// renderer and the web UI, together with their validation rules.
package model

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// ValidationError is returned for invalid input. Its message is meant to be
// shown to the user.
type ValidationError struct{ err error }

func (e *ValidationError) Error() string { return e.err.Error() }
func (e *ValidationError) Unwrap() error { return e.err }

func invalidf(format string, args ...any) error {
	return &ValidationError{fmt.Errorf(format, args...)}
}

// Protocol is the transport protocol a rule matches.
type Protocol string

const (
	ProtoAny    Protocol = "any"
	ProtoTCP    Protocol = "tcp"
	ProtoUDP    Protocol = "udp"
	ProtoTCPUDP Protocol = "tcp+udp"
	ProtoICMP   Protocol = "icmp"
)

// HasPorts reports whether rules with this protocol may restrict ports.
func (p Protocol) HasPorts() bool {
	return p == ProtoTCP || p == ProtoUDP || p == ProtoTCPUDP
}

// Internet is the destination alias for "every address that is not private
// or otherwise non-public". See firewall.NonPublic for the exact ranges.
const Internet = "internet"

const (
	maxNameLen    = 64
	maxCommentLen = 200
)

// Rule allows traffic from a device to a destination. There are no deny rules:
// everything not allowed by some rule is dropped.
type Rule struct {
	ID          int64
	Destination string // Internet, or a masked IPv4 prefix such as "192.168.1.0/24"
	Protocol    Protocol
	PortFrom    int // 0 means any port
	PortTo      int // equal to PortFrom for a single port
	Comment     string
}

// Normalize validates r and rewrites it into canonical form: a bare address
// becomes a /32, an empty protocol becomes ProtoAny and a single port gets
// PortTo == PortFrom.
func (r *Rule) Normalize() error {
	dest := strings.TrimSpace(r.Destination)
	if strings.EqualFold(dest, Internet) {
		r.Destination = Internet
	} else {
		p, err := parseIPv4Prefix(dest)
		if err != nil {
			return invalidf("destination: %w", err)
		}
		r.Destination = p.String()
	}

	if r.Protocol == "" {
		r.Protocol = ProtoAny
	}
	switch r.Protocol {
	case ProtoAny, ProtoTCP, ProtoUDP, ProtoTCPUDP, ProtoICMP:
	default:
		return invalidf("protocol: unknown protocol %q", r.Protocol)
	}

	if r.PortFrom == 0 && r.PortTo == 0 {
		// any port
	} else {
		if !r.Protocol.HasPorts() {
			return invalidf("ports: protocol %q has no ports", r.Protocol)
		}
		if r.PortTo == 0 {
			r.PortTo = r.PortFrom
		}
		if r.PortFrom < 1 || r.PortTo > 65535 || r.PortFrom > r.PortTo {
			return invalidf("ports: invalid range %d-%d", r.PortFrom, r.PortTo)
		}
	}

	r.Comment = strings.TrimSpace(r.Comment)
	if utf8.RuneCountInString(r.Comment) > maxCommentLen {
		return invalidf("comment: longer than %d characters", maxCommentLen)
	}
	return nil
}

// DestinationPrefix returns the destination as a prefix. ok is false for the
// Internet alias.
func (r Rule) DestinationPrefix() (p netip.Prefix, ok bool) {
	if r.Destination == Internet {
		return netip.Prefix{}, false
	}
	p, err := netip.ParsePrefix(r.Destination)
	return p, err == nil
}

// Profile is a named, reusable set of rules that can be assigned to devices.
type Profile struct {
	ID          int64
	Name        string
	Description string
	Rules       []Rule
}

// Validate checks the profile's own fields. Rules are validated separately.
func (p *Profile) Validate() error {
	p.Name = strings.TrimSpace(p.Name)
	p.Description = strings.TrimSpace(p.Description)
	if err := validateName(p.Name); err != nil {
		return err
	}
	if utf8.RuneCountInString(p.Description) > maxCommentLen {
		return invalidf("description: longer than %d characters", maxCommentLen)
	}
	return nil
}

// Device is a WireGuard peer.
type Device struct {
	ID        int64
	Name      string
	PublicKey string     // base64, as printed by `wg pubkey`
	IP        netip.Addr // tunnel address, inside Settings.TunnelCIDR
	Enabled   bool
	// ClientAllowedIPs is what the client routes into the tunnel. It ends up
	// in the client config only; the server always uses IP/32 for the peer.
	ClientAllowedIPs []netip.Prefix
	ProfileIDs       []int64
	Rules            []Rule // custom rules for this device only
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// DefaultClientAllowedIPs is a full tunnel. ::/0 is included so the client's
// IPv6 traffic enters the tunnel (where it is dropped) instead of bypassing it.
var DefaultClientAllowedIPs = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/0"),
	netip.MustParsePrefix("::/0"),
}

// Validate checks the device's own fields against the server settings.
// Rules are validated separately.
func (d *Device) Validate(s Settings) error {
	d.Name = strings.TrimSpace(d.Name)
	if err := validateName(d.Name); err != nil {
		return err
	}
	if err := ValidatePublicKey(d.PublicKey); err != nil {
		return err
	}
	if err := s.CheckDeviceIP(d.IP); err != nil {
		return err
	}
	if len(d.ClientAllowedIPs) == 0 {
		return invalidf("client allowed IPs: at least one prefix is required")
	}
	for i, p := range d.ClientAllowedIPs {
		if !p.IsValid() || p != p.Masked() {
			return invalidf("client allowed IPs: %s is not a valid network prefix", p)
		}
		d.ClientAllowedIPs[i] = p
	}
	return nil
}

// ValidatePublicKey checks that k is a base64 encoded 32 byte key.
func ValidatePublicKey(k string) error {
	b, err := base64.StdEncoding.DecodeString(k)
	if err != nil || len(b) != 32 {
		return invalidf("public key: not a valid WireGuard key")
	}
	return nil
}

// Settings is the server configuration stored in the database.
type Settings struct {
	EndpointPort int    // port clients connect to; may differ from the listen port behind a port forward
	EndpointHost string // host name or address clients connect to
	TunnelCIDR   netip.Prefix
	ClientDNS    []netip.Addr
	MTU          int // 0 means WireGuard's default
	Keepalive    int // seconds, 0 disables
}

// privateRanges are where the tunnel network may be. A public range would
// capture real internet addresses.
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
}

// DefaultSettings are used for a fresh database.
var DefaultSettings = Settings{
	EndpointPort: 51820,
	TunnelCIDR:   netip.MustParsePrefix("10.8.0.0/24"),
	Keepalive:    25,
}

// Validate checks all settings fields.
func (s *Settings) Validate() error {
	if s.EndpointPort < 1 || s.EndpointPort > 65535 {
		return invalidf("endpoint port: %d is out of range", s.EndpointPort)
	}
	s.EndpointHost = strings.TrimSpace(s.EndpointHost)
	if strings.ContainsFunc(s.EndpointHost, func(r rune) bool { return unicode.IsSpace(r) || r == '/' }) {
		return invalidf("endpoint host: must be a host name or address")
	}
	if !s.TunnelCIDR.IsValid() || !s.TunnelCIDR.Addr().Is4() || s.TunnelCIDR != s.TunnelCIDR.Masked() {
		return invalidf("tunnel network: must be a masked IPv4 prefix such as 10.8.0.0/24")
	}
	if !slices.ContainsFunc(privateRanges, func(p netip.Prefix) bool {
		return p.Bits() <= s.TunnelCIDR.Bits() && p.Contains(s.TunnelCIDR.Addr())
	}) {
		return invalidf("tunnel network: must be inside a private range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 or 100.64.0.0/10)")
	}
	if b := s.TunnelCIDR.Bits(); b < 16 || b > 29 {
		return invalidf("tunnel network: prefix length must be between /16 and /29")
	}
	for _, a := range s.ClientDNS {
		if !a.Is4() {
			return invalidf("client DNS: %s is not an IPv4 address", a)
		}
	}
	if s.MTU != 0 && (s.MTU < 1280 || s.MTU > 9000) {
		return invalidf("MTU: %d is out of range (1280-9000, or 0 for default)", s.MTU)
	}
	if s.Keepalive < 0 || s.Keepalive > 3600 {
		return invalidf("keepalive: %d is out of range", s.Keepalive)
	}
	return nil
}

// ServerIP is the server's own tunnel address: the first host in TunnelCIDR.
func (s Settings) ServerIP() netip.Addr {
	return s.TunnelCIDR.Addr().Next()
}

// broadcast returns the last address in TunnelCIDR.
func (s Settings) broadcast() netip.Addr {
	a := s.TunnelCIDR.Addr().As4()
	hostBits := 32 - s.TunnelCIDR.Bits()
	n := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	n |= 1<<hostBits - 1
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}

// CheckDeviceIP reports whether ip can be assigned to a device.
func (s Settings) CheckDeviceIP(ip netip.Addr) error {
	switch {
	case !ip.Is4():
		return invalidf("IP: must be an IPv4 address")
	case !s.TunnelCIDR.Contains(ip):
		return invalidf("IP: %s is outside the tunnel network %s", ip, s.TunnelCIDR)
	case ip == s.TunnelCIDR.Addr(), ip == s.broadcast():
		return invalidf("IP: %s is the network or broadcast address", ip)
	case ip == s.ServerIP():
		return invalidf("IP: %s is the server's address", ip)
	}
	return nil
}

// ErrTunnelFull is returned by AllocateIP when no addresses are left.
var ErrTunnelFull = errors.New("no free addresses left in the tunnel network")

// AllocateIP returns the lowest device address in the tunnel network that is
// not in used.
func (s Settings) AllocateIP(used map[netip.Addr]bool) (netip.Addr, error) {
	last := s.broadcast()
	for ip := s.ServerIP().Next(); ip.Less(last); ip = ip.Next() {
		if !used[ip] {
			return ip, nil
		}
	}
	return netip.Addr{}, ErrTunnelFull
}

// SourcedRule is a rule together with where it came from, for display and
// for comments in the generated firewall ruleset.
type SourcedRule struct {
	Rule
	Source string // e.g. `profile "Internet only"` or "custom"
}

// EffectiveRules returns the union of the device's custom rules and the rules
// of all its profiles. profiles must contain every profile in d.ProfileIDs.
func EffectiveRules(d Device, profiles map[int64]Profile) ([]SourcedRule, error) {
	var out []SourcedRule
	for _, r := range d.Rules {
		out = append(out, SourcedRule{Rule: r, Source: "custom"})
	}
	for _, id := range d.ProfileIDs {
		p, ok := profiles[id]
		if !ok {
			return nil, fmt.Errorf("device %q references unknown profile %d", d.Name, id)
		}
		for _, r := range p.Rules {
			out = append(out, SourcedRule{Rule: r, Source: fmt.Sprintf("profile %q", p.Name)})
		}
	}
	return out, nil
}

func validateName(name string) error {
	if name == "" {
		return invalidf("name: is required")
	}
	if utf8.RuneCountInString(name) > maxNameLen {
		return invalidf("name: longer than %d characters", maxNameLen)
	}
	if strings.ContainsFunc(name, func(r rune) bool { return !unicode.IsPrint(r) }) {
		return invalidf("name: contains control characters")
	}
	return nil
}

func parseIPv4Prefix(s string) (netip.Prefix, error) {
	var p netip.Prefix
	if strings.Contains(s, "/") {
		var err error
		if p, err = netip.ParsePrefix(s); err != nil {
			return p, invalidf("%q is not an IPv4 address or network", s)
		}
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return p, invalidf("%q is not an IPv4 address or network", s)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if !p.Addr().Is4() {
		return p, invalidf("%q is not IPv4", s)
	}
	if p != p.Masked() {
		return p, invalidf("%q has host bits set, did you mean %s?", s, p.Masked())
	}
	return p, nil
}
