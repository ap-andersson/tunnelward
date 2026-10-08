package model

import (
	"net/netip"
	"strings"
	"testing"
)

func TestRuleNormalize(t *testing.T) {
	tests := []struct {
		name string
		in   Rule
		want Rule
	}{
		{"internet alias", Rule{Destination: " Internet "}, Rule{Destination: Internet, Protocol: ProtoAny}},
		{"bare address", Rule{Destination: "192.168.1.10"}, Rule{Destination: "192.168.1.10/32", Protocol: ProtoAny}},
		{"network", Rule{Destination: "192.168.1.0/24", Protocol: ProtoICMP}, Rule{Destination: "192.168.1.0/24", Protocol: ProtoICMP}},
		{"single port", Rule{Destination: "10.0.0.1", Protocol: ProtoTCP, PortFrom: 443}, Rule{Destination: "10.0.0.1/32", Protocol: ProtoTCP, PortFrom: 443, PortTo: 443}},
		{"port range", Rule{Destination: "10.0.0.1", Protocol: ProtoTCPUDP, PortFrom: 8000, PortTo: 8100}, Rule{Destination: "10.0.0.1/32", Protocol: ProtoTCPUDP, PortFrom: 8000, PortTo: 8100}},
		{"everything", Rule{Destination: "0.0.0.0/0"}, Rule{Destination: "0.0.0.0/0", Protocol: ProtoAny}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.in
			if err := r.Normalize(); err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			if r != tt.want {
				t.Errorf("got %+v, want %+v", r, tt.want)
			}
		})
	}
}

func TestRuleNormalizeErrors(t *testing.T) {
	tests := []struct {
		name    string
		in      Rule
		wantErr string
	}{
		{"empty", Rule{}, "destination"},
		{"garbage", Rule{Destination: "lan"}, "destination"},
		{"ipv6", Rule{Destination: "fd00::/8"}, "not IPv4"},
		{"ipv4-mapped ipv6", Rule{Destination: "::ffff:10.0.0.1"}, "not IPv4"},
		{"host bits", Rule{Destination: "192.168.1.5/24"}, "did you mean 192.168.1.0/24"},
		{"unknown protocol", Rule{Destination: "10.0.0.1", Protocol: "sctp"}, "protocol"},
		{"ports without protocol", Rule{Destination: "10.0.0.1", PortFrom: 80}, "no ports"},
		{"ports on icmp", Rule{Destination: "10.0.0.1", Protocol: ProtoICMP, PortFrom: 80}, "no ports"},
		{"port too high", Rule{Destination: "10.0.0.1", Protocol: ProtoTCP, PortFrom: 1, PortTo: 70000}, "invalid range"},
		{"reversed range", Rule{Destination: "10.0.0.1", Protocol: ProtoTCP, PortFrom: 90, PortTo: 80}, "invalid range"},
		{"only port to", Rule{Destination: "10.0.0.1", Protocol: ProtoTCP, PortTo: 80}, "invalid range"},
		{"long comment", Rule{Destination: "10.0.0.1", Comment: strings.Repeat("x", 201)}, "comment"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.in
			err := r.Normalize()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("got error %v, want one containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestCheckDeviceIP(t *testing.T) {
	s := DefaultSettings // 10.8.0.0/24
	for ip, ok := range map[string]bool{
		"10.8.0.2":   true,
		"10.8.0.254": true,
		"10.8.0.0":   false, // network
		"10.8.0.1":   false, // server
		"10.8.0.255": false, // broadcast
		"10.8.1.2":   false, // outside
	} {
		err := s.CheckDeviceIP(netip.MustParseAddr(ip))
		if (err == nil) != ok {
			t.Errorf("CheckDeviceIP(%s) = %v, want ok=%v", ip, err, ok)
		}
	}
}

func TestAllocateIP(t *testing.T) {
	s := Settings{TunnelCIDR: netip.MustParsePrefix("10.8.0.0/29")} // hosts .1-.6, server .1
	used := map[netip.Addr]bool{}
	var got []string
	for {
		ip, err := s.AllocateIP(used)
		if err == ErrTunnelFull {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		used[ip] = true
		got = append(got, ip.String())
	}
	want := "10.8.0.2 10.8.0.3 10.8.0.4 10.8.0.5 10.8.0.6"
	if strings.Join(got, " ") != want {
		t.Errorf("allocated %v, want %s", got, want)
	}
}

func TestSettingsValidate(t *testing.T) {
	s := DefaultSettings
	if err := s.Validate(); err != nil {
		t.Fatalf("default settings invalid: %v", err)
	}
	bad := []func(*Settings){
		func(s *Settings) { s.ListenPort = 0 },
		func(s *Settings) { s.TunnelCIDR = netip.MustParsePrefix("10.8.0.1/24") },
		func(s *Settings) { s.TunnelCIDR = netip.MustParsePrefix("fd00::/64") },
		func(s *Settings) { s.TunnelCIDR = netip.MustParsePrefix("10.0.0.0/8") },
		func(s *Settings) { s.ClientDNS = []netip.Addr{netip.MustParseAddr("::1")} },
		func(s *Settings) { s.MTU = 100 },
		func(s *Settings) { s.EndpointHost = "vpn.example.com/x" },
	}
	for i, mutate := range bad {
		s := DefaultSettings
		mutate(&s)
		if err := s.Validate(); err == nil {
			t.Errorf("case %d: expected an error for %+v", i, s)
		}
	}
}

func TestEffectiveRules(t *testing.T) {
	profiles := map[int64]Profile{
		1: {ID: 1, Name: "Internet only", Rules: []Rule{{Destination: Internet}}},
	}
	d := Device{Name: "phone", ProfileIDs: []int64{1}, Rules: []Rule{{Destination: "192.168.1.10/32"}}}
	got, err := EffectiveRules(d, profiles)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Source != "custom" || got[1].Source != `profile "Internet only"` {
		t.Errorf("unexpected rules: %+v", got)
	}

	d.ProfileIDs = []int64{2}
	if _, err := EffectiveRules(d, profiles); err == nil {
		t.Error("expected an error for an unknown profile")
	}
}
