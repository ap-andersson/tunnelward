package firewall

import (
	"bytes"
	"flag"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ap-andersson/tunnelward/internal/model"
)

var update = flag.Bool("update", false, "rewrite golden files in testdata/")

var tunnel = netip.MustParsePrefix("10.8.0.0/24")

func internetOnly() []model.SourcedRule {
	return []model.SourcedRule{{Rule: model.Rule{Destination: model.Internet}, Source: `profile "Internet only"`}}
}

var renderCases = map[string]Config{
	"no_peers": {Interface: "wg0", TunnelCIDR: tunnel},
	"internet_only": {
		Interface:  "wg0",
		TunnelCIDR: tunnel,
		Peers:      []Peer{{ID: 1, Name: "Kid's phone", IP: netip.MustParseAddr("10.8.0.2"), Rules: internetOnly()}},
	},
	"mixed": {
		Interface:  "wg0",
		TunnelCIDR: tunnel,
		Peers: []Peer{
			// Given out of IP order on purpose: output must be sorted.
			{ID: 3, Name: "Laptop", IP: netip.MustParseAddr("10.8.0.4"), Rules: []model.SourcedRule{
				{Rule: model.Rule{Destination: "192.168.1.0/24"}, Source: `profile "LAN"`},
				{Rule: model.Rule{Destination: model.Internet}, Source: `profile "Internet only"`},
				{Rule: model.Rule{Destination: "10.8.0.1", Protocol: model.ProtoICMP, Comment: "ping the server"}, Source: "custom"},
			}},
			{ID: 2, Name: "Grandma's tablet", IP: netip.MustParseAddr("10.8.0.3"), Rules: []model.SourcedRule{
				{Rule: model.Rule{Destination: model.Internet}, Source: `profile "Internet only"`},
				{Rule: model.Rule{Destination: "192.168.1.10", Protocol: model.ProtoTCP, PortFrom: 8096, Comment: "Jellyfin"}, Source: "custom"},
				{Rule: model.Rule{Destination: "192.168.1.2", Protocol: model.ProtoTCPUDP, PortFrom: 53}, Source: `profile "Home DNS"`},
				{Rule: model.Rule{Destination: "192.168.1.20", Protocol: model.ProtoUDP, PortFrom: 5000, PortTo: 5010}, Source: "custom"},
				// Duplicate of the internet rule via another profile: merged, both origins kept.
				{Rule: model.Rule{Destination: "internet"}, Source: `profile "Streaming"`},
			}},
			{ID: 4, Name: "Locked out\nnewline", IP: netip.MustParseAddr("10.8.0.5")},
		},
	},
	"tunnel_outside_private": {
		Interface:  "wg1",
		TunnelCIDR: netip.MustParsePrefix("198.51.100.0/24"),
		Peers:      []Peer{{ID: 1, Name: "x", IP: netip.MustParseAddr("198.51.100.2"), Rules: internetOnly()}},
	},
}

func TestRenderGolden(t *testing.T) {
	for name, cfg := range renderCases {
		t.Run(name, func(t *testing.T) {
			got, err := Render(cfg)
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			path := filepath.Join("testdata", name+".nft")
			if *update {
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run with -update to create)", err)
			}
			if got != string(want) {
				t.Errorf("ruleset differs from %s (run with -update after reviewing):\n%s", path, got)
			}
		})
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	cfg := renderCases["mixed"]
	first, _ := Render(cfg)
	for range 20 {
		if again, _ := Render(cfg); again != first {
			t.Fatal("Render output changed between calls")
		}
	}
}

func TestRenderErrors(t *testing.T) {
	peer := func(id int64, ip string) Peer {
		return Peer{ID: id, Name: "p", IP: netip.MustParseAddr(ip)}
	}
	tests := map[string]Config{
		"bad interface":       {Interface: `wg0" accept`, TunnelCIDR: tunnel},
		"ipv6 tunnel":         {Interface: "wg0", TunnelCIDR: netip.MustParsePrefix("fd00::/64")},
		"unmasked tunnel":     {Interface: "wg0", TunnelCIDR: netip.MustParsePrefix("10.8.0.1/24")},
		"peer outside tunnel": {Interface: "wg0", TunnelCIDR: tunnel, Peers: []Peer{peer(1, "10.9.0.2")}},
		"peer is server":      {Interface: "wg0", TunnelCIDR: tunnel, Peers: []Peer{peer(1, "10.8.0.1")}},
		"duplicate IP":        {Interface: "wg0", TunnelCIDR: tunnel, Peers: []Peer{peer(1, "10.8.0.2"), peer(2, "10.8.0.2")}},
		"duplicate ID":        {Interface: "wg0", TunnelCIDR: tunnel, Peers: []Peer{peer(1, "10.8.0.2"), peer(1, "10.8.0.3")}},
		"invalid rule": {Interface: "wg0", TunnelCIDR: tunnel, Peers: []Peer{{
			ID: 1, Name: "p", IP: netip.MustParseAddr("10.8.0.2"),
			Rules: []model.SourcedRule{{Rule: model.Rule{Destination: "10.0.0.1; flush ruleset"}}},
		}}},
	}
	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Render(cfg); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

// TestRulesetLoads feeds every golden ruleset to the real nft binary inside a
// throwaway user+network namespace, so it runs without root and never touches
// the host's firewall. Each ruleset is loaded twice to exercise the
// replace-existing-table path.
func TestRulesetLoads(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	if err := exec.Command("unshare", "-rn", "true").Run(); err != nil {
		t.Skipf("cannot create user namespace: %v", err)
	}
	for name, cfg := range renderCases {
		t.Run(name, func(t *testing.T) {
			ruleset, err := Render(cfg)
			if err != nil {
				t.Fatal(err)
			}
			script := `nft -f - <<'EOF'
` + ruleset + `EOF
nft -f - <<'EOF'
` + ruleset + `EOF
nft list table inet ` + Table
			cmd := exec.Command("unshare", "-rn", "sh", "-c", script)
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			if err := cmd.Run(); err != nil {
				t.Fatalf("nft rejected the ruleset: %v\n%s", err, out.String())
			}
			if !strings.Contains(out.String(), "chain forward") {
				t.Errorf("table not listed after loading:\n%s", out.String())
			}
		})
	}
}
