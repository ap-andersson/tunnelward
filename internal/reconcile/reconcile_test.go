package reconcile

import (
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ap-andersson/tunnelward/internal/model"
	"github.com/ap-andersson/tunnelward/internal/store"
)

func TestBuild(t *testing.T) {
	serverKey, _ := wgtypes.GeneratePrivateKey()
	k1, _ := wgtypes.GeneratePrivateKey()
	k2, _ := wgtypes.GeneratePrivateKey()
	set := model.DefaultSettings
	set.MTU = 1380
	snap := store.Snapshot{
		Settings: set,
		Profiles: map[int64]model.Profile{1: {ID: 1, Name: "Internet only", Rules: []model.Rule{{Destination: model.Internet}}}},
		Devices: []model.Device{
			{ID: 1, Name: "on", PublicKey: k1.PublicKey().String(), IP: netip.MustParseAddr("10.8.0.2"), Enabled: true, ProfileIDs: []int64{1},
				Rules: []model.Rule{{Destination: "192.168.1.10/32"}}},
			{ID: 2, Name: "off", PublicKey: k2.PublicKey().String(), IP: netip.MustParseAddr("10.8.0.3"), Enabled: false, ProfileIDs: []int64{1}},
		},
	}

	d, err := Build(snap, "wg0", 51820, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	if d.Interface.Address.String() != "10.8.0.1/24" || d.Interface.MTU != 1380 || d.Interface.ListenPort != 51820 {
		t.Errorf("unexpected interface: %+v", d.Interface)
	}
	if len(d.Peers) != 1 || d.Peers[0].PublicKey != k1.PublicKey() || d.Peers[0].IP != snap.Devices[0].IP {
		t.Errorf("peers = %+v, want only the enabled device", d.Peers)
	}
	if len(d.Firewall.Peers) != 1 || len(d.Firewall.Peers[0].Rules) != 2 {
		t.Errorf("firewall peers = %+v, want the enabled device with 2 rules", d.Firewall.Peers)
	}

	snap.Devices[0].ProfileIDs = []int64{7}
	if _, err := Build(snap, "wg0", 51820, serverKey); err == nil {
		t.Error("expected an error for an unknown profile")
	}
}

func TestEndpointAddrs(t *testing.T) {
	r := &Reconciler{}
	ctx := t.Context()
	if got := r.endpointAddrs(ctx, ""); got != nil {
		t.Errorf("empty host: %v", got)
	}
	if got := r.endpointAddrs(ctx, "203.0.113.7"); len(got) != 1 || got[0].String() != "203.0.113.7" {
		t.Errorf("IP literal: %v", got)
	}
	got := r.endpointAddrs(ctx, "localhost")
	if len(got) == 0 || !got[0].IsLoopback() {
		t.Fatalf("localhost: %v", got)
	}
	// A failed lookup of the same host keeps the last known addresses.
	r.endpointHost = "does-not-resolve.invalid"
	r.endpointIPs = []netip.Addr{netip.MustParseAddr("203.0.113.9")}
	if got := r.endpointAddrs(ctx, "does-not-resolve.invalid"); len(got) != 1 || got[0].String() != "203.0.113.9" {
		t.Errorf("failed lookup: %v, want the last known address", got)
	}
}
