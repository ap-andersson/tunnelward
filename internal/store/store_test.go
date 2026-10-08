package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ap-andersson/tunnelward/internal/model"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.Context(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func randomKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func newDevice(t *testing.T, s *Store, name string, profileIDs ...int64) model.Device {
	t.Helper()
	d := model.Device{Name: name, PublicKey: randomKey(t), Enabled: true, ProfileIDs: profileIDs}
	if err := s.CreateDevice(t.Context(), &d); err != nil {
		t.Fatalf("CreateDevice(%s): %v", name, err)
	}
	return d
}

func TestOpenSeedsDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	set, err := s.Settings(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if set.TunnelCIDR != model.DefaultSettings.TunnelCIDR || set.EndpointPort != 51820 {
		t.Errorf("unexpected default settings: %+v", set)
	}
	profiles, err := s.ListProfiles(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 || profiles[0].Name != "Internet only" ||
		len(profiles[0].Rules) != 1 || profiles[0].Rules[0].Destination != model.Internet {
		t.Errorf("unexpected seeded profiles: %+v", profiles)
	}
	s.Close()

	// Reopening must not re-run migrations.
	s, err = Open(t.Context(), path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	s.Close()
}

func TestDeviceLifecycle(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()

	a := newDevice(t, s, "phone", 1)
	b := newDevice(t, s, "laptop")
	if a.IP.String() != "10.8.0.2" || b.IP.String() != "10.8.0.3" {
		t.Errorf("allocated %s and %s, want 10.8.0.2 and 10.8.0.3", a.IP, b.IP)
	}
	if !slices.Equal(a.ClientAllowedIPs, model.DefaultClientAllowedIPs) {
		t.Errorf("client allowed IPs = %v, want default", a.ClientAllowedIPs)
	}

	r := model.Rule{Destination: "192.168.1.10", Protocol: model.ProtoTCP, PortFrom: 8096, Comment: "Jellyfin"}
	if err := s.AddDeviceRule(ctx, a.ID, &r); err != nil {
		t.Fatal(err)
	}

	got, err := s.Device(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.ProfileIDs, []int64{1}) || len(got.Rules) != 1 || got.Rules[0].Destination != "192.168.1.10/32" {
		t.Errorf("unexpected device: %+v", got)
	}

	got.Name = "kid's phone"
	got.Enabled = false
	got.ProfileIDs = nil
	if err := s.UpdateDevice(ctx, &got); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Device(ctx, a.ID)
	if got.Name != "kid's phone" || got.Enabled || len(got.ProfileIDs) != 0 {
		t.Errorf("update not saved: %+v", got)
	}

	if err := s.DeleteDevice(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Device(ctx, a.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("Device after delete: %v, want ErrNotFound", err)
	}
	if err := s.DeleteRule(ctx, r.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("custom rule not deleted with its device: %v", err)
	}

	// The freed address is reused.
	c := newDevice(t, s, "tablet")
	if c.IP != a.IP {
		t.Errorf("allocated %s, want reused %s", c.IP, a.IP)
	}
}

func TestDeviceConflictsAndValidation(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()
	a := newDevice(t, s, "phone")

	dup := model.Device{Name: "phone", PublicKey: randomKey(t)}
	if err := s.CreateDevice(ctx, &dup); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate name: %v, want ErrConflict", err)
	}
	dup = model.Device{Name: "other", PublicKey: a.PublicKey}
	if err := s.CreateDevice(ctx, &dup); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate key: %v, want ErrConflict", err)
	}
	dup = model.Device{Name: "other", PublicKey: randomKey(t), IP: a.IP}
	if err := s.CreateDevice(ctx, &dup); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate IP: %v, want ErrConflict", err)
	}
	bad := model.Device{Name: "other", PublicKey: "not a key"}
	if err := s.CreateDevice(ctx, &bad); err == nil {
		t.Error("invalid key accepted")
	}
	bad = model.Device{Name: "other", PublicKey: randomKey(t), IP: netip.MustParseAddr("10.8.0.1")}
	if err := s.CreateDevice(ctx, &bad); err == nil {
		t.Error("server IP accepted")
	}
	bad = model.Device{Name: "other", PublicKey: randomKey(t), ProfileIDs: []int64{99}}
	if err := s.CreateDevice(ctx, &bad); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown profile: %v, want ErrNotFound", err)
	}
	if devices, _ := s.ListDevices(ctx); len(devices) != 1 {
		t.Errorf("failed creates left %d devices behind, want 1", len(devices))
	}
}

func TestTunnelFull(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()
	set, _ := s.Settings(ctx)
	set.TunnelCIDR = netip.MustParsePrefix("10.8.0.0/29") // room for 5 devices
	if err := s.UpdateSettings(ctx, set); err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		newDevice(t, s, string(rune('a'+i)))
	}
	d := model.Device{Name: "too many", PublicKey: randomKey(t)}
	if err := s.CreateDevice(ctx, &d); !errors.Is(err, model.ErrTunnelFull) {
		t.Errorf("got %v, want ErrTunnelFull", err)
	}
}

func TestSettingsRefuseOrphaningDevices(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()
	newDevice(t, s, "phone")
	set, _ := s.Settings(ctx)
	set.TunnelCIDR = netip.MustParsePrefix("10.9.0.0/24")
	if err := s.UpdateSettings(ctx, set); err == nil {
		t.Error("tunnel network change accepted although a device would be outside it")
	}

	set, _ = s.Settings(ctx)
	set.EndpointHost = "vpn.example.com"
	set.ClientDNS = []netip.Addr{netip.MustParseAddr("192.168.1.2"), netip.MustParseAddr("1.1.1.1")}
	if err := s.UpdateSettings(ctx, set); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Settings(ctx)
	if got.EndpointHost != "vpn.example.com" || len(got.ClientDNS) != 2 {
		t.Errorf("settings not saved: %+v", got)
	}
}

func TestProfilesAndSnapshot(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()

	lan := model.Profile{Name: "LAN", Description: "Home network"}
	if err := s.CreateProfile(ctx, &lan); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateProfile(ctx, &model.Profile{Name: "LAN"}); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate profile name: %v, want ErrConflict", err)
	}
	r := model.Rule{Destination: "192.168.1.0/24"}
	if err := s.AddProfileRule(ctx, lan.ID, &r); err != nil {
		t.Fatal(err)
	}
	if err := s.AddProfileRule(ctx, 99, &model.Rule{Destination: "10.0.0.1"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("rule for unknown profile: %v, want ErrNotFound", err)
	}
	if err := s.AddProfileRule(ctx, lan.ID, &model.Rule{Destination: "nope"}); err == nil {
		t.Error("invalid rule accepted")
	}

	r.Protocol, r.PortFrom = model.ProtoTCP, 22
	if err := s.UpdateRule(ctx, &r); err != nil {
		t.Fatal(err)
	}

	d := newDevice(t, s, "laptop", 1, lan.ID)

	snap, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Devices) != 1 || len(snap.Profiles) != 2 {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}
	rules, err := model.EffectiveRules(snap.Devices[0], snap.Profiles)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Errorf("effective rules = %+v, want 2", rules)
	}

	// Deleting a profile unassigns it, and only reduces access.
	if err := s.DeleteProfile(ctx, lan.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Device(ctx, d.ID)
	if !slices.Equal(got.ProfileIDs, []int64{1}) {
		t.Errorf("profile IDs after delete = %v, want [1]", got.ProfileIDs)
	}
}

func TestNotFound(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	checks := map[string]error{
		"Device":        func() error { _, err := s.Device(ctx, 42); return err }(),
		"Profile":       func() error { _, err := s.Profile(ctx, 42); return err }(),
		"UpdateDevice":  s.UpdateDevice(ctx, &model.Device{ID: 42, Name: "x", PublicKey: randomKey(t), IP: netip.MustParseAddr("10.8.0.9"), ClientAllowedIPs: model.DefaultClientAllowedIPs}),
		"DeleteDevice":  s.DeleteDevice(ctx, 42),
		"UpdateProfile": s.UpdateProfile(ctx, &model.Profile{ID: 42, Name: "x"}),
		"DeleteProfile": s.DeleteProfile(ctx, 42),
		"UpdateRule":    s.UpdateRule(ctx, &model.Rule{ID: 42, Destination: "10.0.0.1"}),
		"DeleteRule":    s.DeleteRule(ctx, 42),
	}
	for name, err := range checks {
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: %v, want ErrNotFound", name, err)
		}
	}
}
