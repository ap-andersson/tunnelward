// Package reconcile makes the kernel state (nftables table, WireGuard
// interface and peers) match the database. The database is the source of
// truth; Reconcile is called on startup and after every change.
package reconcile

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ap-andersson/tunnelward/internal/firewall"
	"github.com/ap-andersson/tunnelward/internal/model"
	"github.com/ap-andersson/tunnelward/internal/store"
	"github.com/ap-andersson/tunnelward/internal/wg"
)

// Reconciler applies the database state to the system.
type Reconciler struct {
	Store      *store.Store
	Interface  string // e.g. "wg0"
	ListenPort int
	PrivateKey wgtypes.Key

	mu sync.Mutex
}

// Reconcile reads the database and applies it, in this order:
//
//  1. Render the firewall ruleset. Any error stops here, nothing changes.
//  2. Apply the ruleset atomically. On error the old ruleset stays.
//  3. Configure the interface and sync peers.
//
// The firewall goes first so a peer never exists without its rules: a new
// peer's chain is in place before it is added, and a removed peer's packets
// are dropped (unknown source) even before it is removed from WireGuard.
func (r *Reconciler) Reconcile(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	snap, err := r.Store.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("read database: %w", err)
	}
	want, err := Build(snap, r.Interface, r.ListenPort, r.PrivateKey)
	if err != nil {
		return err
	}
	ruleset, err := firewall.Render(want.Firewall)
	if err != nil {
		return fmt.Errorf("render firewall: %w", err)
	}
	if err := firewall.Apply(ctx, ruleset); err != nil {
		return fmt.Errorf("apply firewall: %w", err)
	}
	if err := wg.EnsureInterface(want.Interface); err != nil {
		return err
	}
	if err := wg.SyncPeers(r.Interface, want.Peers); err != nil {
		return err
	}
	slog.Info("applied configuration", "interface", r.Interface, "peers", len(want.Peers))
	return nil
}

// Desired is the full system state derived from a database snapshot.
type Desired struct {
	Interface wg.Interface
	Firewall  firewall.Config
	Peers     []wg.Peer
}

// Build derives the desired system state from a snapshot. Disabled devices
// get neither a peer nor firewall rules.
func Build(snap store.Snapshot, iface string, listenPort int, key wgtypes.Key) (Desired, error) {
	set := snap.Settings
	d := Desired{
		Interface: wg.Interface{
			Name:       iface,
			PrivateKey: key,
			ListenPort: listenPort,
			Address:    netip.PrefixFrom(set.ServerIP(), set.TunnelCIDR.Bits()),
			MTU:        set.MTU,
		},
		Firewall: firewall.Config{Interface: iface, TunnelCIDR: set.TunnelCIDR},
	}
	for _, dev := range snap.Devices {
		if !dev.Enabled {
			continue
		}
		pub, err := wgtypes.ParseKey(dev.PublicKey)
		if err != nil {
			return Desired{}, fmt.Errorf("device %q: invalid public key: %w", dev.Name, err)
		}
		rules, err := model.EffectiveRules(dev, snap.Profiles)
		if err != nil {
			return Desired{}, err
		}
		d.Peers = append(d.Peers, wg.Peer{PublicKey: pub, IP: dev.IP})
		d.Firewall.Peers = append(d.Firewall.Peers, firewall.Peer{
			ID: dev.ID, Name: dev.Name, IP: dev.IP, Rules: rules,
		})
	}
	return d, nil
}
