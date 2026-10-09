// Package reconcile makes the kernel state (nftables table, WireGuard
// interface and peers) match the database. The database is the source of
// truth; Reconcile is called on startup and after every change.
package reconcile

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

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

	mu sync.Mutex // serializes applying

	errMu   sync.Mutex
	lastErr error // result of the last attempt

	// Last successful lookup of the endpoint host, guarded by mu.
	endpointHost string
	endpointIPs  []netip.Addr
}

// Reconcile reads the database and applies it, in this order:
//
//  1. Render the firewall ruleset. Any error stops here.
//  2. Apply the ruleset atomically. On error the old ruleset stays.
//  3. Configure the interface and sync peers.
//
// The firewall goes first so a peer never exists without its rules: a new
// peer's chain is in place before it is added, and a removed peer's packets
// are dropped (unknown source) even before it is removed from WireGuard.
//
// If step 1 or 2 fails, peers that should no longer exist are still removed,
// since that can only take access away. Nothing is added or changed.
func (r *Reconciler) Reconcile(ctx context.Context) error {
	return r.reconcile(ctx, slog.LevelInfo)
}

// Err returns the error of the last attempt, or nil if it succeeded. While
// it is non-nil, the system doesn't match the database.
func (r *Reconciler) Err() error {
	r.errMu.Lock()
	defer r.errMu.Unlock()
	return r.lastErr
}

// Run re-applies the configuration until ctx ends: every retryEvery while
// the last attempt failed, otherwise every refreshEvery. This retries failed
// changes and repairs anything changed behind Tunnelward's back.
func (r *Reconciler) Run(ctx context.Context, retryEvery, refreshEvery time.Duration) {
	for {
		wait := refreshEvery
		if r.Err() != nil {
			wait = retryEvery
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		r.reconcile(ctx, slog.LevelDebug)
	}
}

func (r *Reconciler) reconcile(ctx context.Context, successLevel slog.Level) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	peers, err := r.apply(ctx)

	r.errMu.Lock()
	failedBefore := r.lastErr != nil
	r.lastErr = err
	r.errMu.Unlock()

	switch {
	case err != nil:
		slog.Error("applying configuration failed, will retry", "err", err)
	case failedBefore:
		slog.Info("applied configuration after earlier failures", "interface", r.Interface, "peers", peers)
	default:
		slog.Log(ctx, successLevel, "applied configuration", "interface", r.Interface, "peers", peers)
	}
	return err
}

// apply does the work of one attempt and returns the number of peers.
func (r *Reconciler) apply(ctx context.Context) (int, error) {
	snap, err := r.Store.Snapshot(ctx)
	if err != nil {
		return 0, fmt.Errorf("read database: %w", err)
	}
	want, err := Build(snap, r.Interface, r.ListenPort, r.PrivateKey)
	if err != nil {
		return 0, err
	}
	want.Firewall.ExcludeFromInternet = r.endpointAddrs(ctx, snap.Settings.EndpointHost)
	ruleset, err := firewall.Render(want.Firewall)
	if err == nil {
		err = firewall.Apply(ctx, ruleset)
	}
	if err != nil {
		if perr := wg.RemovePeersExcept(r.Interface, want.Peers); perr != nil {
			slog.Error("removing peers after a firewall error failed", "err", perr)
		}
		return 0, fmt.Errorf("firewall: %w", err)
	}
	if err := wg.EnsureInterface(want.Interface); err != nil {
		return 0, err
	}
	if err := wg.SyncPeers(r.Interface, want.Peers); err != nil {
		return 0, err
	}
	return len(want.Peers), nil
}

// endpointAddrs returns the IPv4 addresses of the endpoint host (your public
// IP), which the internet alias excludes. If resolving fails, the last known
// addresses are kept, so a DNS hiccup doesn't widen access. Called with mu held.
func (r *Reconciler) endpointAddrs(ctx context.Context, host string) []netip.Addr {
	if host == "" {
		return nil
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a.Unmap()}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	found, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		if host == r.endpointHost {
			slog.Warn("looking up the endpoint host failed, keeping its last known address", "host", host, "err", err)
			return r.endpointIPs
		}
		slog.Warn("looking up the endpoint host failed, so internet rules don't exclude your public IP yet", "host", host, "err", err)
		return nil
	}
	addrs := make([]netip.Addr, len(found))
	for i, a := range found {
		addrs[i] = a.Unmap()
	}
	slices.SortFunc(addrs, netip.Addr.Compare)
	if host != r.endpointHost || !slices.Equal(addrs, r.endpointIPs) {
		slog.Info("excluding the endpoint's address from internet rules", "host", host, "addrs", addrs)
	}
	r.endpointHost, r.endpointIPs = host, addrs
	return addrs
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
