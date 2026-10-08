# Tunnelward — design

A small, self-hosted WireGuard server manager with per-device firewall profiles.
Companion to [TunnelVision](https://github.com/ap-andersson/tunnelvision).

Goal: a codebase small enough to read end to end, so it can be trusted.

## Scope

In scope:
- Managing WireGuard peers ("devices") on one server interface
- Per-device access control via profiles + custom rules, enforced with nftables
- A small web UI for a single admin
- Running in Docker

Out of scope (deliberately):
- Users, self-service, SSO/OIDC, MFA
- REST API for third parties
- Multiple interfaces / multiple servers / mesh

## Decisions

| Topic | Decision |
|---|---|
| Language | Go |
| Storage | SQLite (`modernc.org/sqlite`, pure Go, no cgo), single file in the data dir |
| Web | stdlib `net/http` + `html/template` + htmx + Pico CSS (both vendored, no JS build) |
| Auth | One admin account, password hash, session cookie, CSRF token, login rate limit |
| Rule model | **Allow-only union**, default deny |
| Client keys | **Generated server-side, shown once, never stored** (only public key kept) |
| Firewall | Generate nftables **text**, validate with `nft -c`, apply atomically with `nft -f` |
| WireGuard | `wgctrl-go` to sync peers; interface created/owned by Tunnelward via netlink |
| Deployment | Docker, `network_mode: host`, `cap_add: NET_ADMIN` |
| IP versions | **IPv4 only** inside the tunnel; IPv6 from peers is dropped (see below) |

## Data model

```
Device
  id, name, public_key, ipv4, enabled,
  client_allowed_ips   -- what the client routes through the tunnel (default 0.0.0.0/0, ::/0)
  created_at, updated_at
  profiles   -> many-to-many Profile
  rules      -> custom Rule rows owned by the device

Profile
  id, name, description
  rules      -> Rule rows owned by the profile

Rule  (allow only)
  id, owner (profile_id XOR device_id)
  destination   -- IPv4 CIDR, or the built-in alias "internet"
  protocol      -- any | tcp | udp | icmp
  ports         -- optional, single port or range, only for tcp/udp
  comment

Settings (single row)
  listen_port, endpoint_host, tunnel_cidr,
  client_dns, mtu, keepalive
```

A device's effective permissions = union of the rules from all its profiles + its custom rules.
Order never matters. Removing a profile can only ever *reduce* access.

### The `internet` alias
"Anything except non-public ranges". Implemented as a negated nft set:
10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16, 127/8, 0/8, 224/4, 240/4, and the tunnel subnet.

This lets a "family / internet-only" profile be a single rule.

## Firewall

Tunnelward owns exactly one table, `table inet tunnelward`, and never touches other
tables (Docker's, the host's). The whole table is regenerated on every change and applied as one
transaction (`delete table` + `add table ...` in the same `nft -f` file), so there is no incremental
state that can drift.

Sketch:

```nft
table inet tunnelward {
  set nonpublic4 { type ipv4_addr; flags interval; elements = { ... } }

  chain forward {
    type filter hook forward priority filter; policy accept;   # only judge wg traffic
    iifname != "wg0" return
    ct state established,related accept
    ct state invalid drop
    meta nfproto ipv6 drop
    ip saddr vmap { 10.8.0.2 : jump dev_1, 10.8.0.3 : jump dev_2 }
    drop                                                        # unknown source / no match
  }

  chain input {
    type filter hook input priority filter; policy accept;
    iifname != "wg0" return
    ct state established,related accept
    # traffic to the server host itself (incl. the admin UI) is denied unless a rule allows it
    meta nfproto ipv6 drop
    ip saddr vmap { ... }   # same per-device chains, input variant
    drop
  }

  chain dev_1 {
    ip daddr != @nonpublic4 accept          # profile "Internet only"
    ip daddr 192.168.1.10 tcp dport 8096 accept   # custom: Jellyfin
    drop
  }

  chain postrouting {
    type nat hook postrouting priority srcnat;
    ip saddr 10.8.0.0/24 oifname != "wg0" masquerade
  }
}
```

Points to get right (each one gets a test):
- **Default deny** for anything from `wg0` that no rule allows, including peer-to-peer.
- **No IPv6 through the tunnel**: peers' server-side AllowedIPs are v4 only (WireGuard already drops
  v6 from them), and both chains drop IPv6 explicitly as a second layer.
- **Traffic to the host itself** (input chain) is controlled too, not just forwarded traffic.
  Otherwise an "internet only" device could still reach services on the VPN host, including the admin UI.
- **Source spoofing**: WireGuard's cryptokey routing drops packets whose source isn't in the peer's
  AllowedIPs, so `saddr` identifies the device. Server-side AllowedIPs for a peer are always exactly its
  tunnel /32, never anything wider.
- **DNS**: if `client_dns` points at a LAN resolver, the UI warns when a device has no rule reaching it.
- **Fail closed**: if rendering or `nft -c` fails, nothing is applied and peers are not added/changed.

## IPv6 on the client side

The server is IPv4 only, but clients often sit on IPv6-capable networks (mobile, hotel Wi-Fi).
If a full-tunnel client routes only `0.0.0.0/0`, its IPv6 traffic bypasses the VPN entirely.
Default: client configs include `::/0` so IPv6 enters the tunnel and is dropped, and apps fall
back to IPv4 through the tunnel. (Final decision pending.)

## Apply / reconcile flow

1. Any change in the UI → DB transaction commits.
2. Build desired state from the DB.
3. Render the nft ruleset → `nft -c -f` (check) → `nft -f` (apply).
4. Sync WireGuard peers with `wgctrl` (`ReplacePeers: true`).
5. On startup: ensure the interface exists, then run steps 2–4.

Firewall goes before WireGuard so a new peer never exists without its rules.

## Secrets

- Server private key: generated on first start, stored in `<data>/server.key` with mode 0600.
- Client private keys: never stored. If lost, regenerate the device's keys.
- Admin password: set via env on first start (or generated and printed to the log once), stored as a hash.

## Layout

```
cmd/tunnelward/       main: config, startup, reconcile, http server
internal/store/       SQLite, embedded migrations, queries
internal/firewall/    ruleset rendering (pure) + apply via nft
internal/wg/          interface + peer sync via netlink/wgctrl
internal/auth/        password hashing, sessions, CSRF, rate limit
internal/web/         handlers, templates, static (htmx)
```

## Testing

- `internal/firewall`: golden-file tests of rendered rulesets (pure, no root needed).
- Integration (`go test -tags integration`, needs root): network namespaces with a fake LAN, a fake
  "internet" host and a WG server; asserts real reachability per profile, and that IPv6 is dropped.

## Milestones

1. **Core**: store + model + firewall renderer with golden tests.
2. **Host integration**: WG interface/peer sync, nft apply, startup reconcile, netns integration tests.
3. **Web UI**: login, devices (create → config + QR shown once), profiles, rules, settings.
4. **Packaging**: Dockerfile, compose example, README.
5. **Nice to have**: handshake/transfer stats per device, backup/export.
