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
| Auth | One admin account (bcrypt), set on a first-visit setup page; in-memory sessions, SameSite=Strict cookie, Go's `CrossOriginProtection` against CSRF, login rate limit |
| Rule model | **Allow-only union**, default deny |
| Client keys | **Generated server-side, shown once, never stored** (only public key kept) |
| Firewall | Generate nftables **text**, apply atomically with `nft -f` (all or nothing) |
| WireGuard | `wgctrl-go` to sync peers; interface created/owned by Tunnelward via netlink |
| Deployment | Docker, **bridge network** (not host), `cap_add: NET_ADMIN`; everything lives in the container's network namespace |
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
  endpoint_host, endpoint_port,   -- what clients connect to (e.g. router port forward)
  tunnel_cidr,
  client_dns, mtu, keepalive
```

A device's effective permissions = union of the rules from all its profiles + its custom rules.
Order never matters. Removing a profile can only ever *reduce* access.

### The `internet` alias
"Anything except non-public ranges". Implemented as a negated nft set:
10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16, 127/8, 0/8, 192.0.0/24, 198.18/15, 224/4, 240/4,
the tunnel subnet, and the endpoint host's address (your own public IP). Excluding the public IP keeps
devices away from the router and port forwards through hairpin NAT. It is looked up on every apply
(also every 5 minutes, to follow dynamic DNS); if a lookup fails the last known address is kept.

This lets a "family / internet-only" profile be a single rule.

## Firewall

Tunnelward owns exactly one table, `table inet tunnelward`, and never touches other
tables (Docker's, the host's). The whole table is regenerated on every change and applied as one
transaction (`delete table` + `add table ...` in the same `nft -f` file), so there is no incremental
state that can drift.

Sketch:

```nft
table inet tunnelward {
  set nonpublic { type ipv4_addr; flags interval; elements = { ... } }

  chain forward {
    type filter hook forward priority filter; policy accept;   # only judge wg traffic
    iifname != "wg0" oifname != "wg0" return
    ct state invalid drop
    ct state established,related ct direction reply accept     # only replies skip the rules
    iifname != "wg0" drop                                       # nothing else into the tunnel
    meta nfproto ipv6 drop
    ip saddr vmap { 10.8.0.2 : jump fwd_dev_1, 10.8.0.3 : jump fwd_dev_2 }
    drop                                                        # unknown source / no match
  }

  chain input {
    type filter hook input priority filter; policy accept;
    iifname != "wg0" return
    ct state invalid drop
    ct state established,related ct direction reply accept
    # traffic to the server itself (the container, incl. the admin UI) is denied unless a rule allows it
    meta nfproto ipv6 drop
    ip saddr vmap { 10.8.0.2 : jump in_dev_1, ... }            # same rules, minus "internet" ones
    drop
  }

  chain fwd_dev_1 {
    ip daddr != @nonpublic accept                    # profile "Internet only"
    ip daddr 192.168.1.10 tcp dport 8096 accept      # custom: Jellyfin
  }

  chain postrouting {
    type nat hook postrouting priority srcnat;
    ip saddr 10.8.0.0/24 oifname != "wg0" masquerade
  }
}
```

Points to get right (each one gets a test):
- **Default deny** for anything from `wg0` that no rule allows, including peer-to-peer.
- **Rule changes apply to open connections too**: only reply packets skip the rules (`ct direction
  reply`). Everything a device sends is checked against its current rules, so removing a rule cuts
  connections that are already open instead of letting them run until they close.
- **No IPv6 through the tunnel**: peers' server-side AllowedIPs are v4 only (WireGuard already drops
  v6 from them), and both chains drop IPv6 explicitly as a second layer.
- **Traffic to the server itself** (input chain) is controlled too, not just forwarded traffic.
  Otherwise an "internet only" device could still reach the admin UI.
- **Source spoofing**: WireGuard's cryptokey routing drops packets whose source isn't in the peer's
  AllowedIPs, so `saddr` identifies the device. Server-side AllowedIPs for a peer are always exactly its
  tunnel /32, never anything wider.
- **DNS**: if `client_dns` points at a LAN resolver, the UI warns when a device has no rule reaching it.
- **No new connections into the tunnel** from the LAN or anywhere else; devices only receive replies.
- **`internet` rules do not apply to the server itself** (input chain), i.e. the container. The
  Docker host is reached like any other address, and your public IP is excluded from `internet`.
  Other rules apply to both forwarded traffic and the server.
- **Fail closed**: if rendering or `nft -f` fails, the old ruleset stays and no peers are added or
  changed. Peers that should no longer exist are still removed, since that only takes access away.

## IPv6 on the client side

The server is IPv4 only, but clients often sit on IPv6-capable networks (mobile, hotel Wi-Fi).
If a full-tunnel client routes only `0.0.0.0/0`, its IPv6 traffic bypasses the VPN entirely.
Decision: client configs include `::/0` by default, so IPv6 enters the tunnel and is dropped, and apps
fall back to IPv4 through the tunnel. A device's client allowed IPs can still be edited by hand.

## Docker networking

Tunnelward runs on a normal Docker bridge network, like Firezone 0.7 and wg-easy. The WireGuard
interface, the nftables table and IP forwarding all live in the **container's** network namespace:

- `NET_ADMIN` only applies inside the container, so Tunnelward cannot touch the host's firewall.
- From Docker's point of view, VPN traffic is ordinary outbound container traffic, so Docker's
  `FORWARD` DROP policy, ufw and firewalld don't interfere.
- "The server itself" (input chain) means the container. Services on the Docker host are reached
  through its LAN IP and need a rule like any other LAN destination.
- Double NAT (container, then host) is invisible in practice. LAN devices see the host's IP.
- The container always listens on `TW_WG_PORT` (default 51820), published in compose. What clients
  connect to (`endpoint_host:endpoint_port`) is a setting, since a router port forward may differ.
- Requires the `wireguard` kernel module on the host (standard on Ubuntu) and the
  `net.ipv4.ip_forward=1` sysctl on the container (allowed in bridge mode).

## Apply / reconcile flow

1. Any change in the UI → DB transaction commits.
2. Build desired state from the DB.
3. Render the nft ruleset → `nft -f` (atomic).
4. Ensure the interface, then sync WireGuard peers with `wgctrl` by diffing, so unchanged peers keep
   their sessions.
5. On startup run steps 2–4. If that fails, the admin UI still starts (WireGuard stays down).

Firewall goes before WireGuard so a new peer never exists without its rules.

Applying runs independently of the browser request, so closing a tab can't stop it halfway. A failed
attempt is retried every 30 seconds, and the configuration is re-applied every 5 minutes anyway to
repair drift. While the system doesn't match the database, the UI shows a banner with the error.

## Secrets

- Server private key: generated on first start, stored in `<data>/server.key` with mode 0600.
- Client private keys: never stored. If lost, regenerate the device's keys.
- Admin password: chosen on the `/setup` page on first visit (only the first submission can succeed; startup logs a warning
  until it's done), stored as a bcrypt hash. Changeable in Settings, which logs out all other sessions.

## Layout

```
cmd/tunnelward/       main: config, startup, reconcile, http server
internal/model/       core types, validation, IP allocation (pure)
internal/store/       SQLite, embedded migrations, queries
internal/firewall/    ruleset rendering (pure) + apply via nft
internal/wg/          interface + peer sync via netlink/wgctrl
internal/reconcile/   database -> firewall + WireGuard, in a fail-closed order
internal/auth/        password hashing, sessions, login rate limit
internal/clientconf/  client config files (wg-quick format) and file names
internal/web/         handlers, templates, static (htmx 2.0.4, Pico 2.1.1, Atkinson Hyperlegible Next + Mono, all vendored)
```

## Testing

- `internal/firewall`: golden-file tests of rendered rulesets (pure, no root needed).
- Integration (`go test -tags integration`, needs root): network namespaces with a fake LAN, a fake
  "internet" host and a WG server; asserts real reachability per profile, and that IPv6 is dropped.

## Milestones

1. **Core**: store + model + firewall renderer with golden tests.
2. **WireGuard + firewall integration**: WG interface/peer sync, nft apply, startup reconcile, netns integration tests.
3. **Web UI**: login, devices (create → config + QR shown once), profiles, rules, settings.
4. **Packaging**: Dockerfile, compose example, README.
5. **Nice to have**: handshake/transfer stats per device, backup/export.
