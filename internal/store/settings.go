package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"strings"

	"github.com/ap-andersson/tunnelward/internal/model"
)

// Settings returns the server settings.
func (s *Store) Settings(ctx context.Context) (model.Settings, error) {
	return getSettings(ctx, s.db)
}

// UpdateSettings validates and saves set. Changing the tunnel network is
// refused while any device has an address that would fall outside it.
func (s *Store) UpdateSettings(ctx context.Context, set model.Settings) error {
	if err := set.Validate(); err != nil {
		return err
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		devices, err := listDevices(ctx, tx)
		if err != nil {
			return err
		}
		for _, d := range devices {
			if err := set.CheckDeviceIP(d.IP); err != nil {
				return fmt.Errorf("device %q: %w", d.Name, err)
			}
		}
		dns := make([]string, len(set.ClientDNS))
		for i, a := range set.ClientDNS {
			dns[i] = a.String()
		}
		_, err = tx.ExecContext(ctx, `
			UPDATE settings SET listen_port = ?, endpoint_host = ?, tunnel_cidr = ?,
				client_dns = ?, mtu = ?, keepalive = ?
			WHERE id = 1`,
			set.ListenPort, set.EndpointHost, set.TunnelCIDR.String(),
			strings.Join(dns, ","), set.MTU, set.Keepalive)
		return err
	})
}

func getSettings(ctx context.Context, q querier) (model.Settings, error) {
	var (
		set       model.Settings
		cidr, dns string
	)
	err := q.QueryRowContext(ctx, `
		SELECT listen_port, endpoint_host, tunnel_cidr, client_dns, mtu, keepalive
		FROM settings WHERE id = 1`,
	).Scan(&set.ListenPort, &set.EndpointHost, &cidr, &dns, &set.MTU, &set.Keepalive)
	if err != nil {
		return set, fmt.Errorf("read settings: %w", err)
	}
	if set.TunnelCIDR, err = netip.ParsePrefix(cidr); err != nil {
		return set, fmt.Errorf("read settings: %w", err)
	}
	if set.ClientDNS, err = splitList(dns, netip.ParseAddr); err != nil {
		return set, fmt.Errorf("read settings: %w", err)
	}
	return set, nil
}

// splitList parses a comma-separated list. An empty string is an empty list.
func splitList[T any](s string, parse func(string) (T, error)) ([]T, error) {
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	out := make([]T, len(parts))
	for i, p := range parts {
		v, err := parse(p)
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}
