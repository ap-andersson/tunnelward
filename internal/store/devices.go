package store

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"slices"
	"strings"

	"github.com/ap-andersson/tunnelward/internal/model"
)

// ListDevices returns all devices, with their profile IDs and custom rules,
// ordered by IP.
func (s *Store) ListDevices(ctx context.Context) ([]model.Device, error) {
	return listDevices(ctx, s.db)
}

// Device returns one device.
func (s *Store) Device(ctx context.Context, id int64) (model.Device, error) {
	devices, err := queryDevices(ctx, s.db, "WHERE id = ?", id)
	if err != nil {
		return model.Device{}, err
	}
	if len(devices) == 0 {
		return model.Device{}, ErrNotFound
	}
	return devices[0], nil
}

// CreateDevice validates and inserts d, setting its ID and timestamps.
// If d.IP is the zero value, the lowest free address is allocated. If
// d.ClientAllowedIPs is empty, model.DefaultClientAllowedIPs is used.
// Custom rules are not saved here; add them with AddDeviceRule.
func (s *Store) CreateDevice(ctx context.Context, d *model.Device) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		set, err := getSettings(ctx, tx)
		if err != nil {
			return err
		}
		if !d.IP.IsValid() {
			if d.IP, err = allocateIP(ctx, tx, set); err != nil {
				return err
			}
		}
		if len(d.ClientAllowedIPs) == 0 {
			d.ClientAllowedIPs = slices.Clone(model.DefaultClientAllowedIPs)
		}
		if err := d.Validate(set); err != nil {
			return err
		}
		ts := now()
		res, err := tx.ExecContext(ctx, `
			INSERT INTO devices (name, public_key, ip, enabled, client_allowed_ips, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			d.Name, d.PublicKey, d.IP.String(), d.Enabled, joinPrefixes(d.ClientAllowedIPs), ts, ts)
		if err != nil {
			return mapErr(err)
		}
		if d.ID, err = res.LastInsertId(); err != nil {
			return err
		}
		if err := setDeviceProfiles(ctx, tx, d.ID, d.ProfileIDs); err != nil {
			return err
		}
		d.CreatedAt, _ = parseTime(ts)
		d.UpdatedAt = d.CreatedAt
		return nil
	})
}

// UpdateDevice validates and saves d's name, key, IP, enabled flag, client
// allowed IPs and profile assignments. Custom rules are managed separately.
func (s *Store) UpdateDevice(ctx context.Context, d *model.Device) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		set, err := getSettings(ctx, tx)
		if err != nil {
			return err
		}
		if err := d.Validate(set); err != nil {
			return err
		}
		ts := now()
		err = checkAffected(tx.ExecContext(ctx, `
			UPDATE devices SET name = ?, public_key = ?, ip = ?, enabled = ?,
				client_allowed_ips = ?, updated_at = ?
			WHERE id = ?`,
			d.Name, d.PublicKey, d.IP.String(), d.Enabled, joinPrefixes(d.ClientAllowedIPs), ts, d.ID))
		if err != nil {
			return err
		}
		if err := setDeviceProfiles(ctx, tx, d.ID, d.ProfileIDs); err != nil {
			return err
		}
		d.UpdatedAt, _ = parseTime(ts)
		return nil
	})
}

// DeleteDevice deletes a device together with its custom rules.
func (s *Store) DeleteDevice(ctx context.Context, id int64) error {
	return checkAffected(s.db.ExecContext(ctx, "DELETE FROM devices WHERE id = ?", id))
}

func setDeviceProfiles(ctx context.Context, tx *sql.Tx, deviceID int64, profileIDs []int64) error {
	if _, err := tx.ExecContext(ctx, "DELETE FROM device_profiles WHERE device_id = ?", deviceID); err != nil {
		return err
	}
	for _, pid := range profileIDs {
		_, err := tx.ExecContext(ctx,
			"INSERT OR IGNORE INTO device_profiles (device_id, profile_id) VALUES (?, ?)", deviceID, pid)
		if err = mapErr(err); errors.Is(err, ErrNotFound) {
			return model.Invalidf("profiles: a selected profile no longer exists, please check the list again")
		} else if err != nil {
			return err
		}
	}
	return nil
}

func allocateIP(ctx context.Context, q querier, set model.Settings) (netip.Addr, error) {
	devices, err := queryDevices(ctx, q, "")
	if err != nil {
		return netip.Addr{}, err
	}
	used := map[netip.Addr]bool{}
	for _, d := range devices {
		used[d.IP] = true
	}
	return set.AllocateIP(used)
}

func listDevices(ctx context.Context, q querier) ([]model.Device, error) {
	return queryDevices(ctx, q, "")
}

// queryDevices loads devices matching where (with args), plus their profile
// IDs and custom rules.
func queryDevices(ctx context.Context, q querier, where string, args ...any) ([]model.Device, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT id, name, public_key, ip, enabled, client_allowed_ips, created_at, updated_at
		FROM devices `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []model.Device
	byID := map[int64]*model.Device{}
	for rows.Next() {
		var (
			d                   model.Device
			ip, allowed, cr, up string
		)
		if err := rows.Scan(&d.ID, &d.Name, &d.PublicKey, &ip, &d.Enabled, &allowed, &cr, &up); err != nil {
			return nil, err
		}
		if d.IP, err = netip.ParseAddr(ip); err != nil {
			return nil, err
		}
		if d.ClientAllowedIPs, err = splitList(allowed, netip.ParsePrefix); err != nil {
			return nil, err
		}
		if d.CreatedAt, err = parseTime(cr); err != nil {
			return nil, err
		}
		if d.UpdatedAt, err = parseTime(up); err != nil {
			return nil, err
		}
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range devices {
		byID[devices[i].ID] = &devices[i]
	}

	links, err := q.QueryContext(ctx, "SELECT device_id, profile_id FROM device_profiles ORDER BY profile_id")
	if err != nil {
		return nil, err
	}
	defer links.Close()
	for links.Next() {
		var did, pid int64
		if err := links.Scan(&did, &pid); err != nil {
			return nil, err
		}
		if d := byID[did]; d != nil {
			d.ProfileIDs = append(d.ProfileIDs, pid)
		}
	}
	if err := links.Err(); err != nil {
		return nil, err
	}

	err = queryRules(ctx, q, "WHERE device_id IS NOT NULL", func(owner int64, r model.Rule) {
		if d := byID[owner]; d != nil {
			d.Rules = append(d.Rules, r)
		}
	})
	if err != nil {
		return nil, err
	}

	slices.SortFunc(devices, func(a, b model.Device) int { return a.IP.Compare(b.IP) })
	return devices, nil
}

func joinPrefixes(ps []netip.Prefix) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return strings.Join(s, ",")
}
