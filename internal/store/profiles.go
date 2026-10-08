package store

import (
	"context"
	"database/sql"

	"github.com/ap-andersson/tunnelward/internal/model"
)

// ListProfiles returns all profiles with their rules, ordered by name.
func (s *Store) ListProfiles(ctx context.Context) ([]model.Profile, error) {
	return queryProfiles(ctx, s.db, "")
}

// Profile returns one profile with its rules.
func (s *Store) Profile(ctx context.Context, id int64) (model.Profile, error) {
	profiles, err := queryProfiles(ctx, s.db, "WHERE id = ?", id)
	if err != nil {
		return model.Profile{}, err
	}
	if len(profiles) == 0 {
		return model.Profile{}, ErrNotFound
	}
	return profiles[0], nil
}

// CreateProfile validates and inserts p, setting its ID. Rules are not saved
// here; add them with AddProfileRule.
func (s *Store) CreateProfile(ctx context.Context, p *model.Profile) error {
	if err := p.Validate(); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx,
		"INSERT INTO profiles (name, description) VALUES (?, ?)", p.Name, p.Description)
	if err != nil {
		return mapErr(err)
	}
	p.ID, err = res.LastInsertId()
	return err
}

// UpdateProfile saves p's name and description.
func (s *Store) UpdateProfile(ctx context.Context, p *model.Profile) error {
	if err := p.Validate(); err != nil {
		return err
	}
	return checkAffected(s.db.ExecContext(ctx,
		"UPDATE profiles SET name = ?, description = ? WHERE id = ?", p.Name, p.Description, p.ID))
}

// DeleteProfile deletes a profile and its rules, and unassigns it from all
// devices. This can only ever reduce what devices may access.
func (s *Store) DeleteProfile(ctx context.Context, id int64) error {
	return checkAffected(s.db.ExecContext(ctx, "DELETE FROM profiles WHERE id = ?", id))
}

// AddProfileRule normalizes r and adds it to a profile, setting r.ID.
func (s *Store) AddProfileRule(ctx context.Context, profileID int64, r *model.Rule) error {
	return s.addRule(ctx, "profile_id", profileID, r)
}

// AddDeviceRule normalizes r and adds it to a device as a custom rule,
// setting r.ID.
func (s *Store) AddDeviceRule(ctx context.Context, deviceID int64, r *model.Rule) error {
	return s.addRule(ctx, "device_id", deviceID, r)
}

// UpdateRule normalizes r and saves it. The rule keeps its owner.
func (s *Store) UpdateRule(ctx context.Context, r *model.Rule) error {
	if err := r.Normalize(); err != nil {
		return err
	}
	return checkAffected(s.db.ExecContext(ctx, `
		UPDATE rules SET destination = ?, protocol = ?, port_from = ?, port_to = ?, comment = ?
		WHERE id = ?`,
		r.Destination, r.Protocol, r.PortFrom, r.PortTo, r.Comment, r.ID))
}

// DeleteRule deletes a rule.
func (s *Store) DeleteRule(ctx context.Context, id int64) error {
	return checkAffected(s.db.ExecContext(ctx, "DELETE FROM rules WHERE id = ?", id))
}

// addRule inserts r owned by the given column ("profile_id" or "device_id").
func (s *Store) addRule(ctx context.Context, ownerColumn string, ownerID int64, r *model.Rule) error {
	if err := r.Normalize(); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO rules (`+ownerColumn+`, destination, protocol, port_from, port_to, comment)
		VALUES (?, ?, ?, ?, ?, ?)`,
		ownerID, r.Destination, r.Protocol, r.PortFrom, r.PortTo, r.Comment)
	if err != nil {
		return mapErr(err) // unknown owner -> ErrNotFound
	}
	r.ID, err = res.LastInsertId()
	return err
}

func queryProfiles(ctx context.Context, q querier, where string, args ...any) ([]model.Profile, error) {
	rows, err := q.QueryContext(ctx, "SELECT id, name, description FROM profiles "+where+" ORDER BY name", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var profiles []model.Profile
	for rows.Next() {
		var p model.Profile
		if err := rows.Scan(&p.ID, &p.Name, &p.Description); err != nil {
			return nil, err
		}
		profiles = append(profiles, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	byID := map[int64]*model.Profile{}
	for i := range profiles {
		byID[profiles[i].ID] = &profiles[i]
	}
	err = queryRules(ctx, q, "WHERE profile_id IS NOT NULL", func(owner int64, r model.Rule) {
		if p := byID[owner]; p != nil {
			p.Rules = append(p.Rules, r)
		}
	})
	return profiles, err
}

// queryRules calls fn for every rule matching where, in ID order, with the
// rule's owner (profile or device) ID.
func queryRules(ctx context.Context, q querier, where string, fn func(owner int64, r model.Rule)) error {
	rows, err := q.QueryContext(ctx, `
		SELECT coalesce(profile_id, device_id), id, destination, protocol, port_from, port_to, comment
		FROM rules `+where+` ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			owner int64
			r     model.Rule
		)
		if err := rows.Scan(&owner, &r.ID, &r.Destination, &r.Protocol, &r.PortFrom, &r.PortTo, &r.Comment); err != nil {
			return err
		}
		fn(owner, r)
	}
	return rows.Err()
}

// Snapshot is a consistent view of everything the firewall and WireGuard
// configuration are built from.
type Snapshot struct {
	Settings model.Settings
	Devices  []model.Device
	Profiles map[int64]model.Profile
}

// Snapshot reads settings, devices and profiles in one transaction.
func (s *Store) Snapshot(ctx context.Context) (Snapshot, error) {
	var snap Snapshot
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var err error
		if snap.Settings, err = getSettings(ctx, tx); err != nil {
			return err
		}
		if snap.Devices, err = listDevices(ctx, tx); err != nil {
			return err
		}
		profiles, err := queryProfiles(ctx, tx, "")
		if err != nil {
			return err
		}
		snap.Profiles = make(map[int64]model.Profile, len(profiles))
		for _, p := range profiles {
			snap.Profiles[p.ID] = p
		}
		return nil
	})
	return snap, err
}
