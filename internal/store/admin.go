package store

import (
	"context"
	"errors"
)

// AdminPasswordHash returns the admin password hash, or ErrNotFound if
// setup hasn't been completed.
func (s *Store) AdminPasswordHash(ctx context.Context) (string, error) {
	var hash string
	err := s.db.QueryRowContext(ctx, "SELECT password_hash FROM admin WHERE id = 1").Scan(&hash)
	return hash, mapErr(err)
}

// SetInitialAdminPassword stores the first admin password. It returns
// ErrConflict if a password already exists, so only one setup can succeed.
func (s *Store) SetInitialAdminPassword(ctx context.Context, hash string) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO admin (id, password_hash, updated_at) VALUES (1, ?, ?)", hash, now())
	if err = mapErr(err); errors.Is(err, ErrConflict) {
		return ErrConflict
	}
	return err
}

// UpdateAdminPassword replaces the admin password hash.
func (s *Store) UpdateAdminPassword(ctx context.Context, hash string) error {
	return checkAffected(s.db.ExecContext(ctx,
		"UPDATE admin SET password_hash = ?, updated_at = ? WHERE id = 1", hash, now()))
}
