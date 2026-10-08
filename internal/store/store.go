// Package store persists devices, profiles, rules and settings in SQLite.
//
// Every write validates its input with the model package first, so the
// database only ever holds normalized, valid values.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"slices"
	"strings"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

var (
	ErrNotFound = errors.New("not found")
	// ErrConflict is returned when a unique value (name, key, IP) is taken.
	ErrConflict = errors.New("already in use")
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store is the application's database.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the database at path and migrates it to
// the latest schema.
func Open(ctx context.Context, path string) (*Store, error) {
	q := url.Values{}
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "busy_timeout(5000)")
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	// One connection: writes are rare and this rules out SQLITE_BUSY between
	// our own connections.
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error {
	return s.db.Close()
}

// migrate applies migrations/NNNN_*.sql files newer than PRAGMA user_version.
func (s *Store) migrate(ctx context.Context) error {
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	slices.Sort(names)

	var current int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&current); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if current > len(names) {
		return fmt.Errorf("database schema version %d is newer than this build (%d)", current, len(names))
	}
	for i := current; i < len(names); i++ {
		script, err := migrations.ReadFile(names[i])
		if err != nil {
			return err
		}
		err = s.tx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, string(script)); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", i+1))
			return err
		})
		if err != nil {
			return fmt.Errorf("migration %s: %w", names[i], err)
		}
	}
	return nil
}

// querier is implemented by both *sql.DB and *sql.Tx.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// tx runs fn in a transaction, committing if it returns nil.
func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// mapErr turns driver errors into ErrNotFound / ErrConflict where possible.
func mapErr(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() {
		case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
			return fmt.Errorf("%w: %s", ErrConflict, uniqueColumn(se.Error()))
		case sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY:
			return ErrNotFound
		}
	}
	return err
}

// uniqueColumn extracts "name" from "... UNIQUE constraint failed: devices.name ...".
func uniqueColumn(msg string) string {
	_, after, ok := strings.Cut(msg, "constraint failed: ")
	if !ok {
		return "value"
	}
	col, _, _ := strings.Cut(after, " ")
	if _, c, ok := strings.Cut(col, "."); ok {
		col = c
	}
	return strings.ReplaceAll(col, "_", " ")
}

// checkAffected returns ErrNotFound if the statement changed no rows.
func checkAffected(res sql.Result, err error) error {
	if err != nil {
		return mapErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, s)
}
