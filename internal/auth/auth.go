// Package auth provides password hashing, in-memory sessions and a login
// rate limiter for the single admin account.
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

// MinPasswordLength is the minimum admin password length in characters.
const MinPasswordLength = 10

// bcrypt ignores everything after 72 bytes, so longer passwords are refused
// rather than silently truncated.
const maxPasswordBytes = 72

// ValidatePassword checks a new password.
func ValidatePassword(pw string) error {
	if utf8.RuneCountInString(pw) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	if len(pw) > maxPasswordBytes {
		return fmt.Errorf("password must be at most %d bytes", maxPasswordBytes)
	}
	return nil
}

// HashPassword validates and hashes a new password.
func HashPassword(pw string) (string, error) {
	if err := ValidatePassword(pw); err != nil {
		return "", err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	return string(h), err
}

// CheckPassword reports whether pw matches hash.
func CheckPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// Sessions keeps logged-in sessions in memory. A restart logs everyone out.
type Sessions struct {
	ttl time.Duration
	mu  sync.Mutex
	m   map[string]time.Time // token -> expiry
}

// NewSessions returns a session store whose sessions last ttl.
func NewSessions(ttl time.Duration) *Sessions {
	return &Sessions{ttl: ttl, m: map[string]time.Time{}}
}

// Create starts a session and returns its token.
func (s *Sessions) Create() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for t, exp := range s.m {
		if now.After(exp) {
			delete(s.m, t)
		}
	}
	s.m[token] = now.Add(s.ttl)
	return token, nil
}

// Valid reports whether token is a live session.
func (s *Sessions) Valid(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.m[token]
	return ok && time.Now().Before(exp)
}

// Delete ends one session.
func (s *Sessions) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, token)
}

// DeleteAll ends every session.
func (s *Sessions) DeleteAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.m)
}

// ErrTooManyAttempts is returned by LoginLimiter.Allow while a client is
// locked out.
var ErrTooManyAttempts = errors.New("too many failed login attempts, try again later")

// LoginLimiter allows a limited number of failed logins per client within a
// time window.
type LoginLimiter struct {
	Max    int
	Window time.Duration

	mu       sync.Mutex
	failures map[string][]time.Time
	now      func() time.Time
}

// NewLoginLimiter allows max failures per client within window.
func NewLoginLimiter(max int, window time.Duration) *LoginLimiter {
	return &LoginLimiter{Max: max, Window: window, failures: map[string][]time.Time{}, now: time.Now}
}

// Allow returns ErrTooManyAttempts if client has used up its failures.
func (l *LoginLimiter) Allow(client string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.recent(client)) >= l.Max {
		return ErrTooManyAttempts
	}
	return nil
}

// Fail records a failed login.
func (l *LoginLimiter) Fail(client string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failures[client] = append(l.recent(client), l.now())
}

// Reset forgets a client's failures after a successful login.
func (l *LoginLimiter) Reset(client string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, client)
}

// recent drops expired failures for client and returns the rest.
func (l *LoginLimiter) recent(client string) []time.Time {
	cutoff := l.now().Add(-l.Window)
	var keep []time.Time
	for _, t := range l.failures[client] {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	if keep == nil {
		delete(l.failures, client)
	} else {
		l.failures[client] = keep
	}
	return keep
}
