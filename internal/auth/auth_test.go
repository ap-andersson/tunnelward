package auth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPasswords(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Error("short password accepted")
	}
	if _, err := HashPassword(strings.Repeat("x", 73)); err == nil {
		t.Error("password over 72 bytes accepted")
	}
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, "correct horse battery") || CheckPassword(h, "wrong horse battery") {
		t.Error("CheckPassword gave the wrong answer")
	}
}

func TestSessions(t *testing.T) {
	s := NewSessions(time.Hour)
	a, _ := s.Create()
	b, _ := s.Create()
	if a == b || !s.Valid(a) || !s.Valid(b) || s.Valid("nope") || s.Valid("") {
		t.Fatal("unexpected session validity")
	}
	s.Delete(a)
	if s.Valid(a) || !s.Valid(b) {
		t.Error("Delete removed the wrong session")
	}
	s.DeleteAll()
	if s.Valid(b) {
		t.Error("DeleteAll left a session")
	}

	expired := NewSessions(-time.Second)
	c, _ := expired.Create()
	if expired.Valid(c) {
		t.Error("expired session is valid")
	}
}

func TestLoginLimiter(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewLoginLimiter(3, time.Minute)
	l.now = func() time.Time { return now }

	for range 3 {
		if err := l.Allow("a"); err != nil {
			t.Fatal(err)
		}
		l.Fail("a")
	}
	if err := l.Allow("a"); !errors.Is(err, ErrTooManyAttempts) {
		t.Errorf("after 3 failures: %v, want ErrTooManyAttempts", err)
	}
	if err := l.Allow("b"); err != nil {
		t.Errorf("other client blocked: %v", err)
	}

	now = now.Add(61 * time.Second)
	if err := l.Allow("a"); err != nil {
		t.Errorf("still blocked after the window: %v", err)
	}

	l.Fail("a")
	l.Reset("a")
	if len(l.failures) != 0 {
		t.Errorf("Reset left failures: %v", l.failures)
	}
}
