package web

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/ap-andersson/tunnelward/internal/auth"
	"github.com/ap-andersson/tunnelward/internal/store"
)

func (s *Server) setupForm(w http.ResponseWriter, r *http.Request) {
	if !s.NeedsSetup() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "setup.html", page{Title: "Set up"})
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	if !s.NeedsSetup() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	pw := r.PostFormValue("password")
	fail := func(msg string) {
		s.render(w, r, http.StatusUnprocessableEntity, "setup.html", page{Title: "Set up", Error: msg})
	}
	if pw != r.PostFormValue("confirm") {
		fail("The passwords don't match.")
		return
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		fail(capitalize(err.Error()) + ".")
		return
	}
	switch err := s.store.SetInitialAdminPassword(r.Context(), hash); {
	case errors.Is(err, store.ErrConflict):
		// Someone else completed setup first.
		s.setUp.Store(true)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	s.setUp.Store(true)
	slog.Info("admin password set up", "client", clientIP(r))
	if err := s.startSession(w); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	if s.NeedsSetup() {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "login.html", page{Title: "Log in"})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if s.NeedsSetup() {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	client := clientIP(r)
	if err := s.limiter.Allow(client); err != nil {
		s.render(w, r, http.StatusTooManyRequests, "login.html", page{Title: "Log in", Error: "Too many failed attempts. Try again in a few minutes."})
		return
	}
	hash, err := s.store.AdminPasswordHash(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !auth.CheckPassword(hash, r.PostFormValue("password")) {
		s.limiter.Fail(client)
		slog.Warn("failed login", "client", client)
		s.render(w, r, http.StatusUnauthorized, "login.html", page{Title: "Log in", Error: "Wrong password."})
		return
	}
	s.limiter.Reset(client)
	if err := s.startSession(w); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, "/devices", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.Delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.secureCookies, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	fail := func(msg string) {
		data, err := s.settingsData(ctx)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		s.render(w, r, http.StatusUnprocessableEntity, "settings.html", page{Title: "Settings", Error: msg, Data: data})
	}
	hash, err := s.store.AdminPasswordHash(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !auth.CheckPassword(hash, r.PostFormValue("current")) {
		fail("The current password is wrong.")
		return
	}
	pw := r.PostFormValue("password")
	if pw != r.PostFormValue("confirm") {
		fail("The new passwords don't match.")
		return
	}
	newHash, err := auth.HashPassword(pw)
	if err != nil {
		fail(capitalize(err.Error()) + ".")
		return
	}
	if err := s.store.UpdateAdminPassword(ctx, newHash); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.sessions.DeleteAll()
	if err := s.startSession(w); err != nil {
		s.serverError(w, r, err)
		return
	}
	slog.Info("admin password changed")
	http.Redirect(w, r, "/settings?msg=password-changed", http.StatusSeeOther)
}
