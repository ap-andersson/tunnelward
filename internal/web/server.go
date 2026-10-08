// Package web is the admin UI: server-rendered HTML with htmx for small
// in-page updates. Every page works without JavaScript.
package web

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"path"
	"strconv"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ap-andersson/tunnelward/internal/auth"
	"github.com/ap-andersson/tunnelward/internal/store"
	"github.com/ap-andersson/tunnelward/internal/wg"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

const sessionCookie = "tw_session"

// Server serves the admin UI.
type Server struct {
	store           *store.Store
	apply           func(context.Context) error
	statuses        func() (map[wgtypes.Key]wg.PeerStatus, error)
	serverPublicKey wgtypes.Key
	listenPort      int
	secureCookies   bool

	sessions *auth.Sessions
	limiter  *auth.LoginLimiter
	pages    map[string]*template.Template
	setUp    atomic.Bool // admin password exists
}

// Config is what New needs.
type Config struct {
	Store           *store.Store
	Apply           func(context.Context) error // reconcile after a change
	Statuses        func() (map[wgtypes.Key]wg.PeerStatus, error)
	ServerPublicKey wgtypes.Key
	ListenPort      int  // shown in Settings
	SecureCookies   bool // set when served over HTTPS (e.g. behind a proxy)
}

// New parses the templates and returns a Server.
func New(ctx context.Context, cfg Config) (*Server, error) {
	s := &Server{
		store:           cfg.Store,
		apply:           cfg.Apply,
		statuses:        cfg.Statuses,
		serverPublicKey: cfg.ServerPublicKey,
		listenPort:      cfg.ListenPort,
		secureCookies:   cfg.SecureCookies,
		sessions:        auth.NewSessions(12 * time.Hour),
		limiter:         auth.NewLoginLimiter(5, 5*time.Minute),
		pages:           map[string]*template.Template{},
	}
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	switch _, err := cfg.Store.AdminPasswordHash(ctx); {
	case err == nil:
		s.setUp.Store(true)
	case !errors.Is(err, store.ErrNotFound):
		return nil, err
	}
	return s, nil
}

// NeedsSetup reports whether the admin password still has to be chosen.
func (s *Server) NeedsSetup() bool { return !s.setUp.Load() }

func (s *Server) parseTemplates() error {
	shared := []string{"templates/layout.html", "templates/partials.html"}
	pages, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return err
	}
	for _, p := range pages {
		name := path.Base(p)
		if name == "layout.html" || name == "partials.html" {
			continue
		}
		t, err := template.New(name).Funcs(funcs).ParseFS(templateFS, append(shared, p)...)
		if err != nil {
			return err
		}
		s.pages[name] = t
	}
	return nil
}

// Handler returns the UI's HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))

	mux.HandleFunc("GET /setup", s.setupForm)
	mux.HandleFunc("POST /setup", s.setup)
	mux.HandleFunc("GET /login", s.loginForm)
	mux.HandleFunc("POST /login", s.login)

	authed := http.NewServeMux()
	authed.HandleFunc("POST /logout", s.logout)
	authed.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/devices", http.StatusSeeOther)
	})

	authed.HandleFunc("GET /devices", s.listDevices)
	authed.HandleFunc("GET /devices/new", s.newDeviceForm)
	authed.HandleFunc("POST /devices", s.createDevice)
	authed.HandleFunc("GET /devices/{id}", s.showDevice)
	authed.HandleFunc("POST /devices/{id}", s.updateDevice)
	authed.HandleFunc("GET /devices/{id}/delete", s.confirmDeleteDevice)
	authed.HandleFunc("POST /devices/{id}/delete", s.deleteDevice)
	authed.HandleFunc("GET /devices/{id}/regenerate", s.confirmRegenerate)
	authed.HandleFunc("POST /devices/{id}/regenerate", s.regenerate)
	authed.HandleFunc("POST /devices/{id}/rules", s.addDeviceRule)
	authed.HandleFunc("POST /devices/{id}/rules/{rule}/delete", s.deleteDeviceRule)

	authed.HandleFunc("GET /profiles", s.listProfiles)
	authed.HandleFunc("GET /profiles/new", s.newProfileForm)
	authed.HandleFunc("POST /profiles", s.createProfile)
	authed.HandleFunc("GET /profiles/{id}", s.showProfile)
	authed.HandleFunc("POST /profiles/{id}", s.updateProfile)
	authed.HandleFunc("GET /profiles/{id}/delete", s.confirmDeleteProfile)
	authed.HandleFunc("POST /profiles/{id}/delete", s.deleteProfile)
	authed.HandleFunc("POST /profiles/{id}/rules", s.addProfileRule)
	authed.HandleFunc("POST /profiles/{id}/rules/{rule}/delete", s.deleteProfileRule)

	authed.HandleFunc("GET /settings", s.showSettings)
	authed.HandleFunc("POST /settings", s.updateSettings)
	authed.HandleFunc("POST /settings/password", s.changePassword)

	mux.Handle("/", s.requireLogin(authed))

	// CrossOriginProtection rejects cross-site POSTs (CSRF) using the
	// browser's Sec-Fetch-Site / Origin headers.
	return securityHeaders(http.NewCrossOriginProtection().Handler(mux))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// requireLogin sends visitors to /setup until a password exists, and to
// /login without a valid session.
func (s *Server) requireLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.NeedsSetup() {
			s.redirect(w, r, "/setup")
			return
		}
		if !s.loggedIn(r) {
			s.redirect(w, r, "/login")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) loggedIn(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	return err == nil && s.sessions.Valid(c.Value)
}

func (s *Server) startSession(w http.ResponseWriter) error {
	token, err := s.sessions.Create()
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   int((12 * time.Hour).Seconds()),
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteStrictMode,
	})
	return nil
}

// page is the data every template gets.
type page struct {
	Title    string
	LoggedIn bool
	Flash    string
	Error    string
	Data     any
}

var flashes = map[string]string{
	"saved":            "Saved.",
	"deleted":          "Deleted.",
	"password-changed": "Password changed. Any other sessions were logged out.",
	"apply-failed":     "Saved, but applying the change to WireGuard or the firewall failed. Check the logs.",
}

// render writes a full page. The flash message is picked by the "msg" query
// parameter from a fixed list, so no user text is ever reflected.
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name string, p page) {
	p.LoggedIn = s.loggedIn(r)
	if p.Flash == "" {
		p.Flash = flashes[r.URL.Query().Get("msg")]
	}
	s.execute(w, status, name, "layout", p)
}

// renderPartial writes one named template (for htmx swaps).
func (s *Server) renderPartial(w http.ResponseWriter, page, block string, data any) {
	s.execute(w, http.StatusOK, page, block, data)
}

func (s *Server) execute(w http.ResponseWriter, status int, name, block string, data any) {
	t, ok := s.pages[name]
	if !ok {
		panic("web: unknown page " + name)
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, block, data); err != nil {
		slog.Error("render template", "page", name, "block", block, "err", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

// redirect works for both normal and htmx requests.
func (s *Server) redirect(w http.ResponseWriter, r *http.Request, url string) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", url)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, url, http.StatusSeeOther)
}

// applyAndRedirect applies the configuration after a change and redirects
// with a "saved"-style message, or a warning if applying failed.
func (s *Server) applyAndRedirect(w http.ResponseWriter, r *http.Request, url, msg string) {
	if !s.applyChanges(r.Context()) {
		msg = "apply-failed"
	}
	s.redirect(w, r, fmt.Sprintf("%s?msg=%s", url, msg))
}

func (s *Server) applyChanges(ctx context.Context) bool {
	if err := s.apply(ctx); err != nil {
		slog.Error("applying configuration failed", "err", err)
		return false
	}
	return true
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusNotFound, "message.html", page{Title: "Not found", Error: "That page doesn't exist (any more)."})
}

func (s *Server) serverError(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
	s.render(w, r, http.StatusInternalServerError, "message.html", page{Title: "Error", Error: "Something went wrong. Check the logs."})
}

// storeError renders ErrNotFound as 404 and anything else as 500.
func (s *Server) storeError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrNotFound) {
		s.notFound(w, r)
		return
	}
	s.serverError(w, r, err)
}

// pathID parses a numeric path value.
func pathID(r *http.Request, name string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	return id, err == nil && id > 0
}

// clientIP is used for login rate limiting. Behind a reverse proxy all
// clients share the proxy's address, which makes the limit global; that is
// acceptable for a single-admin app.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
