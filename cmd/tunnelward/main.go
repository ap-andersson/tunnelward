// Command tunnelward runs the Tunnelward WireGuard server manager.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ap-andersson/tunnelward/internal/reconcile"
	"github.com/ap-andersson/tunnelward/internal/store"
	"github.com/ap-andersson/tunnelward/internal/web"
	"github.com/ap-andersson/tunnelward/internal/wg"
)

// config comes from the environment. Everything else is stored in the
// database and edited in the UI.
type config struct {
	DataDir   string // TW_DATA_DIR: database and server key
	Interface string // TW_INTERFACE: WireGuard interface name
	WGPort    int    // TW_WG_PORT: UDP port WireGuard listens on
	HTTPAddr  string // TW_HTTP_ADDR: admin UI listen address
	// TW_COOKIE_SECURE: set when the UI is served over HTTPS (e.g. behind a
	// reverse proxy), so the session cookie is only sent over HTTPS.
	CookieSecure bool
}

func loadConfig() (config, error) {
	cfg := config{
		DataDir:   env("TW_DATA_DIR", "/data"),
		Interface: env("TW_INTERFACE", "wg0"),
		HTTPAddr:  env("TW_HTTP_ADDR", ":8080"),
	}
	secure, err := strconv.ParseBool(env("TW_COOKIE_SECURE", "false"))
	if err != nil {
		return cfg, fmt.Errorf("TW_COOKIE_SECURE: %w", err)
	}
	cfg.CookieSecure = secure
	port, err := strconv.Atoi(env("TW_WG_PORT", "51820"))
	if err != nil || port < 1 || port > 65535 {
		return cfg, fmt.Errorf("TW_WG_PORT: invalid port %q", os.Getenv("TW_WG_PORT"))
	}
	cfg.WGPort = port
	return cfg, nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if err := checkDataDir(cfg.DataDir); err != nil {
		return err
	}
	ensureForwarding()

	st, err := store.Open(ctx, filepath.Join(cfg.DataDir, "tunnelward.db"))
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer st.Close()

	key, err := wg.LoadOrCreatePrivateKey(filepath.Join(cfg.DataDir, "server.key"))
	if err != nil {
		return fmt.Errorf("server key: %w", err)
	}
	slog.Info("starting", "interface", cfg.Interface, "port", cfg.WGPort, "public_key", key.PublicKey().String())

	r := &reconcile.Reconciler{Store: st, Interface: cfg.Interface, ListenPort: cfg.WGPort, PrivateKey: key}
	if err := r.Reconcile(ctx); err != nil {
		// Keep going: the admin UI is needed to fix whatever is wrong, and
		// nothing is allowed through until applying succeeds.
		slog.Warn("starting the admin UI anyway; WireGuard stays down until the configuration applies")
	}
	go r.Run(ctx, 30*time.Second, 5*time.Minute)

	ui, err := web.New(ctx, web.Config{
		Store:           st,
		Apply:           r.Reconcile,
		Statuses:        func() (map[wgtypes.Key]wg.PeerStatus, error) { return wg.PeerStatuses(cfg.Interface) },
		SyncError:       r.Err,
		ServerPublicKey: key.PublicKey(),
		ListenPort:      cfg.WGPort,
		SecureCookies:   cfg.CookieSecure,
	})
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           ui.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	slog.Info("admin UI listening", "addr", cfg.HTTPAddr)
	if ui.NeedsSetup() {
		slog.Warn("no admin password yet: open the admin UI now to set it. Until then, anyone who can reach the UI can set it.")
	}

	select {
	case err := <-errc:
		return fmt.Errorf("admin UI: %w", err)
	case <-ctx.Done():
	}
	slog.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// checkDataDir creates the data directory if needed and makes sure it is
// writable, with a hint for the common Docker bind-mount mistake.
func checkDataDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("data directory %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, ".write-test-*")
	if err != nil {
		return fmt.Errorf("data directory %s is not writable: %w. "+
			"The container runs without the capability to write to folders it doesn't own: "+
			"let Docker create the folder, or make it owned by root (sudo chown -R root:root <folder>)", dir, err)
	}
	f.Close()
	return os.Remove(f.Name())
}

// ensureForwarding turns on IPv4 forwarding if it is off. In Docker this
// usually fails (read-only /proc/sys); the compose file sets it instead.
func ensureForwarding() {
	const path = "/proc/sys/net/ipv4/ip_forward"
	b, err := os.ReadFile(path)
	if err != nil || strings.TrimSpace(string(b)) == "1" {
		return
	}
	if err := os.WriteFile(path, []byte("1"), 0o644); err != nil {
		slog.Warn("IP forwarding is disabled, so devices can't reach anything through the server. "+
			"With Docker, add `sysctls: [net.ipv4.ip_forward=1]` to the service.", "err", err)
		return
	}
	slog.Info("enabled IP forwarding")
}
