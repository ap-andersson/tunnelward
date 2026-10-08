// Command tunnelward runs the Tunnelward WireGuard server manager.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/ap-andersson/tunnelward/internal/reconcile"
	"github.com/ap-andersson/tunnelward/internal/store"
	"github.com/ap-andersson/tunnelward/internal/wg"
)

// config comes from the environment. Everything else is stored in the
// database and edited in the UI.
type config struct {
	DataDir   string // TW_DATA_DIR: database and server key
	Interface string // TW_INTERFACE: WireGuard interface name
	WGPort    int    // TW_WG_PORT: UDP port WireGuard listens on
}

func loadConfig() (config, error) {
	cfg := config{
		DataDir:   env("TW_DATA_DIR", "/data"),
		Interface: env("TW_INTERFACE", "wg0"),
	}
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
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
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
		return err
	}

	<-ctx.Done()
	slog.Info("shutting down")
	return nil
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
