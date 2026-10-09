package reconcile

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ap-andersson/tunnelward/internal/firewall"
	"github.com/ap-andersson/tunnelward/internal/model"
	"github.com/ap-andersson/tunnelward/internal/store"
	"github.com/ap-andersson/tunnelward/internal/wg"
)

const childEnv = "TUNNELWARD_INTEGRATION_CHILD"

// TestIntegration sends real traffic through a real WireGuard server
// configured by Reconcile, and checks what each device can and cannot reach.
//
// It re-runs itself in a new user + network namespace, so it needs no root
// and never touches the host's network. Topology (all namespaces):
//
//	client1 (10.8.0.2) ─┐                   ┌─ lan      192.168.77.10 (:80, :8096)
//	                    ├─ server (wg0) ────┤
//	client2 (10.8.0.3) ─┘   10.8.0.1 :9000  └─ internet 203.0.113.10 (:80)
func TestIntegration(t *testing.T) {
	if os.Getenv(childEnv) == "" {
		runInNamespace(t)
		return
	}
	integration(t)
}

func runInNamespace(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestIntegration$", "-test.v")
	cmd.Env = append(os.Environ(), childEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	switch {
	case err != nil && !errors.As(err, &exitErr):
		t.Skipf("cannot create user/network namespace: %v", err)
	case err != nil:
		t.Fatalf("integration test failed:\n%s", out)
	case bytes.Contains(out, []byte("--- SKIP")):
		t.Skipf("skipped in namespace:\n%s", out)
	}
	t.Logf("%s", out)
}

func integration(t *testing.T) {
	ctx := t.Context()

	server, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	upLoopback(t, server)
	lan, inet, client1, client2 := newNS(t), newNS(t), newNS(t), newNS(t)
	veth(t, server, "lan0", "192.168.77.1/24", lan, "192.168.77.10/24")
	veth(t, server, "inet0", "203.0.113.1/24", inet, "203.0.113.10/24")
	veth(t, server, "up1", "198.51.100.1/30", client1, "198.51.100.2/30")
	veth(t, server, "up2", "198.51.100.5/30", client2, "198.51.100.6/30")
	addRoute(t, lan, "10.8.0.0/24", "192.168.77.1") // only for the "LAN initiates" check
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Server: database + Reconcile, exactly like the real program.
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "tunnelward.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	serverKey, _ := wgtypes.GeneratePrivateKey()
	r := &Reconciler{Store: st, Interface: "wg0", ListenPort: 51820, PrivateKey: serverKey}

	key1, _ := wgtypes.GeneratePrivateKey()
	key2, _ := wgtypes.GeneratePrivateKey()
	kid := model.Device{Name: "kid", PublicKey: key1.PublicKey().String(), Enabled: true, ProfileIDs: []int64{1}}
	laptop := model.Device{Name: "laptop", PublicKey: key2.PublicKey().String(), Enabled: true, ProfileIDs: []int64{1}}
	for _, d := range []*model.Device{&kid, &laptop} {
		if err := st.CreateDevice(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	for _, rule := range []model.Rule{
		{Destination: "192.168.77.10", Protocol: model.ProtoTCP, PortFrom: 8096},
		{Destination: "192.168.77.10", Protocol: model.ProtoTCP, PortFrom: 7},
		{Destination: "10.8.0.1", Protocol: model.ProtoTCP, PortFrom: 9000},
	} {
		if err := st.AddDeviceRule(ctx, laptop.ID, &rule); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if err := r.Reconcile(ctx); err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}

	serverPub := serverKey.PublicKey()
	setupClient(t, client1, key1, kid.IP, serverPub, "198.51.100.1:51820")
	setupClient(t, client2, key2, laptop.IP, serverPub, "198.51.100.5:51820")

	// Every address checked below has a listener, so a blocked connection
	// times out because of the firewall, not because nothing is there.
	serve(t, lan, "192.168.77.10:80")
	serve(t, lan, "192.168.77.10:8096")
	serve(t, inet, "203.0.113.10:80")
	serve(t, server, "0.0.0.0:9000") // stands in for the admin UI
	serve(t, client2, "10.8.0.3:80")
	serveEcho(t, lan, "192.168.77.10:7")
	serveEcho(t, inet, "203.0.113.10:7")

	type check struct {
		name    string
		from    netns.NsHandle
		addr    string
		allowed bool
	}
	run := func(checks []check) {
		t.Helper()
		for _, c := range checks {
			err := dial(t, c.from, c.addr, c.allowed)
			switch {
			case c.allowed && err != nil:
				t.Errorf("%s: expected allowed, got %v", c.name, err)
			case !c.allowed && err == nil:
				t.Errorf("%s: expected blocked, but connected", c.name)
			case !c.allowed && !isTimeout(err):
				t.Errorf("%s: expected a silent drop (timeout), got %v", c.name, err)
			}
		}
	}

	run([]check{
		// Allowed checks first: they also complete the WireGuard handshakes.
		{"internet-only device reaches the internet", client1, "203.0.113.10:80", true},
		{"laptop reaches its custom LAN port", client2, "192.168.77.10:8096", true},
		{"laptop reaches the internet", client2, "203.0.113.10:80", true},
		{"laptop reaches the server port it is allowed", client2, "10.8.0.1:9000", true},

		{"internet-only device can't reach a LAN host", client1, "192.168.77.10:80", false},
		{"internet-only device can't reach the laptop's LAN port", client1, "192.168.77.10:8096", false},
		{"internet-only device can't reach the server's tunnel IP", client1, "10.8.0.1:9000", false},
		{"internet-only device can't reach the server's LAN IP", client1, "192.168.77.1:9000", false},
		{"internet rule doesn't open the server's public IP", client1, "203.0.113.1:9000", false},
		{"no peer-to-peer without a rule", client1, "10.8.0.3:80", false},
		{"laptop can't reach other LAN ports", client2, "192.168.77.10:80", false},
		{"LAN can't open connections into the tunnel", lan, "10.8.0.3:80", false},
	})

	// Connections that stay open across the changes below.
	lanConn := openEcho(t, client2, "192.168.77.10:7")
	inetConn := openEcho(t, client2, "203.0.113.10:7")

	// Changes: disable one device, take a profile away from the other.
	handshakeBefore := lastHandshake(t, laptop.PublicKey)
	kid.Enabled = false
	if err := st.UpdateDevice(ctx, &kid); err != nil {
		t.Fatal(err)
	}
	laptop.ProfileIDs = nil
	if err := st.UpdateDevice(ctx, &laptop); err != nil {
		t.Fatal(err)
	}
	if err := r.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile after changes: %v", err)
	}
	if keys, _ := wg.PeerKeys("wg0"); len(keys) != 1 || keys[0].String() != laptop.PublicKey {
		t.Errorf("peers after disabling kid = %v, want only the laptop", keys)
	}
	if after := lastHandshake(t, laptop.PublicKey); !after.Equal(handshakeBefore) {
		t.Errorf("laptop's session was reset by an unrelated change (handshake %v -> %v)", handshakeBefore, after)
	}

	if err := lanConn.echo(); err != nil {
		t.Errorf("open connection the laptop is still allowed was cut: %v", err)
	}
	if err := inetConn.echo(); err == nil {
		t.Error("open internet connection kept working after the laptop lost its internet profile")
	}

	run([]check{
		{"laptop still reaches its custom LAN port", client2, "192.168.77.10:8096", true},
		{"disabled device is cut off", client1, "203.0.113.10:80", false},
		{"laptop lost internet with its profile", client2, "203.0.113.10:80", false},
	})

	// When the firewall can't be updated, deleted devices still lose their
	// peer, the error is reported, and the next successful attempt clears it.
	if err := st.DeleteDevice(ctx, laptop.ID); err != nil {
		t.Fatal(err)
	}
	firewall.NFT = "false" // a command that always fails
	if err := r.Reconcile(ctx); err == nil {
		t.Fatal("Reconcile succeeded although nft failed")
	}
	if r.Err() == nil {
		t.Error("Err() is nil after a failed attempt")
	}
	if keys, _ := wg.PeerKeys("wg0"); len(keys) != 0 {
		t.Errorf("deleted device's peer kept after a firewall error: %v", keys)
	}
	firewall.NFT = "nft"
	if err := r.Reconcile(ctx); err != nil || r.Err() != nil {
		t.Errorf("Reconcile after nft works again: %v (Err: %v)", err, r.Err())
	}
}

// newNS creates a network namespace with loopback up.
func newNS(t *testing.T) netns.NsHandle {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer orig.Close()
	ns, err := netns.New() // also switches this thread into it
	if err != nil {
		t.Fatal(err)
	}
	if err := netns.Set(orig); err != nil {
		panic(err) // thread stays locked and is discarded
	}
	t.Cleanup(func() { ns.Close() })
	upLoopback(t, ns)
	return ns
}

func handleAt(t *testing.T, ns netns.NsHandle) *netlink.Handle {
	t.Helper()
	h, err := netlink.NewHandleAt(ns)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	return h
}

func upLoopback(t *testing.T, ns netns.NsHandle) {
	t.Helper()
	h := handleAt(t, ns)
	lo, err := h.LinkByName("lo")
	if err == nil {
		err = h.LinkSetUp(lo)
	}
	if err != nil {
		t.Fatal(err)
	}
}

// veth connects namespace a (interface name, address) with namespace b,
// where the other end is called eth0.
func veth(t *testing.T, a netns.NsHandle, name, addrA string, b netns.NsHandle, addrB string) {
	t.Helper()
	ha, hb := handleAt(t, a), handleAt(t, b)
	attrs := netlink.NewLinkAttrs()
	attrs.Name = name
	err := ha.LinkAdd(&netlink.Veth{LinkAttrs: attrs, PeerName: "eth0", PeerNamespace: netlink.NsFd(b)})
	if err != nil {
		t.Fatalf("create veth %s: %v", name, err)
	}
	for _, side := range []struct {
		h    *netlink.Handle
		name string
		addr string
	}{{ha, name, addrA}, {hb, "eth0", addrB}} {
		link, err := side.h.LinkByName(side.name)
		if err != nil {
			t.Fatal(err)
		}
		addr, _ := netlink.ParseAddr(side.addr)
		if err := side.h.AddrAdd(link, addr); err != nil {
			t.Fatal(err)
		}
		if err := side.h.LinkSetUp(link); err != nil {
			t.Fatal(err)
		}
	}
}

func addRoute(t *testing.T, ns netns.NsHandle, dst, gw string) {
	t.Helper()
	_, dstNet, _ := net.ParseCIDR(dst)
	if err := handleAt(t, ns).RouteAdd(&netlink.Route{Dst: dstNet, Gw: net.ParseIP(gw)}); err != nil {
		t.Fatal(err)
	}
}

// setupClient configures a WireGuard client in ns, routing the test
// networks through the tunnel (but not the underlay to the server).
func setupClient(t *testing.T, ns netns.NsHandle, key wgtypes.Key, ip netip.Addr, server wgtypes.Key, endpoint string) {
	t.Helper()
	err := inNS(ns, func() error {
		attrs := netlink.NewLinkAttrs()
		attrs.Name = "wg0"
		if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: attrs}); err != nil {
			return err
		}
		link, err := netlink.LinkByName("wg0")
		if err != nil {
			return err
		}
		addr, _ := netlink.ParseAddr(ip.String() + "/24")
		if err := netlink.AddrAdd(link, addr); err != nil {
			return err
		}
		ep, err := net.ResolveUDPAddr("udp", endpoint)
		if err != nil {
			return err
		}
		c, err := wgctrl.New()
		if err != nil {
			return err
		}
		defer c.Close()
		_, all, _ := net.ParseCIDR("0.0.0.0/0")
		err = c.ConfigureDevice("wg0", wgtypes.Config{
			PrivateKey: &key,
			Peers:      []wgtypes.PeerConfig{{PublicKey: server, Endpoint: ep, AllowedIPs: []net.IPNet{*all}}},
		})
		if err != nil {
			return err
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return err
		}
		for _, dst := range []string{"192.168.77.0/24", "203.0.113.0/24"} {
			_, n, _ := net.ParseCIDR(dst)
			if err := netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: n}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("set up client %s: %v", ip, err)
	}
}

// serve answers every TCP connection on addr (in ns) with "ok".
func serve(t *testing.T, ns netns.NsHandle, addr string) {
	t.Helper()
	var l net.Listener
	err := inNS(ns, func() error {
		var err error
		l, err = net.Listen("tcp4", addr)
		return err
	})
	if err != nil {
		t.Fatalf("listen %s: %v", addr, err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("ok"))
			c.Close()
		}
	}()
}

// serveEcho echoes every line back, on connections that stay open.
func serveEcho(t *testing.T, ns netns.NsHandle, addr string) {
	t.Helper()
	var l net.Listener
	err := inNS(ns, func() error {
		var err error
		l, err = net.Listen("tcp4", addr)
		return err
	})
	if err != nil {
		t.Fatalf("listen %s: %v", addr, err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				s := bufio.NewScanner(c)
				for s.Scan() {
					c.Write([]byte(s.Text() + "\n"))
				}
			}()
		}
	}()
}

// echoConn is an open connection to an echo server.
type echoConn struct {
	c net.Conn
	r *bufio.Reader
}

// openEcho connects from ns and checks one round trip.
func openEcho(t *testing.T, ns netns.NsHandle, addr string) *echoConn {
	t.Helper()
	var c net.Conn
	err := inNS(ns, func() error {
		var err error
		c, err = net.DialTimeout("tcp4", addr, 5*time.Second)
		return err
	})
	if err != nil {
		t.Fatalf("connect to %s: %v", addr, err)
	}
	t.Cleanup(func() { c.Close() })
	e := &echoConn{c: c, r: bufio.NewReader(c)}
	if err := e.echo(); err != nil {
		t.Fatalf("echo via %s: %v", addr, err)
	}
	return e
}

// echo sends a line and waits briefly for it to come back.
func (e *echoConn) echo() error {
	e.c.SetDeadline(time.Now().Add(time.Second))
	if _, err := e.c.Write([]byte("ping\n")); err != nil {
		return err
	}
	_, err := e.r.ReadString('\n')
	return err
}

// dial connects to addr from ns and expects "ok". Expected-blocked
// connections use a short timeout, since a drop only shows as a timeout.
func dial(t *testing.T, ns netns.NsHandle, addr string, expectAllowed bool) error {
	t.Helper()
	timeout := 700 * time.Millisecond
	if expectAllowed {
		timeout = 5 * time.Second // may include the WireGuard handshake
	}
	var c net.Conn
	err := inNS(ns, func() error {
		var err error
		c, err = net.DialTimeout("tcp4", addr, timeout)
		return err
	})
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	b, err := io.ReadAll(c)
	if err != nil {
		return err
	}
	if string(b) != "ok" {
		return errors.New("unexpected response " + string(b))
	}
	return nil
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// lastHandshake returns the server's last handshake time with a peer.
func lastHandshake(t *testing.T, pub string) time.Time {
	t.Helper()
	c, err := wgctrl.New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	dev, err := c.Device("wg0")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range dev.Peers {
		if p.PublicKey.String() == pub {
			if p.LastHandshakeTime.IsZero() {
				t.Fatalf("peer %s never completed a handshake", pub)
			}
			return p.LastHandshakeTime
		}
	}
	t.Fatalf("peer %s not found", pub)
	return time.Time{}
}

// inNS runs fn on a thread switched into ns.
func inNS(ns netns.NsHandle, fn func() error) error {
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		return err
	}
	defer orig.Close()
	if err := netns.Set(ns); err != nil {
		runtime.UnlockOSThread()
		return err
	}
	fnErr := fn()
	if err := netns.Set(orig); err != nil {
		panic(err) // thread stays locked and is discarded
	}
	runtime.UnlockOSThread()
	return fnErr
}
