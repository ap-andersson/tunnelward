package web

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ap-andersson/tunnelward/internal/model"
	"github.com/ap-andersson/tunnelward/internal/store"
)

const testPassword = "correct horse battery"

type testEnv struct {
	t       *testing.T
	store   *store.Store
	srv     *httptest.Server
	client  *http.Client
	applied atomic.Int32
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := &testEnv{t: t, store: st}
	key, _ := wgtypes.GeneratePrivateKey()
	ui, err := New(t.Context(), Config{
		Store:           st,
		Apply:           func(context.Context) error { e.applied.Add(1); return nil },
		ServerPublicKey: key.PublicKey(),
		ListenPort:      51820,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewServer(ui.Handler())
	t.Cleanup(e.srv.Close)
	jar, _ := cookiejar.New(nil)
	e.client = &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return e
}

func (e *testEnv) do(method, path string, form url.Values, header ...string) (*http.Response, string) {
	e.t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		e.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func (e *testEnv) get(path string) (*http.Response, string) { return e.do("GET", path, nil) }
func (e *testEnv) post(path string, form url.Values, header ...string) (*http.Response, string) {
	return e.do("POST", path, form, header...)
}

// setUp completes setup, which also logs the client in.
func (e *testEnv) setUp() {
	e.t.Helper()
	resp, body := e.post("/setup", url.Values{"password": {testPassword}, "confirm": {testPassword}})
	if resp.StatusCode != http.StatusSeeOther {
		e.t.Fatalf("setup: %d\n%s", resp.StatusCode, body)
	}
}

func (e *testEnv) setEndpoint() {
	e.t.Helper()
	set, _ := e.store.Settings(e.t.Context())
	set.EndpointHost = "vpn.example.com"
	if err := e.store.UpdateSettings(e.t.Context(), set); err != nil {
		e.t.Fatal(err)
	}
}

func wantStatus(t *testing.T, resp *http.Response, body string, status int) {
	t.Helper()
	if resp.StatusCode != status {
		t.Fatalf("%s %s: status %d, want %d\n%s", resp.Request.Method, resp.Request.URL.Path, resp.StatusCode, status, body)
	}
}

func wantRedirect(t *testing.T, resp *http.Response, body, location string) {
	t.Helper()
	wantStatus(t, resp, body, http.StatusSeeOther)
	if got := resp.Header.Get("Location"); got != location {
		t.Fatalf("redirect to %q, want %q", got, location)
	}
}

func TestSetupFlow(t *testing.T) {
	e := newEnv(t)

	resp, body := e.get("/devices")
	wantRedirect(t, resp, body, "/setup")
	resp, body = e.get("/login")
	wantRedirect(t, resp, body, "/setup")

	resp, body = e.post("/setup", url.Values{"password": {testPassword}, "confirm": {"something else"}})
	wantStatus(t, resp, body, http.StatusUnprocessableEntity)
	if !strings.Contains(body, "don&#39;t match") {
		t.Errorf("missing mismatch message:\n%s", body)
	}
	resp, body = e.post("/setup", url.Values{"password": {"short"}, "confirm": {"short"}})
	wantStatus(t, resp, body, http.StatusUnprocessableEntity)

	resp, body = e.post("/setup", url.Values{"password": {testPassword}, "confirm": {testPassword}})
	wantRedirect(t, resp, body, "/settings")
	resp, body = e.get("/settings")
	wantStatus(t, resp, body, http.StatusOK)

	// Setup is closed for good, also for a new visitor.
	e.client.Jar, _ = cookiejar.New(nil)
	resp, body = e.post("/setup", url.Values{"password": {"attacker password"}, "confirm": {"attacker password"}})
	wantRedirect(t, resp, body, "/login")
	resp, body = e.post("/login", url.Values{"password": {"attacker password"}})
	wantStatus(t, resp, body, http.StatusUnauthorized)
}

func TestLoginAndLogout(t *testing.T) {
	e := newEnv(t)
	e.setUp()
	e.client.Jar, _ = cookiejar.New(nil)

	resp, body := e.get("/devices")
	wantRedirect(t, resp, body, "/login")
	resp, body = e.post("/devices", url.Values{"name": {"x"}})
	wantRedirect(t, resp, body, "/login")

	resp, body = e.post("/login", url.Values{"password": {testPassword}})
	wantRedirect(t, resp, body, "/devices")
	resp, body = e.get("/devices")
	wantStatus(t, resp, body, http.StatusOK)

	resp, body = e.post("/logout", url.Values{})
	wantRedirect(t, resp, body, "/login")
	resp, body = e.get("/devices")
	wantRedirect(t, resp, body, "/login")
}

func TestLoginRateLimit(t *testing.T) {
	e := newEnv(t)
	e.setUp()
	e.client.Jar, _ = cookiejar.New(nil)
	for range 5 {
		resp, body := e.post("/login", url.Values{"password": {"wrong password"}})
		wantStatus(t, resp, body, http.StatusUnauthorized)
	}
	// Locked out, even with the right password.
	resp, body := e.post("/login", url.Values{"password": {testPassword}})
	wantStatus(t, resp, body, http.StatusTooManyRequests)
}

func TestCrossSiteRequestsRejected(t *testing.T) {
	e := newEnv(t)
	e.setUp()
	e.setEndpoint()
	resp, body := e.post("/devices", url.Values{"name": {"evil"}}, "Sec-Fetch-Site", "cross-site")
	wantStatus(t, resp, body, http.StatusForbidden)
	resp, body = e.post("/devices", url.Values{"name": {"evil"}}, "Origin", "https://evil.example")
	wantStatus(t, resp, body, http.StatusForbidden)
	if devices, _ := e.store.ListDevices(t.Context()); len(devices) != 0 {
		t.Errorf("cross-site request created %d devices", len(devices))
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t)
	resp, _ := e.get("/setup")
	for _, h := range []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"} {
		if resp.Header.Get(h) == "" {
			t.Errorf("missing header %s", h)
		}
	}
}

func TestCreateDevice(t *testing.T) {
	e := newEnv(t)
	e.setUp()

	resp, body := e.post("/devices", url.Values{"name": {"phone"}, "profile": {"1"}})
	wantStatus(t, resp, body, http.StatusUnprocessableEntity)
	if !strings.Contains(body, "endpoint host") {
		t.Errorf("missing endpoint hint:\n%s", body)
	}

	e.setEndpoint()
	resp, body = e.post("/devices", url.Values{"name": {"phone"}, "profile": {"1"}})
	wantStatus(t, resp, body, http.StatusOK)
	for _, want := range []string{"PrivateKey = ", "data:image/png;base64,", `download="phone.conf"`, "Endpoint = vpn.example.com:51820"} {
		if !strings.Contains(body, want) {
			t.Errorf("config page lacks %q", want)
		}
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("config page may be cached")
	}
	if e.applied.Load() == 0 {
		t.Error("configuration was not applied")
	}
	devices, _ := e.store.ListDevices(t.Context())
	if len(devices) != 1 || len(devices[0].ProfileIDs) != 1 {
		t.Fatalf("unexpected devices: %+v", devices)
	}
	// The private key is not stored anywhere: only the public key matches.
	if strings.Contains(body, devices[0].PublicKey) {
		t.Error("config page contains the device's public key instead of its private key")
	}

	resp, body = e.post("/devices", url.Values{"name": {"phone"}})
	wantStatus(t, resp, body, http.StatusUnprocessableEntity)
	if !strings.Contains(body, "Name already in use") {
		t.Errorf("missing duplicate name message:\n%s", body)
	}
}

func TestOutputIsEscaped(t *testing.T) {
	e := newEnv(t)
	e.setUp()
	d := model.Device{Name: `<script>alert(1)</script>`, PublicKey: mustKey(t), Enabled: true}
	if err := e.store.CreateDevice(t.Context(), &d); err != nil {
		t.Fatal(err)
	}
	_, body := e.get("/devices")
	if strings.Contains(body, "<script>alert") {
		t.Error("device name rendered unescaped")
	}
}

func TestRuleEditing(t *testing.T) {
	e := newEnv(t)
	e.setUp()
	a := model.Device{Name: "a", PublicKey: mustKey(t), Enabled: true}
	b := model.Device{Name: "b", PublicKey: mustKey(t), Enabled: true}
	for _, d := range []*model.Device{&a, &b} {
		if err := e.store.CreateDevice(t.Context(), d); err != nil {
			t.Fatal(err)
		}
	}
	base := "/devices/" + itoa(a.ID)
	htmx := []string{"HX-Request", "true"}

	// htmx: the rules section comes back, with the new rule.
	resp, body := e.post(base+"/rules", url.Values{"destination": {"192.168.1.10"}, "protocol": {"tcp"}, "ports": {"8096"}, "comment": {"Jellyfin"}}, htmx...)
	wantStatus(t, resp, body, http.StatusOK)
	if !strings.HasPrefix(strings.TrimSpace(body), `<div id="rules">`) || !strings.Contains(body, "Jellyfin") || !strings.Contains(body, "8096") {
		t.Fatalf("unexpected partial:\n%s", body)
	}

	// Invalid input: error shown, typed values kept, nothing saved.
	resp, body = e.post(base+"/rules", url.Values{"destination": {"192.168.1.5/24"}, "ports": {"80"}}, htmx...)
	wantStatus(t, resp, body, http.StatusOK)
	if !strings.Contains(body, "did you mean 192.168.1.0/24") || !strings.Contains(body, `value="192.168.1.5/24"`) {
		t.Errorf("missing error or typed value:\n%s", body)
	}
	resp, body = e.post(base+"/rules", url.Values{"destination": {"10.0.0.1"}, "protocol": {"tcp"}, "ports": {"eighty"}}, htmx...)
	if !strings.Contains(body, "use a number like 443") {
		t.Errorf("missing ports error:\n%s", body)
	}

	// Without htmx: redirect back to the page.
	resp, body = e.post(base+"/rules", url.Values{"destination": {"internet"}})
	wantRedirect(t, resp, body, base+"?msg=saved")

	got, _ := e.store.Device(t.Context(), a.ID)
	if len(got.Rules) != 2 {
		t.Fatalf("rules = %+v, want 2", got.Rules)
	}

	// A rule can't be deleted through another device's URL.
	resp, body = e.post("/devices/"+itoa(b.ID)+"/rules/"+itoa(got.Rules[0].ID)+"/delete", url.Values{}, htmx...)
	wantStatus(t, resp, body, http.StatusNotFound)
	resp, body = e.post(base+"/rules/"+itoa(got.Rules[0].ID)+"/delete", url.Values{}, htmx...)
	wantStatus(t, resp, body, http.StatusOK)
	if strings.Contains(body, "Jellyfin") {
		t.Error("deleted rule still shown")
	}
}

func TestPagesRender(t *testing.T) {
	e := newEnv(t)
	e.setUp()
	e.setEndpoint()
	d := model.Device{Name: "phone", PublicKey: mustKey(t), Enabled: true, ProfileIDs: []int64{1}}
	if err := e.store.CreateDevice(t.Context(), &d); err != nil {
		t.Fatal(err)
	}
	id := itoa(d.ID)
	for _, path := range []string{
		"/devices", "/devices/new", "/devices/" + id, "/devices/" + id + "/delete", "/devices/" + id + "/regenerate",
		"/profiles", "/profiles/new", "/profiles/1", "/profiles/1/delete", "/settings",
		"/static/pico.min.css", "/static/htmx.min.js", "/static/app.css", "/static/theme.js",
		"/static/logo.svg", "/static/favicon.svg", "/favicon.ico", "/apple-touch-icon.png",
	} {
		resp, body := e.get(path)
		wantStatus(t, resp, body, http.StatusOK)
	}
	for _, path := range []string{"/devices/999", "/devices/abc", "/profiles/999"} {
		resp, body := e.get(path)
		wantStatus(t, resp, body, http.StatusNotFound)
	}
}

func TestSettingsAndDeviceUpdates(t *testing.T) {
	e := newEnv(t)
	e.setUp()
	resp, body := e.post("/settings", url.Values{
		"endpoint_host": {"vpn.example.com"}, "endpoint_port": {"51821"}, "tunnel_cidr": {"10.9.0.0/24"},
		"client_dns": {"192.168.1.2, 1.1.1.1"}, "mtu": {""}, "keepalive": {"25"},
	})
	wantRedirect(t, resp, body, "/settings?msg=saved")
	set, _ := e.store.Settings(t.Context())
	if set.EndpointPort != 51821 || set.TunnelCIDR.String() != "10.9.0.0/24" || len(set.ClientDNS) != 2 {
		t.Errorf("settings not saved: %+v", set)
	}
	resp, body = e.post("/settings", url.Values{"endpoint_host": {"x"}, "endpoint_port": {"1"}, "tunnel_cidr": {"nope"}})
	wantStatus(t, resp, body, http.StatusUnprocessableEntity)

	d := model.Device{Name: "phone", PublicKey: mustKey(t), Enabled: true}
	if err := e.store.CreateDevice(t.Context(), &d); err != nil {
		t.Fatal(err)
	}
	resp, body = e.post("/devices/"+itoa(d.ID), url.Values{"name": {"tablet"}, "profile": {"1"}, "allowed_ips": {"0.0.0.0/0"}})
	wantRedirect(t, resp, body, "/devices/"+itoa(d.ID)+"?msg=saved")
	got, _ := e.store.Device(t.Context(), d.ID)
	if got.Name != "tablet" || got.Enabled || len(got.ProfileIDs) != 1 || len(got.ClientAllowedIPs) != 1 {
		t.Errorf("device not updated: %+v", got)
	}
	resp, body = e.post("/devices/"+itoa(d.ID), url.Values{"name": {"tablet"}, "allowed_ips": {"garbage"}})
	wantStatus(t, resp, body, http.StatusUnprocessableEntity)
	if !strings.Contains(body, "Client allowed IPs") {
		t.Errorf("missing allowed IPs error:\n%s", body)
	}

	resp, body = e.post("/devices/"+itoa(d.ID)+"/delete", url.Values{})
	wantRedirect(t, resp, body, "/devices?msg=deleted")
}

func mustKey(t *testing.T) string {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().String()
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
