package clientconf

import (
	"net/netip"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ap-andersson/tunnelward/internal/model"
)

func TestRender(t *testing.T) {
	priv, _ := wgtypes.ParseKey("YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=")
	server, _ := wgtypes.ParseKey("HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=")
	set := model.DefaultSettings
	set.EndpointHost = "vpn.example.com"
	set.ClientDNS = []netip.Addr{netip.MustParseAddr("192.168.1.2")}
	got, err := Render(Params{
		Settings: set,
		Device: model.Device{
			Name: "Kid's phone\n[Peer]", IP: netip.MustParseAddr("10.8.0.2"),
			ClientAllowedIPs: model.DefaultClientAllowedIPs,
		},
		PrivateKey:      priv,
		ServerPublicKey: server,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `[Interface]
# Kid's phone[Peer]
PrivateKey = YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.8.0.2/32
DNS = 192.168.1.2

[Peer]
PublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
`
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}

	set.EndpointHost = "2001:db8::1"
	got, _ = Render(Params{Settings: set, Device: model.Device{IP: netip.MustParseAddr("10.8.0.2")}})
	if !strings.Contains(got, "Endpoint = [2001:db8::1]:51820") {
		t.Errorf("IPv6 endpoint not bracketed:\n%s", got)
	}

	set.EndpointHost = ""
	if _, err := Render(Params{Settings: set}); err == nil {
		t.Error("expected an error without an endpoint host")
	}
}

func TestFileName(t *testing.T) {
	for in, want := range map[string]string{
		"Kid's phone":             "Kids-phone.conf",
		"a very long device name": "a-very-long-dev.conf",
		"../../etc/passwd":        "etcpasswd.conf",
		"ÅÄÖ":                     "tunnelward.conf",
	} {
		if got := FileName(in); got != want {
			t.Errorf("FileName(%q) = %q, want %q", in, got, want)
		}
	}
}
