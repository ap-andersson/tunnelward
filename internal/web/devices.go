package web

import (
	"context"
	"encoding/base64"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ap-andersson/tunnelward/internal/clientconf"
	"github.com/ap-andersson/tunnelward/internal/firewall"
	"github.com/ap-andersson/tunnelward/internal/model"
	"github.com/ap-andersson/tunnelward/internal/store"
	"github.com/ap-andersson/tunnelward/internal/wg"
)

type deviceRow struct {
	model.Device
	Profiles []string
	Status   *wg.PeerStatus
}

// peerStatuses returns live peer status by public key. Errors (e.g. no
// interface yet) just mean no status is shown.
func (s *Server) peerStatuses() map[string]*wg.PeerStatus {
	out := map[string]*wg.PeerStatus{}
	if s.statuses == nil {
		return out
	}
	st, err := s.statuses()
	if err != nil {
		slog.Debug("reading peer status", "err", err)
		return out
	}
	for k, v := range st {
		out[k.String()] = &v
	}
	return out
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	snap, err := s.store.Snapshot(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	statuses := s.peerStatuses()
	rows := make([]deviceRow, len(snap.Devices))
	for i, d := range snap.Devices {
		rows[i] = deviceRow{Device: d, Status: statuses[d.PublicKey]}
		for _, id := range d.ProfileIDs {
			rows[i].Profiles = append(rows[i].Profiles, snap.Profiles[id].Name)
		}
	}
	s.render(w, r, http.StatusOK, "devices.html", page{Title: "Devices", Data: struct {
		Devices         []deviceRow
		EndpointMissing bool
	}{rows, snap.Settings.EndpointHost == ""}})
}

type newDeviceData struct {
	Profiles        []model.Profile
	Selected        map[int64]bool
	Name            string
	EndpointMissing bool
}

func (s *Server) newDeviceForm(w http.ResponseWriter, r *http.Request) {
	data, err := s.newDeviceData(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "device_new.html", page{Title: "Add device", Data: data})
}

func (s *Server) newDeviceData(ctx context.Context) (newDeviceData, error) {
	profiles, err := s.store.ListProfiles(ctx)
	if err != nil {
		return newDeviceData{}, err
	}
	set, err := s.store.Settings(ctx)
	if err != nil {
		return newDeviceData{}, err
	}
	return newDeviceData{Profiles: profiles, Selected: map[int64]bool{}, EndpointMissing: set.EndpointHost == ""}, nil
}

func (s *Server) createDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d := model.Device{Name: r.PostFormValue("name"), Enabled: true, ProfileIDs: formIDs(r, "profile")}

	fail := func(msg string) {
		data, err := s.newDeviceData(ctx)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		data.Name = d.Name
		for _, id := range d.ProfileIDs {
			data.Selected[id] = true
		}
		s.render(w, r, http.StatusUnprocessableEntity, "device_new.html", page{Title: "Add device", Error: msg, Data: data})
	}

	set, err := s.store.Settings(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if set.EndpointHost == "" {
		fail("Set the endpoint host in Settings first, so the device's config can be generated.")
		return
	}
	priv, pub, err := wg.NewKeyPair()
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d.PublicKey = pub.String()
	if err := s.store.CreateDevice(ctx, &d); err != nil {
		if msg := userError(err); msg != "" {
			fail(msg)
			return
		}
		s.serverError(w, r, err)
		return
	}
	slog.Info("device created", "id", d.ID, "name", d.Name, "ip", d.IP)
	s.showConfig(w, r, d, priv, "created")
}

// showConfig applies the configuration and shows the device's client config
// once. The private key only exists in this response.
func (s *Server) showConfig(w http.ResponseWriter, r *http.Request, d model.Device, priv wgtypes.Key, what string) {
	ctx := r.Context()
	s.applyChanges(ctx) // a failure shows as the out-of-sync banner
	set, err := s.store.Settings(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	conf, err := clientconf.Render(clientconf.Params{Settings: set, Device: d, PrivateKey: priv, ServerPublicKey: s.serverPublicKey})
	if err != nil {
		s.render(w, r, http.StatusUnprocessableEntity, "message.html", page{Title: "Error", Error: capitalize(err.Error()) + "."})
		return
	}
	png, err := qrcode.Encode(conf, qrcode.Medium, 360)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	p := page{Title: d.Name, Data: struct {
		Device   model.Device
		What     string
		Config   string
		QR       template.URL
		Download template.URL
		FileName string
	}{
		Device:   d,
		What:     what,
		Config:   conf,
		QR:       template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png)),
		Download: template.URL("data:application/octet-stream;base64," + base64.StdEncoding.EncodeToString([]byte(conf))),
		FileName: clientconf.FileName(d.Name),
	}}
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, r, http.StatusOK, "device_config.html", p)
}

type deviceData struct {
	Device     model.Device
	Profiles   []model.Profile
	Assigned   map[int64]bool
	AllowedIPs string
	Status     *wg.PeerStatus
	Rules      rulesData
	// DNSUnreachable are configured DNS servers this device's rules don't
	// reach, so it can't look up names while connected.
	DNSUnreachable []netip.Addr
}

func (s *Server) deviceData(ctx context.Context, id int64) (deviceData, error) {
	snap, err := s.store.Snapshot(ctx)
	if err != nil {
		return deviceData{}, err
	}
	var data deviceData
	found := false
	for _, d := range snap.Devices {
		if d.ID == id {
			data.Device, found = d, true
		}
	}
	if !found {
		return data, store.ErrNotFound
	}
	d := data.Device
	data.Assigned = map[int64]bool{}
	for _, pid := range d.ProfileIDs {
		data.Assigned[pid] = true
	}
	profiles, err := s.store.ListProfiles(ctx)
	if err != nil {
		return data, err
	}
	data.Profiles = profiles
	allowed := make([]string, len(d.ClientAllowedIPs))
	for i, p := range d.ClientAllowedIPs {
		allowed[i] = p.String()
	}
	data.AllowedIPs = strings.Join(allowed, ", ")
	data.Status = s.peerStatuses()[d.PublicKey]
	effective, err := model.EffectiveRules(d, snap.Profiles)
	if err != nil {
		return data, err
	}
	for _, dns := range snap.Settings.ClientDNS {
		if !firewall.Reaches(effective, snap.Settings.TunnelCIDR, nil, dns, model.ProtoUDP, 53) {
			data.DNSUnreachable = append(data.DNSUnreachable, dns)
		}
	}
	data.Rules = rulesData{
		BaseURL:   "/devices/" + strconv.FormatInt(id, 10),
		Rules:     d.Rules,
		Effective: effective,
		IsDevice:  true,
	}
	return data, nil
}

func (s *Server) showDevice(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return
	}
	data, err := s.deviceData(r.Context(), id)
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "device.html", page{Title: data.Device.Name, Data: data})
}

func (s *Server) updateDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return
	}
	d, err := s.store.Device(ctx, id)
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	d.Name = r.PostFormValue("name")
	d.Enabled = r.PostFormValue("enabled") == "on"
	d.ProfileIDs = formIDs(r, "profile")
	allowed, err := parsePrefixes(r.PostFormValue("allowed_ips"))
	if err != nil {
		err = formErrorf("client allowed IPs: %s", err)
	} else {
		d.ClientAllowedIPs = allowed
		err = s.store.UpdateDevice(ctx, &d)
	}
	if err != nil {
		msg := userError(err)
		if msg == "" {
			s.storeError(w, r, err)
			return
		}
		data, derr := s.deviceData(ctx, id)
		if derr != nil {
			s.storeError(w, r, derr)
			return
		}
		// Keep what was typed.
		data.Device.Name, data.Device.Enabled = d.Name, d.Enabled
		data.AllowedIPs = r.PostFormValue("allowed_ips")
		data.Assigned = map[int64]bool{}
		for _, pid := range d.ProfileIDs {
			data.Assigned[pid] = true
		}
		s.render(w, r, http.StatusUnprocessableEntity, "device.html", page{Title: data.Device.Name, Error: msg, Data: data})
		return
	}
	slog.Info("device updated", "id", d.ID, "name", d.Name, "enabled", d.Enabled)
	s.applyAndRedirect(w, r, "/devices/"+strconv.FormatInt(id, 10), "saved")
}

func (s *Server) confirmDeleteDevice(w http.ResponseWriter, r *http.Request) {
	s.confirmDevice(w, r, "Delete device", "Delete %q? Its config stops working immediately. This can't be undone.", "delete", "Delete device", true)
}

func (s *Server) confirmRegenerate(w http.ResponseWriter, r *http.Request) {
	s.confirmDevice(w, r, "New keys", "Generate new keys for %q? Its current config stops working, and you'll get a new one to install.", "regenerate", "Generate new keys", false)
}

func (s *Server) confirmDevice(w http.ResponseWriter, r *http.Request, title, question, action, button string, danger bool) {
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return
	}
	d, err := s.store.Device(r.Context(), id)
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	base := "/devices/" + strconv.FormatInt(id, 10)
	s.render(w, r, http.StatusOK, "confirm.html", page{Title: title, Data: confirmData{
		Question: fmt.Sprintf(question, d.Name),
		Action:   base + "/" + action,
		Button:   button,
		Danger:   danger,
		Cancel:   base,
	}})
}

func (s *Server) deleteDevice(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return
	}
	if err := s.store.DeleteDevice(r.Context(), id); err != nil {
		s.storeError(w, r, err)
		return
	}
	slog.Info("device deleted", "id", id)
	s.applyAndRedirect(w, r, "/devices", "deleted")
}

func (s *Server) regenerate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return
	}
	d, err := s.store.Device(ctx, id)
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	priv, pub, err := wg.NewKeyPair()
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d.PublicKey = pub.String()
	if err := s.store.UpdateDevice(ctx, &d); err != nil {
		s.serverError(w, r, err)
		return
	}
	slog.Info("device keys regenerated", "id", d.ID, "name", d.Name)
	s.showConfig(w, r, d, priv, "regenerated")
}

func (s *Server) addDeviceRule(w http.ResponseWriter, r *http.Request) {
	s.addRule(w, r, func(ctx context.Context, id int64, rule *model.Rule) error {
		return s.store.AddDeviceRule(ctx, id, rule)
	}, s.deviceRulesPage)
}

func (s *Server) deleteDeviceRule(w http.ResponseWriter, r *http.Request) {
	s.deleteRule(w, r, s.store.DeleteDeviceRule, s.deviceRulesPage)
}

// deviceRulesPage loads the device page data for the rules editor.
func (s *Server) deviceRulesPage(ctx context.Context, id int64) (string, page, *rulesData, error) {
	data, err := s.deviceData(ctx, id)
	if err != nil {
		return "", page{}, nil, err
	}
	p := page{Title: data.Device.Name, Data: &data}
	return "device.html", p, &data.Rules, nil
}
