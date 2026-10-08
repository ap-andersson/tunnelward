package web

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"

	"github.com/ap-andersson/tunnelward/internal/model"
)

type settingsData struct {
	Settings        model.Settings
	TunnelCIDR      string
	ClientDNS       string
	ServerPublicKey string
	ListenPort      int
	HasDevices      bool
}

func (s *Server) settingsData(ctx context.Context) (settingsData, error) {
	set, err := s.store.Settings(ctx)
	if err != nil {
		return settingsData{}, err
	}
	devices, err := s.store.ListDevices(ctx)
	if err != nil {
		return settingsData{}, err
	}
	dns := make([]string, len(set.ClientDNS))
	for i, a := range set.ClientDNS {
		dns[i] = a.String()
	}
	return settingsData{
		Settings:        set,
		TunnelCIDR:      set.TunnelCIDR.String(),
		ClientDNS:       strings.Join(dns, ", "),
		ServerPublicKey: s.serverPublicKey.String(),
		ListenPort:      s.listenPort,
		HasDevices:      len(devices) > 0,
	}, nil
}

func (s *Server) showSettings(w http.ResponseWriter, r *http.Request) {
	data, err := s.settingsData(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "settings.html", page{Title: "Settings", Data: data})
}

func (s *Server) updateSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	set, err := s.parseSettings(r)
	if err == nil {
		err = s.store.UpdateSettings(ctx, set)
	}
	if err != nil {
		msg := userError(err)
		if msg == "" {
			s.serverError(w, r, err)
			return
		}
		data, derr := s.settingsData(ctx)
		if derr != nil {
			s.serverError(w, r, derr)
			return
		}
		// Keep what was typed.
		data.Settings.EndpointHost = r.PostFormValue("endpoint_host")
		data.TunnelCIDR = r.PostFormValue("tunnel_cidr")
		data.ClientDNS = r.PostFormValue("client_dns")
		s.render(w, r, http.StatusUnprocessableEntity, "settings.html", page{Title: "Settings", Error: msg, Data: data})
		return
	}
	slog.Info("settings updated")
	s.applyAndRedirect(w, r, "/settings", "saved")
}

func (s *Server) parseSettings(r *http.Request) (model.Settings, error) {
	var set model.Settings
	var err error
	set.EndpointHost = strings.TrimSpace(r.PostFormValue("endpoint_host"))
	if set.EndpointPort, err = atoiField(r, "endpoint_port", "endpoint port"); err != nil {
		return set, err
	}
	if set.MTU, err = atoiField(r, "mtu", "MTU"); err != nil {
		return set, err
	}
	if set.Keepalive, err = atoiField(r, "keepalive", "keepalive"); err != nil {
		return set, err
	}
	cidr := strings.TrimSpace(r.PostFormValue("tunnel_cidr"))
	if set.TunnelCIDR, err = netip.ParsePrefix(cidr); err != nil {
		return set, formErrorf("tunnel network: %q is not a network like 10.8.0.0/24", cidr)
	}
	if set.ClientDNS, err = parseAddrs(r.PostFormValue("client_dns")); err != nil {
		return set, formErrorf("client DNS: %s", err)
	}
	return set, nil
}
