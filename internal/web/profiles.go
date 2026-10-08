package web

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/ap-andersson/tunnelward/internal/model"
	"github.com/ap-andersson/tunnelward/internal/store"
)

type profileRow struct {
	model.Profile
	Devices int
}

func (s *Server) listProfiles(w http.ResponseWriter, r *http.Request) {
	snap, err := s.store.Snapshot(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	profiles, err := s.store.ListProfiles(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	rows := make([]profileRow, len(profiles))
	for i, p := range profiles {
		rows[i] = profileRow{Profile: p, Devices: len(devicesUsing(snap, p.ID))}
	}
	s.render(w, r, http.StatusOK, "profiles.html", page{Title: "Profiles", Data: rows})
}

func devicesUsing(snap store.Snapshot, profileID int64) []model.Device {
	var out []model.Device
	for _, d := range snap.Devices {
		for _, id := range d.ProfileIDs {
			if id == profileID {
				out = append(out, d)
				break
			}
		}
	}
	return out
}

func (s *Server) newProfileForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "profile_new.html", page{Title: "New profile", Data: model.Profile{}})
}

func (s *Server) createProfile(w http.ResponseWriter, r *http.Request) {
	p := model.Profile{Name: r.PostFormValue("name"), Description: r.PostFormValue("description")}
	if err := s.store.CreateProfile(r.Context(), &p); err != nil {
		if msg := userError(err); msg != "" {
			s.render(w, r, http.StatusUnprocessableEntity, "profile_new.html", page{Title: "New profile", Error: msg, Data: p})
			return
		}
		s.serverError(w, r, err)
		return
	}
	slog.Info("profile created", "id", p.ID, "name", p.Name)
	s.redirect(w, r, fmt.Sprintf("/profiles/%d?msg=saved", p.ID))
}

type profileData struct {
	Profile model.Profile
	UsedBy  []model.Device
	Rules   rulesData
}

func (s *Server) profileData(ctx context.Context, id int64) (profileData, error) {
	p, err := s.store.Profile(ctx, id)
	if err != nil {
		return profileData{}, err
	}
	snap, err := s.store.Snapshot(ctx)
	if err != nil {
		return profileData{}, err
	}
	return profileData{
		Profile: p,
		UsedBy:  devicesUsing(snap, id),
		Rules:   rulesData{BaseURL: "/profiles/" + strconv.FormatInt(id, 10), Rules: p.Rules},
	}, nil
}

func (s *Server) showProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return
	}
	data, err := s.profileData(r.Context(), id)
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "profile.html", page{Title: data.Profile.Name, Data: data})
}

func (s *Server) updateProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return
	}
	p := model.Profile{ID: id, Name: r.PostFormValue("name"), Description: r.PostFormValue("description")}
	if err := s.store.UpdateProfile(ctx, &p); err != nil {
		msg := userError(err)
		if msg == "" {
			s.storeError(w, r, err)
			return
		}
		data, derr := s.profileData(ctx, id)
		if derr != nil {
			s.storeError(w, r, derr)
			return
		}
		data.Profile.Name, data.Profile.Description = p.Name, p.Description
		s.render(w, r, http.StatusUnprocessableEntity, "profile.html", page{Title: p.Name, Error: msg, Data: data})
		return
	}
	// Profile names appear in the firewall ruleset's comments.
	s.applyAndRedirect(w, r, "/profiles/"+strconv.FormatInt(id, 10), "saved")
}

func (s *Server) confirmDeleteProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return
	}
	data, err := s.profileData(r.Context(), id)
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	q := fmt.Sprintf("Delete the profile %q?", data.Profile.Name)
	if n := len(data.UsedBy); n > 0 {
		q += fmt.Sprintf(" %d device(s) use it and will lose the access it gives.", n)
	}
	base := "/profiles/" + strconv.FormatInt(id, 10)
	s.render(w, r, http.StatusOK, "confirm.html", page{Title: "Delete profile", Data: confirmData{
		Question: q, Action: base + "/delete", Button: "Delete profile", Danger: true, Cancel: base,
	}})
}

func (s *Server) deleteProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return
	}
	if err := s.store.DeleteProfile(r.Context(), id); err != nil {
		s.storeError(w, r, err)
		return
	}
	slog.Info("profile deleted", "id", id)
	s.applyAndRedirect(w, r, "/profiles", "deleted")
}

func (s *Server) addProfileRule(w http.ResponseWriter, r *http.Request) {
	s.addRule(w, r, func(ctx context.Context, id int64, rule *model.Rule) error {
		return s.store.AddProfileRule(ctx, id, rule)
	}, s.profileRulesPage)
}

func (s *Server) deleteProfileRule(w http.ResponseWriter, r *http.Request) {
	s.deleteRule(w, r, s.store.DeleteProfileRule, s.profileRulesPage)
}

func (s *Server) profileRulesPage(ctx context.Context, id int64) (string, page, *rulesData, error) {
	data, err := s.profileData(ctx, id)
	if err != nil {
		return "", page{}, nil, err
	}
	return "profile.html", page{Title: data.Profile.Name, Data: &data}, &data.Rules, nil
}
