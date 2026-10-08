package web

import (
	"context"
	"net/http"

	"github.com/ap-andersson/tunnelward/internal/model"
)

// rulesPage loads the page that owns a rules editor (a device or profile),
// returning the template name, the full page and its rules section.
type rulesPage func(ctx context.Context, ownerID int64) (string, page, *rulesData, error)

// addRule handles the rule form. htmx requests get the re-rendered rules
// section; plain form posts get a redirect (or the full page on error).
func (s *Server) addRule(w http.ResponseWriter, r *http.Request, add func(context.Context, int64, *model.Rule) error, load rulesPage) {
	ctx := r.Context()
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return
	}
	rule, form, err := parseRuleForm(r)
	if err == nil {
		err = add(ctx, id, &rule)
	}
	var msg string
	if err != nil {
		if msg = userError(err); msg == "" {
			s.storeError(w, r, err)
			return
		}
	}
	s.finishRuleChange(w, r, id, err == nil, msg, form, load)
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request, del func(context.Context, int64, int64) error, load rulesPage) {
	id, ok1 := pathID(r, "id")
	ruleID, ok2 := pathID(r, "rule")
	if !ok1 || !ok2 {
		s.notFound(w, r)
		return
	}
	if err := del(r.Context(), id, ruleID); err != nil {
		s.storeError(w, r, err)
		return
	}
	s.finishRuleChange(w, r, id, true, "", ruleForm{}, load)
}

// finishRuleChange applies a successful change and responds. On a failed
// change, msg is the error and form is what the user typed.
func (s *Server) finishRuleChange(w http.ResponseWriter, r *http.Request, id int64, changed bool, msg string, form ruleForm, load rulesPage) {
	ctx := r.Context()
	applyFailed := changed && !s.applyChanges(ctx)
	if applyFailed {
		msg = flashes["apply-failed"]
	}
	name, p, rules, err := load(ctx, id)
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	rules.Error = msg
	if !changed {
		rules.Form = form
	}

	if isHTMX(r) {
		s.renderPartial(w, name, "rules", rules)
		return
	}
	switch {
	case !changed:
		s.render(w, r, http.StatusUnprocessableEntity, name, p)
	case applyFailed:
		s.redirect(w, r, rules.BaseURL+"?msg=apply-failed")
	default:
		s.redirect(w, r, rules.BaseURL+"?msg=saved")
	}
}

// confirmData is for the generic confirmation page, used instead of
// JavaScript confirm dialogs.
type confirmData struct {
	Question string
	Action   string // POST target
	Button   string
	Danger   bool   // style the button as destructive
	Cancel   string // link back
}
