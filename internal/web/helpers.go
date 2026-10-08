package web

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ap-andersson/tunnelward/internal/model"
	"github.com/ap-andersson/tunnelward/internal/store"
	"github.com/ap-andersson/tunnelward/internal/wg"
)

var funcs = template.FuncMap{
	"ruleDest": func(r model.Rule) string {
		if r.Destination == model.Internet {
			return "Internet"
		}
		return strings.TrimSuffix(r.Destination, "/32")
	},
	"ruleProto":  func(r model.Rule) string { return protoLabel(r.Protocol) },
	"protoLabel": protoLabel,
	"rulePorts": func(r model.Rule) string {
		switch {
		case r.PortFrom == 0:
			return "Any"
		case r.PortFrom == r.PortTo:
			return strconv.Itoa(r.PortFrom)
		}
		return fmt.Sprintf("%d–%d", r.PortFrom, r.PortTo)
	},
	"state":  stateOf,
	"ago":    ago,
	"bytes":  humanBytes,
	"online": online,
	"protocols": func() []model.Protocol {
		return []model.Protocol{model.ProtoAny, model.ProtoTCP, model.ProtoUDP, model.ProtoTCPUDP, model.ProtoICMP}
	},
}

func protoLabel(p model.Protocol) string {
	if p == model.ProtoAny {
		return "Any"
	}
	return strings.ToUpper(string(p))
}

// deviceState is how a device is shown: online, offline or disabled.
type deviceState struct {
	Kind  string // CSS class and icon
	Label string
}

func stateOf(enabled bool, st *wg.PeerStatus) deviceState {
	switch {
	case !enabled:
		return deviceState{"disabled", "Disabled"}
	case online(st):
		return deviceState{"online", "Online"}
	}
	return deviceState{"offline", "Offline"}
}

// online reports whether a peer has had a handshake recently. WireGuard
// re-handshakes every 2 minutes while traffic flows.
func online(st *wg.PeerStatus) bool {
	return st != nil && !st.LastHandshake.IsZero() && time.Since(st.LastHandshake) < 3*time.Minute
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "Never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "Just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	}
	return fmt.Sprintf("%d days ago", int(d.Hours()/24))
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// userError returns a message to show for err, or "" if err is internal
// and should only be logged.
func userError(err error) string {
	var ve *model.ValidationError
	var fe *formError
	if errors.As(err, &ve) || errors.As(err, &fe) || errors.Is(err, store.ErrConflict) || errors.Is(err, model.ErrTunnelFull) {
		return capitalize(err.Error()) + "."
	}
	return ""
}

// formError is a problem with submitted form syntax, shown to the user.
type formError struct{ msg string }

func (e *formError) Error() string { return e.msg }

func formErrorf(format string, args ...any) error {
	return &formError{fmt.Sprintf(format, args...)}
}

func capitalize(s string) string {
	r, size := utf8.DecodeRuneInString(s)
	return string(unicode.ToUpper(r)) + s[size:]
}

// ruleForm holds a submitted rule form, to refill it after an error.
type ruleForm struct {
	Destination string
	Protocol    string
	Ports       string
	Comment     string
}

// parseRuleForm reads a rule from the request. Validation happens later in
// Rule.Normalize, except for the ports syntax.
func parseRuleForm(r *http.Request) (model.Rule, ruleForm, error) {
	f := ruleForm{
		Destination: strings.TrimSpace(r.PostFormValue("destination")),
		Protocol:    r.PostFormValue("protocol"),
		Ports:       strings.TrimSpace(r.PostFormValue("ports")),
		Comment:     strings.TrimSpace(r.PostFormValue("comment")),
	}
	rule := model.Rule{Destination: f.Destination, Protocol: model.Protocol(f.Protocol), Comment: f.Comment}
	if f.Ports != "" {
		from, to, isRange := strings.Cut(f.Ports, "-")
		var err1, err2 error
		rule.PortFrom, err1 = strconv.Atoi(strings.TrimSpace(from))
		rule.PortTo = rule.PortFrom
		if isRange {
			rule.PortTo, err2 = strconv.Atoi(strings.TrimSpace(to))
		}
		if err1 != nil || err2 != nil {
			return rule, f, formErrorf("ports: use a number like 443 or a range like 8000-8100")
		}
	}
	return rule, f, nil
}

// rulesData is the data for the "rules" partial, shared by device and
// profile pages.
type rulesData struct {
	BaseURL   string // the owner's page; the form posts to BaseURL + "/rules"
	Rules     []model.Rule
	Effective []model.SourcedRule // device pages only: everything the device may reach
	IsDevice  bool
	Form      ruleForm
	Error     string
}

// splitList splits a list separated by commas, spaces or newlines.
func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
}

func parsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range splitList(s) {
		p, err := netip.ParsePrefix(f)
		if err != nil {
			return nil, formErrorf("%q is not a network like 0.0.0.0/0", f)
		}
		out = append(out, p)
	}
	return out, nil
}

func parseAddrs(s string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, f := range splitList(s) {
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, formErrorf("%q is not an IP address", f)
		}
		out = append(out, a)
	}
	return out, nil
}

// atoiField parses an optional integer form field (empty means 0).
func atoiField(r *http.Request, name, label string) (int, error) {
	v := strings.TrimSpace(r.PostFormValue(name))
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, formErrorf("%s: %q is not a number", label, v)
	}
	return n, nil
}

// formIDs parses repeated numeric form values (e.g. checked profiles).
func formIDs(r *http.Request, name string) []int64 {
	var ids []int64
	for _, v := range r.PostForm[name] {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

func isHTMX(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true"
}
