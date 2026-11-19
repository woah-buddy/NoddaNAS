package httpapi

import (
	"net/http"
	"time"

	"github.com/woah-buddy/NoddaNAS/internal/auth"
	"github.com/woah-buddy/NoddaNAS/internal/config"
	"github.com/woah-buddy/NoddaNAS/internal/domain"
	"github.com/woah-buddy/NoddaNAS/internal/service"
	"github.com/woah-buddy/NoddaNAS/internal/settings"
)

// The admin area and first-time setup. Authorization lives below this
// layer (service.RequireAdmin / RequireFreshAdmin and the settings
// manager); these handlers only decode, delegate and encode.

// maxSettingsBody fits a pasted SAML metadata document (1 MiB) or a logo
// (512 KiB, as base64) plus the rest of the request.
const maxSettingsBody = 2 << 20

var errNoSettings = domain.E(domain.CodeNotFound, "web settings are not available on this server")

func (s *Server) handleAdminSession(w http.ResponseWriter, r *http.Request, p service.Principal) {
	if err := s.svc.RequireAdmin(r.Context(), p); err != nil {
		s.writeError(w, r, err)
		return
	}
	v := map[string]any{"recent": s.svc.RequireFreshAdmin(r.Context(), p) == nil, "window": service.RecentSignIn.String()}
	if !p.ReauthAt.IsZero() {
		v["recentUntil"] = p.ReauthAt.Add(service.RecentSignIn).UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request, p service.Principal) {
	if s.settings == nil {
		s.writeError(w, r, errNoSettings)
		return
	}
	v, err := s.settings.View(r.Context(), p)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request, p service.Principal) {
	if s.settings == nil {
		s.writeError(w, r, errNoSettings)
		return
	}
	var req settings.UpdateRequest
	if err := decodeJSONLimit(w, r, &req, maxSettingsBody); err != nil {
		s.writeError(w, r, err)
		return
	}
	v, err := s.settings.Update(r.Context(), p, req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

type adminUserView struct {
	ID           string    `json:"id"`
	DisplayName  string    `json:"displayName"`
	Email        string    `json:"email,omitempty"`
	SignIn       string    `json:"signIn"` // "oidc" or "saml"
	Admin        bool      `json:"admin"`
	AdminGranted bool      `json:"adminGranted"`
	KeysSetUp    bool      `json:"keysSetUp"`
	QuotaBytes   int64     `json:"quotaBytes"`
	UsedBytes    int64     `json:"usedBytes"`
	CreatedAt    time.Time `json:"createdAt"`
}

func (s *Server) handleAdminListUsers(w http.ResponseWriter, r *http.Request, p service.Principal) {
	users, err := s.svc.AdminListUsers(r.Context(), p, r.URL.Query().Get("q"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	out := make([]adminUserView, len(users))
	for i, u := range users {
		method := "oidc"
		if len(u.Issuer) > 5 && u.Issuer[:5] == "saml:" {
			method = "saml"
		}
		out[i] = adminUserView{ID: u.ID, DisplayName: u.DisplayName, Email: u.Email, SignIn: method, Admin: u.Admin,
			AdminGranted: u.AdminGranted, KeysSetUp: u.KeysSetUp, QuotaBytes: u.QuotaBytes, UsedBytes: u.UsedBytes, CreatedAt: u.CreatedAt}
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

func (s *Server) handleAdminSetAdmin(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req struct {
		Admin bool `json:"admin"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.svc.AdminSetAdmin(r.Context(), p, r.PathValue("id"), req.Admin); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdminSetUserQuota(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req struct {
		Size string `json:"size"` // e.g. "10GiB"
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	n, err := config.ParseSize(req.Size)
	if err != nil {
		s.writeError(w, r, domain.E(domain.CodeInvalid, "%s", err.Error()))
		return
	}
	if err := s.svc.AdminSetUserQuota(r.Context(), p, r.PathValue("id"), n); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleAdminRevokeAccess signs a person out everywhere and deletes their
// app passwords (offboarding). It does not stop them signing in again:
// that is the identity provider's decision, so remove them there first.
func (s *Server) handleAdminRevokeAccess(w http.ResponseWriter, r *http.Request, p service.Principal) {
	if err := s.svc.RequireFreshAdmin(r.Context(), p); err != nil {
		s.writeError(w, r, err)
		return
	}
	target := r.PathValue("id")
	if target == p.UserID {
		s.writeError(w, r, domain.E(domain.CodeInvalid, "use “Sign out everywhere” in your own settings instead"))
		return
	}
	u, err := s.svc.UserByID(r.Context(), target)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	n, err := s.auth.RevokeUserCredentials(r.Context(), u.ID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.log.InfoContext(r.Context(), "audit", "event", "user.access_revoked", "user", p.UserID, "target", u.ID, "app_passwords", n)
	writeJSON(w, http.StatusOK, map[string]int64{"appPasswords": n})
}

// handleAdminEndAllSessions signs everyone out of every browser, including
// the administrator who asks.
func (s *Server) handleAdminEndAllSessions(w http.ResponseWriter, r *http.Request, p service.Principal) {
	if err := s.svc.RequireFreshAdmin(r.Context(), p); err != nil {
		s.writeError(w, r, err)
		return
	}
	n, err := s.auth.EndEverySession(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.log.InfoContext(r.Context(), "audit", "event", "sessions.revoke_everyone", "user", p.UserID, "sessions", n)
	http.SetCookie(w, s.auth.EndSession(r))
	writeJSON(w, http.StatusOK, map[string]int64{"sessions": n})
}

// ---- first-time setup ------------------------------------------------------------------
// The setup token travels in the request body, never in a URL: the setup
// page reads it from the URL fragment, which browsers do not send.

type setupReq struct {
	Token    string            `json:"token"`
	Revision int64             `json:"revision"`
	Set      map[string]string `json:"set"`
	Confirm  []string          `json:"confirm"`
	Method   string            `json:"method"`
}

func (s *Server) handleSetupView(w http.ResponseWriter, r *http.Request) {
	var req setupReq
	if err := s.decodeSetup(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	v, err := s.settings.SetupView(r.Context(), req.Token)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleSetupSave(w http.ResponseWriter, r *http.Request) {
	var req setupReq
	if err := s.decodeSetup(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	v, err := s.settings.SetupSave(r.Context(), req.Token,
		settings.UpdateRequest{Revision: req.Revision, Set: req.Set, Confirm: req.Confirm})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// handleSetupLogin starts the sign-in that finishes setup. It answers with
// the IdP URL (and the login cookie) rather than redirecting, because the
// token has to come in a POST body.
func (s *Server) handleSetupLogin(w http.ResponseWriter, r *http.Request) {
	var req setupReq
	if err := s.decodeSetup(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	hash, err := s.settings.SetupLogin(r.Context(), req.Token)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	o := auth.LoginOptions{ReturnTo: "/admin", Reauth: true, Setup: hash}
	var to string
	var cookie *http.Cookie
	switch req.Method {
	case "oidc":
		to, cookie, err = s.auth.BeginLogin(r.Context(), o)
	case "saml":
		to, cookie, err = s.auth.BeginSAMLLogin(r.Context(), o)
	default:
		err = domain.E(domain.CodeInvalid, "method must be oidc or saml")
	}
	if err != nil {
		if domain.CodeOf(err) == "" {
			s.log.ErrorContext(r.Context(), "setup sign-in unavailable", "err", err)
			err = domain.E(domain.CodePrecondition, "sign-in is not available yet; check the identity provider settings")
		}
		s.writeError(w, r, err)
		return
	}
	http.SetCookie(w, cookie)
	writeJSON(w, http.StatusOK, map[string]string{"redirect": to})
}

func (s *Server) decodeSetup(w http.ResponseWriter, r *http.Request, req *setupReq) error {
	if s.settings == nil {
		return errNoSettings
	}
	return decodeJSONLimit(w, r, req, maxSettingsBody)
}
