package httpapi

import (
	"encoding/base64"
	"net/http"
	"time"

	"rsc.io/qr"

	"github.com/woah-buddy/FrontDir/internal/auth"
	"github.com/woah-buddy/FrontDir/internal/domain"
	"github.com/woah-buddy/FrontDir/internal/service"
)

// Local accounts (internal/auth/local.go): email, password and a one-time
// code. All of these answer JSON (the web app drives them); tokens travel
// in bodies, never in URLs.

// startSession begins a session for a completed sign-in.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, res *auth.LoginResult, method string) error {
	_ = s.auth.EndSession(r) // never reuse a pre-existing session
	cookie, err := s.auth.StartSession(r.Context(), res)
	if err != nil {
		return err
	}
	s.log.InfoContext(r.Context(), "audit", "event", "login.success", "method", method, "user", res.User.ID,
		"reauth", !res.ReauthAt.IsZero(), "ip", s.clientIP(r).String())
	http.SetCookie(w, cookie)
	return nil
}

func (s *Server) localFailed(r *http.Request, err error) {
	s.log.WarnContext(r.Context(), "audit", "event", "login.failed", "method", "local", "err", err,
		"request_id", requestID(r.Context()), "ip", s.clientIP(r).String())
}

func (s *Server) handleLocalLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	ticket, err := s.auth.StartLocalLogin(r.Context(), req.Email, req.Password)
	if err != nil {
		s.localFailed(r, err)
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ticket": ticket})
}

func (s *Server) handleLocalCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Ticket string `json:"ticket"`
		Code   string `json:"code"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	res, err := s.auth.FinishLocalLogin(r.Context(), req.Ticket, req.Code)
	if err == nil {
		err = s.startSession(w, r, res, "local")
	}
	if err != nil {
		s.localFailed(r, err)
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleLocalInvite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	in, err := s.auth.OpenLocalInvite(r.Context(), req.Token)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"email": in.User.Email, "displayName": in.User.DisplayName, "reset": in.Reset})
}

func (s *Server) handleLocalEnroll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	en, err := s.auth.StartLocalEnroll(r.Context(), req.Token, req.Password, s.cfg.PublicURL.Host)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	// The QR code is drawn here (the web app has no build step to bring an
	// encoder); the page shows it from a blob, so it needs no CSP change.
	code, err := qr.Encode(en.URI, qr.M)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	code.Scale = 6
	writeJSON(w, http.StatusOK, map[string]string{"ticket": en.Token, "uri": en.URI, "secret": en.Secret,
		"qr": base64.StdEncoding.EncodeToString(code.PNG())})
}

func (s *Server) handleLocalEnrollFinish(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Ticket string `json:"ticket"`
		Code   string `json:"code"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	res, codes, err := s.auth.FinishLocalEnroll(r.Context(), req.Ticket, req.Code)
	if err == nil {
		err = s.startSession(w, r, res, "local")
	}
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recoveryCodes": codes})
}

// handleLocalReauth is "confirm it's you" for local accounts: password and
// a one-time code, instead of a trip to an identity provider.
func (s *Server) handleLocalReauth(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	c, err := r.Cookie(auth.SessionCookie)
	if err != nil {
		s.writeError(w, r, auth.ErrBadCredentials)
		return
	}
	if err := s.auth.LocalReauth(r.Context(), c.Value, p.UserID, req.Password, req.Code); err != nil {
		s.localFailed(r, err)
		s.writeError(w, r, err)
		return
	}
	s.log.InfoContext(r.Context(), "audit", "event", "login.reauth", "method", "local", "user", p.UserID)
	w.WriteHeader(http.StatusNoContent)
}

type inviteView struct {
	UserID    string    `json:"userId"`
	Token     string    `json:"token"` // goes after /invite# ; shown once
	ExpiresAt time.Time `json:"expiresAt"`
}

func (s *Server) handleAdminCreateLocal(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req struct {
		Email       string `json:"email"`
		DisplayName string `json:"displayName"`
		Admin       bool   `json:"admin"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	if !s.auth.LocalEnabled() {
		s.writeError(w, r, domain.E(domain.CodePrecondition, "local accounts are not enabled (Admin → Settings → Local accounts)"))
		return
	}
	u, err := s.svc.AdminCreateLocalUser(r.Context(), p, req.Email, req.DisplayName, req.Admin)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	token, exp, err := s.auth.NewLocalInvite(r.Context(), u, p.UserID, false)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, inviteView{UserID: u.ID, Token: token, ExpiresAt: exp})
}

// handleAdminLocalReset stops a local account's sign-in at once (password,
// authenticator, recovery codes, sessions) and returns a link to set new
// ones.
func (s *Server) handleAdminLocalReset(w http.ResponseWriter, r *http.Request, p service.Principal) {
	u, err := s.svc.AdminLocalUser(r.Context(), p, r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	token, exp, err := s.auth.NewLocalInvite(r.Context(), u, p.UserID, true)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, inviteView{UserID: u.ID, Token: token, ExpiresAt: exp})
}

// handleSetupLocal finishes setup with a local administrator: the setup
// link turns local accounts on, creates the account and returns its invite.
func (s *Server) handleSetupLocal(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token       string `json:"token"`
		Email       string `json:"email"`
		DisplayName string `json:"displayName"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	if s.settings == nil {
		s.writeError(w, r, domain.ErrNotFound)
		return
	}
	u, err := s.settings.SetupLocal(r.Context(), req.Token, req.Email, req.DisplayName)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	token, exp, err := s.auth.NewLocalInvite(r.Context(), u, "setup-link", false)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, inviteView{UserID: u.ID, Token: token, ExpiresAt: exp})
}
