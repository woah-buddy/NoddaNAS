package httpapi

import (
	"encoding/xml"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/woah-buddy/FrontDir/internal/auth"
	"github.com/woah-buddy/FrontDir/internal/domain"
	"github.com/woah-buddy/FrontDir/internal/service"
)

// ---- sign-in ------------------------------------------------------------------------

func (s *Server) handleAuthMethods(w http.ResponseWriter, r *http.Request) {
	oidc, saml := s.auth.Methods()
	writeJSON(w, http.StatusOK, map[string]bool{"oidc": oidc, "saml": saml, "setup": !oidc && !saml})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	u, cookie, err := s.auth.BeginLogin(r.Context(), auth.LoginOptions{ReturnTo: r.URL.Query().Get("return_to")})
	s.redirectToIdP(w, r, u, cookie, err)
}

func (s *Server) handleSAMLLogin(w http.ResponseWriter, r *http.Request) {
	u, cookie, err := s.auth.BeginSAMLLogin(r.Context(), auth.LoginOptions{ReturnTo: r.URL.Query().Get("return_to")})
	s.redirectToIdP(w, r, u, cookie, err)
}

// handleReauth sends a signed-in person back to their identity provider to
// authenticate again ("confirm it's you"), through the method their account
// came from.
func (s *Server) handleReauth(w http.ResponseWriter, r *http.Request, p service.Principal) {
	u, err := s.svc.UserByID(r.Context(), p.UserID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	o := auth.LoginOptions{ReturnTo: r.URL.Query().Get("return_to"), Reauth: true}
	var to string
	var cookie *http.Cookie
	if strings.HasPrefix(u.Issuer, "saml:") {
		to, cookie, err = s.auth.BeginSAMLLogin(r.Context(), o)
	} else {
		to, cookie, err = s.auth.BeginLogin(r.Context(), o)
	}
	s.redirectToIdP(w, r, to, cookie, err)
}

func (s *Server) redirectToIdP(w http.ResponseWriter, r *http.Request, u string, cookie *http.Cookie, err error) {
	if err != nil {
		s.log.ErrorContext(r.Context(), "sign-in unavailable", "err", err, "request_id", requestID(r.Context()))
		http.Error(w, "Sign-in is temporarily unavailable.", http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, cookie)
	// u is the IdP's authorization URL, built by the auth manager from the
	// configured issuer or SAML metadata; nothing in it comes from the request
	// except the validated return path, which stays server-side.
	http.Redirect(w, r, u, http.StatusFound) // #nosec G710 -- see above
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, auth.ClearLoginCookie())
	res, err := s.auth.CompleteLogin(r)
	s.finishLogin(w, r, res, err, "oidc")
}

func (s *Server) handleSAMLACS(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, auth.ClearSAMLCookie())
	res, err := s.auth.CompleteSAMLLogin(r)
	s.finishLogin(w, r, res, err, "saml")
}

func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, res *auth.LoginResult, err error, method string) {
	if err != nil {
		s.log.WarnContext(r.Context(), "audit", "event", "login.failed", "method", method, "err", err,
			"request_id", requestID(r.Context()), "ip", s.clientIP(r).String())
		reason := "signin"
		if errors.Is(err, auth.ErrNotAllowed) {
			reason = "not_allowed"
		}
		http.Redirect(w, r, "/?error="+reason, http.StatusSeeOther)
		return
	}
	if res.Setup != "" && s.settings != nil {
		// Signed in through the setup link: this person becomes the first
		// administrator (if nobody beat them to it).
		if _, err := s.settings.ClaimSetup(r.Context(), res.Setup, res.User.ID); err != nil {
			s.writeError(w, r, err)
			return
		}
		if res.User, err = s.svc.UserByID(r.Context(), res.User.ID); err != nil {
			s.writeError(w, r, err)
			return
		}
	}
	_ = s.auth.EndSession(r) // never reuse a pre-existing session
	cookie, err := s.auth.StartSession(r.Context(), res)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.log.InfoContext(r.Context(), "audit", "event", "login.success", "method", method, "user", res.User.ID,
		"reauth", !res.ReauthAt.IsZero(), "ip", s.clientIP(r).String())
	http.SetCookie(w, cookie)
	http.Redirect(w, r, res.ReturnTo, http.StatusSeeOther)
}

func (s *Server) handleSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	md, err := s.auth.SAMLMetadata(r.Context())
	if err != nil || md == nil {
		http.NotFound(w, r)
		return
	}
	out, err := xml.MarshalIndent(md, "", "  ")
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	if _, err := w.Write(append([]byte(xml.Header), out...)); err != nil {
		s.log.DebugContext(r.Context(), "write SAML metadata", "err", err)
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, s.auth.EndSession(r))
	writeJSON(w, http.StatusOK, map[string]string{"logoutUrl": s.auth.LogoutURL(r.Context())})
}

// ---- account & keys --------------------------------------------------------------

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, p service.Principal) {
	u, sp, err := s.svc.Me(r.Context(), p)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":          userView{ID: u.ID, Email: u.Email, DisplayName: u.DisplayName, Admin: u.Admin, Keys: viewKeys(u.Keys)},
		"personalSpace": viewSpace(sp, domain.RoleManage, nil),
		"readOnly":      p.ReadOnly,
	})
}

func (s *Server) handleGetKeys(w http.ResponseWriter, r *http.Request, p service.Principal) {
	b, err := s.svc.KeyBundle(r.Context(), p)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"bundle": b})
}

type spaceKeysReq struct {
	PublicKey string `json:"publicKey"`
	KeySig    string `json:"keySig"`
	RootKey   string `json:"rootKey"`
}

func (k spaceKeysReq) toService() service.SpaceKeys {
	return service.SpaceKeys{PublicKey: k.PublicKey, KeySig: k.KeySig, RootKey: k.RootKey}
}

// handleSetupKeys stores the first key bundle (interactive session only).
func (s *Server) handleSetupKeys(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req struct {
		Bundle        string       `json:"bundle"`
		PersonalSpace spaceKeysReq `json:"personalSpace"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.svc.SetupKeys(r.Context(), p, req.Bundle, req.PersonalSpace.toService()); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleUpdateKeys replaces the bundle, e.g. after a passphrase change.
func (s *Server) handleUpdateKeys(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req struct {
		Bundle string `json:"bundle"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.svc.UpdateKeyBundle(r.Context(), p, req.Bundle); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func publicUserView(u *service.PublicUser) userView {
	return userView{ID: u.ID, Email: u.Email, DisplayName: u.DisplayName, Keys: viewKeys(u.Keys)}
}

func (s *Server) handleUserKeys(w http.ResponseWriter, r *http.Request, p service.Principal) {
	u, err := s.svc.UserKeys(r.Context(), p, r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, publicUserView(u))
}

func (s *Server) handleLookupUser(w http.ResponseWriter, r *http.Request, p service.Principal) {
	u, err := s.svc.LookupUser(r.Context(), p, r.URL.Query().Get("email"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, publicUserView(u))
}

// ---- app passwords and sessions ------------------------------------------------------

type appPasswordView struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	ReadOnly   bool       `json:"readOnly"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
}

func viewAppPassword(a *domain.AppPassword) appPasswordView {
	return appPasswordView{ID: a.ID, Name: a.Name, ReadOnly: a.ReadOnly, CreatedAt: a.CreatedAt, LastUsedAt: a.LastUsedAt, ExpiresAt: a.ExpiresAt}
}

func (s *Server) handleListAppPasswords(w http.ResponseWriter, r *http.Request, p service.Principal) {
	aps, err := s.auth.ListAppPasswords(r.Context(), p.UserID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	out := make([]appPasswordView, len(aps))
	for i, a := range aps {
		out[i] = viewAppPassword(a)
	}
	writeJSON(w, http.StatusOK, map[string]any{"appPasswords": out})
}

func (s *Server) handleCreateAppPassword(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req struct {
		Name          string `json:"name"`
		ReadOnly      bool   `json:"readOnly"`
		ExpiresInDays int    `json:"expiresInDays"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	ap, token, err := s.auth.CreateAppPassword(r.Context(), p.UserID, req.Name, req.ReadOnly, time.Duration(req.ExpiresInDays)*24*time.Hour)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.log.InfoContext(r.Context(), "audit", "event", "app_password.create", "user", p.UserID, "id", ap.ID, "read_only", ap.ReadOnly)
	writeJSON(w, http.StatusCreated, map[string]any{"appPassword": viewAppPassword(ap), "token": token})
}

func (s *Server) handleRevokeAppPassword(w http.ResponseWriter, r *http.Request, p service.Principal) {
	if err := s.auth.RevokeAppPassword(r.Context(), p.UserID, r.PathValue("id")); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.log.InfoContext(r.Context(), "audit", "event", "app_password.revoke", "user", p.UserID, "id", r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRevokeAllSessions(w http.ResponseWriter, r *http.Request, p service.Principal) {
	if err := s.auth.EndAllSessions(r.Context(), p.UserID); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.log.InfoContext(r.Context(), "audit", "event", "sessions.revoke_all", "user", p.UserID)
	http.SetCookie(w, s.auth.EndSession(r))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetContacts(w http.ResponseWriter, r *http.Request, p service.Principal) {
	sealed, rev, err := s.svc.Contacts(r.Context(), p)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"contacts": sealed, "revision": rev})
}

func (s *Server) handleSetContacts(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req struct {
		Contacts string `json:"contacts"`
		Revision int64  `json:"revision"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	rev, err := s.svc.SetContacts(r.Context(), p, req.Contacts, req.Revision)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"revision": rev})
}
