// Package auth authenticates callers and turns them into service.Principals.
//
// NoddaNAS deliberately does not store user passwords or implement MFA. It
// delegates sign-in to an external OpenID Connect provider (Keycloak,
// Authentik, Zitadel, Pocket ID, Entra ID, Google, ...), which already does
// those things well. Two credential types exist on the NoddaNAS side:
//
//   - Browser sessions (backend-for-frontend pattern): the server completes
//     the OIDC code flow itself (PKCE + state + nonce) and gives the browser
//     only an opaque, HttpOnly, Secure, SameSite cookie. No OAuth token ever
//     reaches JavaScript, so an XSS bug cannot steal a long-lived credential.
//   - App passwords for non-browser clients (WebDAV, CLI, sync tools):
//     random 256-bit tokens, stored hashed, revocable, optionally read-only.
//     They are created only from an interactive session, so a leaked app
//     password cannot be used to mint more of them.
package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/woah-buddy/NoddaNAS/internal/domain"
	"github.com/woah-buddy/NoddaNAS/internal/secure"
	"github.com/woah-buddy/NoddaNAS/internal/service"
)

// LoginRequest is the server-side state of an in-progress OIDC login.
type LoginRequest struct {
	TokenHash string
	State     string
	Nonce     string
	Verifier  string // PKCE code verifier
	ReturnTo  string
	ExpiresAt time.Time
}

// Session is a browser session.
type Session struct {
	TokenHash  string
	UserID     string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time // absolute expiry
}

// Store persists authentication state.
type Store interface {
	CreateLoginRequest(ctx context.Context, r *LoginRequest) error
	ConsumeLoginRequest(ctx context.Context, tokenHash string, now time.Time) (*LoginRequest, error)
	CreateSession(ctx context.Context, s *Session) error
	GetSession(ctx context.Context, tokenHash string) (*Session, error)
	TouchSession(ctx context.Context, tokenHash string, now time.Time) error
	DeleteSession(ctx context.Context, tokenHash string) error
	DeleteUserSessions(ctx context.Context, userID string) error
	CreateAppPassword(ctx context.Context, ap *domain.AppPassword) error
	GetAppPassword(ctx context.Context, tokenHash string) (*domain.AppPassword, error)
	TouchAppPassword(ctx context.Context, id string, now time.Time) error
	ListAppPasswords(ctx context.Context, userID string) ([]*domain.AppPassword, error)
	DeleteAppPassword(ctx context.Context, userID, id string) error
	DeleteExpiredAuth(ctx context.Context, now time.Time) error
}

// Cookie names use the __Host- prefix, which browsers only accept for
// cookies that are Secure, host-only (no Domain) and Path=/. That stops a
// sibling subdomain from planting or overwriting them.
const (
	SessionCookie = "__Host-ndn_session"
	LoginCookie   = "__Host-ndn_login"
)

// Config controls session lifetimes.
type Config struct {
	SessionIdle     time.Duration // sign out after this much inactivity
	SessionAbsolute time.Duration // and after this long regardless
}

// Method records how a request authenticated. Cookie-authenticated requests
// need CSRF protection; header-authenticated ones do not, because a browser
// never attaches an Authorization header to a cross-site request on its own.
type Method int

const (
	MethodNone Method = iota
	MethodSession
	MethodAppPassword
)

// Manager authenticates requests and manages sessions and app passwords.
type Manager struct {
	store Store
	svc   *service.Service
	cfg   Config
	oidc  *OIDC
	now   func() time.Time
}

// NewManager wires a Manager. oidc may be nil (e.g. in tests).
func NewManager(store Store, svc *service.Service, cfg Config, oidc *OIDC) *Manager {
	return &Manager{store: store, svc: svc, cfg: cfg, oidc: oidc, now: func() time.Time { return time.Now().UTC() }}
}

// ErrBadCredentials is returned when presented credentials are invalid.
var ErrBadCredentials = domain.E(domain.CodeUnauthorized, "invalid or expired credentials")

// Authenticate identifies the caller. It returns MethodNone (and no error)
// for anonymous requests; presenting bad credentials is always an error,
// never a silent downgrade to anonymous.
func (m *Manager) Authenticate(r *http.Request) (service.Principal, Method, error) {
	if h := r.Header.Get("Authorization"); h != "" {
		token, ok := bearerOrBasic(h)
		if !ok {
			return service.Principal{}, MethodNone, ErrBadCredentials
		}
		p, err := m.appPassword(r.Context(), token)
		return p, MethodAppPassword, err
	}
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return service.Principal{}, MethodNone, nil
	}
	p, err := m.session(r.Context(), c.Value)
	return p, MethodSession, err
}

func bearerOrBasic(h string) (string, bool) {
	scheme, rest, ok := strings.Cut(h, " ")
	if !ok {
		return "", false
	}
	switch strings.ToLower(scheme) {
	case "bearer":
		return strings.TrimSpace(rest), true
	case "basic":
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest))
		if err != nil {
			return "", false
		}
		// The username is ignored: the app password alone identifies the
		// account, and accepting any username keeps WebDAV clients simple.
		_, pass, ok := strings.Cut(string(raw), ":")
		return pass, ok
	}
	return "", false
}

func (m *Manager) appPassword(ctx context.Context, token string) (service.Principal, error) {
	if !secure.ValidAppPassword(token) {
		return service.Principal{}, ErrBadCredentials
	}
	ap, err := m.store.GetAppPassword(ctx, secure.HashToken(secure.PurposeAppPassword, token))
	if errors.Is(err, domain.ErrNotFound) {
		return service.Principal{}, ErrBadCredentials
	} else if err != nil {
		return service.Principal{}, err
	}
	now := m.now()
	if ap.ExpiresAt != nil && !now.Before(*ap.ExpiresAt) {
		return service.Principal{}, ErrBadCredentials
	}
	if ap.LastUsedAt == nil || now.Sub(*ap.LastUsedAt) > 5*time.Minute {
		_ = m.store.TouchAppPassword(ctx, ap.ID, now)
	}
	return service.Principal{UserID: ap.UserID, ReadOnly: ap.ReadOnly}, nil
}

func (m *Manager) session(ctx context.Context, token string) (service.Principal, error) {
	if !secure.ValidToken(token) {
		return service.Principal{}, ErrBadCredentials
	}
	h := secure.HashToken(secure.PurposeSession, token)
	s, err := m.store.GetSession(ctx, h)
	if errors.Is(err, domain.ErrNotFound) {
		return service.Principal{}, ErrBadCredentials
	} else if err != nil {
		return service.Principal{}, err
	}
	now := m.now()
	if !now.Before(s.ExpiresAt) || now.Sub(s.LastSeenAt) > m.cfg.SessionIdle {
		_ = m.store.DeleteSession(ctx, h)
		return service.Principal{}, ErrBadCredentials
	}
	if now.Sub(s.LastSeenAt) > time.Minute {
		_ = m.store.TouchSession(ctx, h, now)
	}
	return service.Principal{UserID: s.UserID}, nil
}

// StartSession creates a new session for userID and returns its cookie.
// A fresh random token is minted on every login, which prevents session
// fixation.
func (m *Manager) StartSession(ctx context.Context, userID string) (*http.Cookie, error) {
	token := secure.NewToken()
	now := m.now()
	s := &Session{
		TokenHash: secure.HashToken(secure.PurposeSession, token), UserID: userID,
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(m.cfg.SessionAbsolute),
	}
	if err := m.store.CreateSession(ctx, s); err != nil {
		return nil, err
	}
	return &http.Cookie{
		Name: SessionCookie, Value: token, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: int(m.cfg.SessionAbsolute.Seconds()),
	}, nil
}

// EndSession deletes the session behind the request's cookie, if any, and
// returns a cookie that clears it in the browser.
func (m *Manager) EndSession(r *http.Request) *http.Cookie {
	if c, err := r.Cookie(SessionCookie); err == nil && secure.ValidToken(c.Value) {
		_ = m.store.DeleteSession(r.Context(), secure.HashToken(secure.PurposeSession, c.Value))
	}
	return &http.Cookie{Name: SessionCookie, Value: "", Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: -1}
}

// EndAllSessions signs the user out everywhere.
func (m *Manager) EndAllSessions(ctx context.Context, userID string) error {
	return m.store.DeleteUserSessions(ctx, userID)
}

// CreateAppPassword mints an app password. The token is returned once.
func (m *Manager) CreateAppPassword(ctx context.Context, userID, name string, readOnly bool, ttl time.Duration) (*domain.AppPassword, string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return nil, "", domain.E(domain.CodeInvalid, "name must be 1-100 characters")
	}
	if ttl < 0 || ttl > 5*365*24*time.Hour {
		return nil, "", domain.E(domain.CodeInvalid, "invalid lifetime")
	}
	token := secure.NewAppPassword()
	now := m.now()
	ap := &domain.AppPassword{
		ID: secure.NewID(), UserID: userID, Name: name, ReadOnly: readOnly, CreatedAt: now,
		TokenHash: secure.HashToken(secure.PurposeAppPassword, token),
	}
	if ttl > 0 {
		exp := now.Add(ttl)
		ap.ExpiresAt = &exp
	}
	if err := m.store.CreateAppPassword(ctx, ap); err != nil {
		return nil, "", err
	}
	return ap, token, nil
}

// ListAppPasswords lists a user's app passwords (never their secrets).
func (m *Manager) ListAppPasswords(ctx context.Context, userID string) ([]*domain.AppPassword, error) {
	return m.store.ListAppPasswords(ctx, userID)
}

// RevokeAppPassword deletes one of the user's app passwords.
func (m *Manager) RevokeAppPassword(ctx context.Context, userID, id string) error {
	return m.store.DeleteAppPassword(ctx, userID, id)
}

// Cleanup removes expired sessions, login requests and app passwords.
func (m *Manager) Cleanup(ctx context.Context) error {
	return m.store.DeleteExpiredAuth(ctx, m.now())
}
