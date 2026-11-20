// Package auth authenticates callers and turns them into service.Principals.
//
// Sign-in is preferably delegated to an external identity provider (OpenID
// Connect: Keycloak, Authentik, Zitadel, Pocket ID, Entra ID, Google, ...;
// or SAML), which already does it well. For people without an account
// there, or servers without one, optional local accounts (local.go) sign
// in with a password and a one-time code from an authenticator app, both
// always required. Two credential types exist on the FrontDir side:
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
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	"github.com/woah-buddy/FrontDir/internal/domain"
	"github.com/woah-buddy/FrontDir/internal/secure"
	"github.com/woah-buddy/FrontDir/internal/service"
)

// LoginRequest is the server-side state of an in-progress sign-in.
type LoginRequest struct {
	TokenHash string
	Kind      string // "oidc" or "saml"
	State     string
	Nonce     string
	Verifier  string // PKCE code verifier
	ReturnTo  string
	Reauth    bool   // the IdP was asked for a fresh authentication
	Setup     string // hash of the setup token this sign-in completes, if any
	ExpiresAt time.Time
}

// loginTTL bounds how long a sign-in may take at the IdP.
const loginTTL = 10 * time.Minute

// Started is when the sign-in began.
func (r *LoginRequest) Started() time.Time { return r.ExpiresAt.Add(-loginTTL) }

// LoginOptions shape a sign-in.
type LoginOptions struct {
	ReturnTo string
	// Reauth asks the IdP to authenticate the person again even if they
	// have a session there (OIDC prompt=login and max_age=0, SAML
	// ForceAuthn), and checks that it did. A session started this way
	// counts as a recent sign-in, which sensitive actions require.
	Reauth bool
	Setup  string // hash of a setup token (see the settings package)
}

// LoginResult is a completed sign-in.
type LoginResult struct {
	User     *domain.User
	ReturnTo string
	ReauthAt time.Time // when the IdP confirmed a fresh authentication (zero if not asked)
	Setup    string    // the setup token hash from LoginOptions
}

// Session is a browser session.
type Session struct {
	TokenHash  string
	UserID     string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time  // absolute expiry
	ReauthAt   *time.Time // when the person last re-authenticated at the IdP on request
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
	DeleteAllSessions(ctx context.Context) (int64, error)
	CreateAppPassword(ctx context.Context, ap *domain.AppPassword) error
	GetAppPassword(ctx context.Context, tokenHash string) (*domain.AppPassword, error)
	TouchAppPassword(ctx context.Context, id string, now time.Time) error
	ListAppPasswords(ctx context.Context, userID string) ([]*domain.AppPassword, error)
	DeleteAppPassword(ctx context.Context, userID, id string) error
	DeleteUserAppPasswords(ctx context.Context, userID string) (int64, error)
	DeleteExpiredAuth(ctx context.Context, now time.Time) error
}

// Cookie names use the __Host- prefix, which browsers only accept for
// cookies that are Secure, host-only (no Domain) and Path=/. That stops a
// sibling subdomain from planting or overwriting them.
const (
	SessionCookie = "__Host-fd_session"
	LoginCookie   = "__Host-fd_login"
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
//
// Its configuration (session lifetimes, sign-in methods) can be replaced
// while the server runs; each request works with one consistent snapshot.
type Manager struct {
	store  Store
	svc    *service.Service
	log    *slog.Logger
	clock  atomic.Pointer[func() time.Time]
	state  atomic.Pointer[authState]
	sealer atomic.Pointer[secure.Sealer] // encrypts local accounts' TOTP secrets
}

type authState struct {
	cfg  Config
	oidc *OIDC
	saml *SAML
}

// NewManager wires a Manager. Either sign-in method may be nil; with
// neither, the server is in setup mode.
func NewManager(store Store, svc *service.Service, cfg Config, oidc *OIDC, saml *SAML) *Manager {
	m := &Manager{store: store, svc: svc, log: slog.Default()}
	m.state.Store(&authState{cfg: cfg, oidc: oidc, saml: saml})
	return m
}

func (m *Manager) st() *authState { return m.state.Load() }

// SetClock replaces the manager's clock. Tests use it to hold time still
// across one-time-code steps.
func (m *Manager) SetClock(now func() time.Time) { m.clock.Store(&now) }

func (m *Manager) now() time.Time {
	if c := m.clock.Load(); c != nil {
		return (*c)()
	}
	return time.Now().UTC()
}

// Reconfigure replaces session lifetimes and sign-in methods. A method
// whose configuration did not change keeps its client (and the IdP
// metadata it has fetched). Sign-ins already under way with a method that
// changed fail and can simply be started again.
func (m *Manager) Reconfigure(cfg Config, oidc *OIDCConfig, saml *SAMLConfig) {
	cur := m.st()
	next := &authState{cfg: cfg}
	if oidc != nil {
		if cur.oidc != nil && reflect.DeepEqual(cur.oidc.raw, *oidc) {
			next.oidc = cur.oidc
		} else {
			next.oidc = NewOIDC(*oidc)
		}
	}
	if saml != nil {
		if cur.saml != nil && reflect.DeepEqual(cur.saml.raw, *saml) {
			next.saml = cur.saml
		} else {
			next.saml = NewSAML(*saml)
		}
	}
	m.state.Store(next)
}

// Methods reports which sign-in methods are configured.
func (m *Manager) Methods() (oidc, saml bool) {
	st := m.st()
	return st.oidc != nil, st.saml != nil
}

// SAMLMetadata returns the SP metadata (nil, nil if SAML is not configured).
func (m *Manager) SAMLMetadata(ctx context.Context) (any, error) {
	st := m.st()
	if st.saml == nil {
		return nil, nil
	}
	return st.saml.Metadata(ctx)
}

// SAMLIdPEntityID returns the entity ID of the configured SAML IdP ("" if
// SAML is off).
func (m *Manager) SAMLIdPEntityID(ctx context.Context) (string, error) {
	st := m.st()
	if st.saml == nil {
		return "", nil
	}
	sp, err := st.saml.provider(ctx)
	if err != nil {
		return "", err
	}
	return sp.IDPMetadata.EntityID, nil
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
	// Lifetimes are checked against the current settings, so shortening
	// them takes effect for existing sessions too.
	cfg := m.st().cfg
	if !now.Before(s.ExpiresAt) || !now.Before(s.CreatedAt.Add(cfg.SessionAbsolute)) || now.Sub(s.LastSeenAt) > cfg.SessionIdle {
		_ = m.store.DeleteSession(ctx, h)
		return service.Principal{}, ErrBadCredentials
	}
	if now.Sub(s.LastSeenAt) > time.Minute {
		_ = m.store.TouchSession(ctx, h, now)
	}
	p := service.Principal{UserID: s.UserID}
	if s.ReauthAt != nil {
		p.ReauthAt = *s.ReauthAt
	}
	return p, nil
}

// StartSession creates a new session for a completed sign-in and returns
// its cookie. A fresh random token is minted on every sign-in, which
// prevents session fixation.
func (m *Manager) StartSession(ctx context.Context, res *LoginResult) (*http.Cookie, error) {
	token := secure.NewToken()
	now := m.now()
	cfg := m.st().cfg
	s := &Session{
		TokenHash: secure.HashToken(secure.PurposeSession, token), UserID: res.User.ID,
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(cfg.SessionAbsolute),
	}
	if !res.ReauthAt.IsZero() {
		at := res.ReauthAt
		s.ReauthAt = &at
	}
	if err := m.store.CreateSession(ctx, s); err != nil {
		return nil, err
	}
	return &http.Cookie{
		Name: SessionCookie, Value: token, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: int(cfg.SessionAbsolute.Seconds()),
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

// RevokeUserCredentials ends every session and deletes every app password
// of a user (operator offboarding). For a local account it also removes
// the password and authenticator, so it cannot sign in again until reset;
// for an identity-provider account, new sign-ins are the provider's
// decision, so remove the user there first.
func (m *Manager) RevokeUserCredentials(ctx context.Context, userID string) (appPasswords int64, err error) {
	if userID == "" {
		return 0, domain.E(domain.CodeInvalid, "user required")
	}
	if err := m.DisableLocal(ctx, userID); err != nil {
		return 0, err
	}
	if err := m.store.DeleteUserSessions(ctx, userID); err != nil {
		return 0, err
	}
	return m.store.DeleteUserAppPasswords(ctx, userID)
}

// EndEverySession signs every user out of every browser (for example after
// restoring a backup, which brings back sessions that had since ended).
// Users sign in again through the identity provider, which applies its
// current rules. App passwords are not affected.
func (m *Manager) EndEverySession(ctx context.Context) (int64, error) {
	return m.store.DeleteAllSessions(ctx)
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
