// Package httpapi exposes NoddaNAS over HTTP: the JSON API used by the web
// UI and scripts, browser sign-in, public links, WebDAV, and the static UI.
package httpapi

import (
	"context"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"

	"github.com/woah-buddy/NoddaNAS/internal/auth"
	"github.com/woah-buddy/NoddaNAS/internal/service"
	"github.com/woah-buddy/NoddaNAS/internal/theme"
)

// Config configures the HTTP layer.
type Config struct {
	// PublicURL is the externally visible origin, e.g. https://files.example.com.
	// It must be HTTPS (except for localhost) and is used for Host checks,
	// CSRF origin checks and OIDC redirects.
	PublicURL *url.URL
	// TrustedProxies lists reverse proxies whose X-Forwarded-For is believed.
	TrustedProxies []netip.Prefix
	// EnableWebDAV mounts the WebDAV endpoint at /dav/.
	EnableWebDAV bool
	// Per-IP rate limits (requests per minute). Zero means the default.
	RateLimits RateLimits
	// Theme is the validated branding and appearance; nil means the built-in theme.
	Theme *theme.Theme
}

// RateLimits are per-client-IP request budgets per minute.
type RateLimits struct {
	Public       int // anonymous endpoints (default 120)
	Login        int // sign-in flows (default 20)
	AuthFailures int // failed credential checks (default 30)
}

func orDefault(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

// Pinger is implemented by dependencies that readiness checks should probe.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Server is the HTTP front end.
type Server struct {
	svc          *service.Service
	auth         *auth.Manager
	cfg          Config
	log          *slog.Logger
	ui           fs.FS
	ready        []Pinger
	publicLimit  *limiter
	loginLimit   *limiter
	authFailures *limiter
	dav          http.Handler
	theme        *theme.Theme
}

// New builds the server. ui holds the static web client (may be nil).
func New(svc *service.Service, am *auth.Manager, cfg Config, log *slog.Logger, ui fs.FS, ready ...Pinger) *Server {
	s := &Server{
		svc: svc, auth: am, cfg: cfg, log: log, ui: ui, ready: ready,
		publicLimit:  newLimiter(orDefault(cfg.RateLimits.Public, 120), 30),
		loginLimit:   newLimiter(orDefault(cfg.RateLimits.Login, 20), 10),
		authFailures: newLimiter(orDefault(cfg.RateLimits.AuthFailures, 30), 10),
		theme:        cfg.Theme,
	}
	if s.theme == nil {
		s.theme = theme.Default()
	}
	if cfg.EnableWebDAV {
		s.dav = s.newDAV()
	}
	return s
}

// Handler returns the complete, middleware-wrapped HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Health. Liveness says "the process is up"; readiness says "dependencies
	// are reachable". Neither reveals details to the caller.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /readyz", s.handleReady)

	// Theming: generated stylesheet, branding metadata, sanitized logo.
	mux.HandleFunc("GET /theme.css", s.handleThemeCSS)
	mux.HandleFunc("GET /api/v1/branding", s.handleBranding)
	mux.HandleFunc("GET /branding/logo", s.handleLogo)

	// Sign-in: OIDC and/or SAML, then a server-side session.
	mux.HandleFunc("GET /api/v1/auth/methods", s.public(s.handleAuthMethods))
	mux.HandleFunc("GET /auth/login", s.rateLimited(s.loginLimit, s.handleLogin))
	mux.HandleFunc("GET /auth/callback", s.rateLimited(s.loginLimit, s.handleCallback))
	mux.HandleFunc("GET /auth/saml/login", s.rateLimited(s.loginLimit, s.handleSAMLLogin))
	mux.HandleFunc("POST /auth/saml/acs", s.rateLimited(s.loginLimit, s.handleSAMLACS))
	mux.HandleFunc("GET /auth/saml/metadata", s.public(s.handleSAMLMetadata))
	mux.HandleFunc("POST /auth/logout", s.handleLogout)

	// Account, E2EE keys and the public-key directory.
	mux.HandleFunc("GET /api/v1/me", s.authed(s.handleMe))
	mux.HandleFunc("GET /api/v1/keys", s.authed(s.handleGetKeys))
	mux.HandleFunc("POST /api/v1/keys", s.sessionOnly(s.handleSetupKeys))
	mux.HandleFunc("PUT /api/v1/keys", s.sessionOnly(s.handleUpdateKeys))
	mux.HandleFunc("GET /api/v1/users/lookup", s.authed(s.handleLookupUser))
	mux.HandleFunc("GET /api/v1/users/{id}/keys", s.authed(s.handleUserKeys))
	mux.HandleFunc("GET /api/v1/app-passwords", s.sessionOnly(s.handleListAppPasswords))
	mux.HandleFunc("POST /api/v1/app-passwords", s.sessionOnly(s.handleCreateAppPassword))
	mux.HandleFunc("DELETE /api/v1/app-passwords/{id}", s.sessionOnly(s.handleRevokeAppPassword))
	mux.HandleFunc("POST /api/v1/sessions/revoke-all", s.sessionOnly(s.handleRevokeAllSessions))

	// Spaces: personal space and team folders.
	mux.HandleFunc("GET /api/v1/spaces", s.authed(s.handleListSpaces))
	mux.HandleFunc("POST /api/v1/spaces", s.authed(s.handleCreateTeam))
	mux.HandleFunc("GET /api/v1/spaces/{id}", s.authed(s.handleGetSpace))
	mux.HandleFunc("PATCH /api/v1/spaces/{id}", s.authed(s.handleRenameTeam))
	mux.HandleFunc("DELETE /api/v1/spaces/{id}", s.authed(s.handleDeleteTeam))
	mux.HandleFunc("GET /api/v1/spaces/{id}/members", s.authed(s.handleListMembers))
	mux.HandleFunc("PUT /api/v1/spaces/{id}/members/{user}", s.authed(s.handleUpdateMember))
	mux.HandleFunc("DELETE /api/v1/spaces/{id}/members/{user}", s.authed(s.handleRemoveMember))
	mux.HandleFunc("GET /api/v1/spaces/{id}/groups", s.authed(s.handleListGroups))
	mux.HandleFunc("PUT /api/v1/spaces/{id}/groups/{group}", s.authed(s.handleSetGroup))
	mux.HandleFunc("DELETE /api/v1/spaces/{id}/groups/{group}", s.authed(s.handleDeleteGroup))
	mux.HandleFunc("PUT /api/v1/spaces/{id}/quota", s.authed(s.handleSetQuota))
	mux.HandleFunc("GET /api/v1/spaces/{id}/trash", s.authed(s.handleListTrash))
	mux.HandleFunc("DELETE /api/v1/spaces/{id}/trash", s.authed(s.handleEmptyTrash))
	mux.HandleFunc("GET /api/v1/admin/spaces", s.authed(s.handleAdminListTeams))

	// Files and folders (names, keys and content are client-encrypted).
	mux.HandleFunc("GET /api/v1/nodes/{id}", s.authed(s.handleGetNode))
	mux.HandleFunc("GET /api/v1/nodes/{id}/path", s.authed(s.handleNodePath))
	mux.HandleFunc("GET /api/v1/nodes/{id}/children", s.authed(s.handleListChildren))
	mux.HandleFunc("POST /api/v1/nodes/{id}/folders", s.authed(s.handleCreateFolder))
	mux.HandleFunc("POST /api/v1/nodes/{id}/files", s.authed(s.handleUploadFile))
	mux.HandleFunc("PUT /api/v1/nodes/{id}/content", s.authed(s.handleUploadVersion))
	mux.HandleFunc("GET /api/v1/nodes/{id}/content", s.authed(s.handleDownload))
	mux.HandleFunc("PATCH /api/v1/nodes/{id}", s.authed(s.handleUpdateNode))
	mux.HandleFunc("POST /api/v1/nodes/{id}/trash", s.authed(s.handleTrashNode))
	mux.HandleFunc("GET /api/v1/nodes/{id}/versions", s.authed(s.handleListVersions))
	mux.HandleFunc("POST /api/v1/nodes/{id}/versions/{vid}/restore", s.authed(s.handleRestoreVersion))
	mux.HandleFunc("POST /api/v1/trash/{id}/restore", s.authed(s.handleRestoreTrash))
	mux.HandleFunc("DELETE /api/v1/trash/{id}", s.authed(s.handleDeleteTrash))

	// Sharing.
	mux.HandleFunc("GET /api/v1/nodes/{id}/shares", s.authed(s.handleListShares))
	mux.HandleFunc("POST /api/v1/nodes/{id}/shares", s.authed(s.handleCreateShare))
	mux.HandleFunc("DELETE /api/v1/shares/{id}", s.authed(s.handleDeleteShare))
	mux.HandleFunc("GET /api/v1/shared-with-me", s.authed(s.handleSharedWithMe))

	// Public links (anonymous). The access token travels in request bodies,
	// never URLs; the key that decrypts never reaches the server at all.
	mux.HandleFunc("POST /api/v1/public/node", s.public(s.handlePublicNode))
	mux.HandleFunc("POST /api/v1/public/download", s.public(s.handlePublicDownload))
	mux.HandleFunc("POST /api/v1/public/signer", s.public(s.handlePublicSigner))

	// Anything else under /api is an unknown endpoint.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]errorBody{"error": {Code: "not_found", Message: "no such endpoint"}})
	})

	if s.dav != nil {
		mux.Handle("/dav/", s.dav)
	}
	if s.ui != nil {
		mux.Handle("/", s.uiHandler())
	}

	// CSRF: Go's CrossOriginProtection rejects cross-origin, state-changing
	// browser requests using the Sec-Fetch-Site and Origin headers. Requests
	// without those headers (curl, WebDAV clients) are not browsers and
	// carry no ambient cookies, so they are allowed through to normal auth.
	csrf := http.NewCrossOriginProtection()
	_ = csrf.AddTrustedOrigin(s.cfg.PublicURL.Scheme + "://" + s.cfg.PublicURL.Host)
	// The SAML ACS receives a cross-site POST from the IdP by design. It is
	// authenticated by the IdP's XML signature plus a single-use request ID
	// bound to this browser, not by cookies, so CSRF does not apply.
	csrf.AddInsecureBypassPattern("POST /auth/saml/acs")
	csrf.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusForbidden, map[string]errorBody{"error": {Code: "forbidden", Message: "cross-origin request blocked"}})
	}))

	var h http.Handler = mux
	h = csrf.Handler(h)
	h = s.checkHost(h)
	h = deadlines(h)
	h = securityHeaders(h)
	h = s.observe(h)
	return h
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	for _, p := range s.ready {
		if err := p.Ping(r.Context()); err != nil {
			s.log.WarnContext(r.Context(), "readiness check failed", "err", err)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
