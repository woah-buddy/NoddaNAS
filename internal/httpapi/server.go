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
}

// New builds the server. ui holds the static web client (may be nil).
func New(svc *service.Service, am *auth.Manager, cfg Config, log *slog.Logger, ui fs.FS, ready ...Pinger) *Server {
	s := &Server{
		svc: svc, auth: am, cfg: cfg, log: log, ui: ui, ready: ready,
		publicLimit:  newLimiter(120, 30), // anonymous endpoints, per IP
		loginLimit:   newLimiter(20, 10),  // sign-in attempts, per IP
		authFailures: newLimiter(30, 10),  // failed credential checks, per IP
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

	// Browser sign-in (OIDC).
	mux.HandleFunc("GET /auth/login", s.rateLimited(s.loginLimit, s.handleLogin))
	mux.HandleFunc("GET /auth/callback", s.rateLimited(s.loginLimit, s.handleCallback))
	mux.HandleFunc("POST /auth/logout", s.handleLogout)

	// Account.
	mux.HandleFunc("GET /api/v1/me", s.authed(s.handleMe))
	mux.HandleFunc("GET /api/v1/app-passwords", s.sessionOnly(s.handleListAppPasswords))
	mux.HandleFunc("POST /api/v1/app-passwords", s.sessionOnly(s.handleCreateAppPassword))
	mux.HandleFunc("DELETE /api/v1/app-passwords/{id}", s.sessionOnly(s.handleRevokeAppPassword))
	mux.HandleFunc("POST /api/v1/sessions/revoke-all", s.sessionOnly(s.handleRevokeAllSessions))

	// Files and folders.
	mux.HandleFunc("GET /api/v1/nodes/{id}", s.authed(s.handleGetNode))
	mux.HandleFunc("GET /api/v1/nodes/{id}/children", s.authed(s.handleListChildren))
	mux.HandleFunc("POST /api/v1/nodes/{id}/folders", s.authed(s.handleCreateFolder))
	mux.HandleFunc("POST /api/v1/nodes/{id}/upload", s.authed(s.handleUploadNew))
	mux.HandleFunc("PUT /api/v1/nodes/{id}/content", s.authed(s.handleUploadVersion))
	mux.HandleFunc("GET /api/v1/nodes/{id}/content", s.authed(s.handleDownload))
	mux.HandleFunc("PATCH /api/v1/nodes/{id}", s.authed(s.handleUpdateNode))
	mux.HandleFunc("DELETE /api/v1/nodes/{id}", s.authed(s.handleTrashNode))
	mux.HandleFunc("GET /api/v1/nodes/{id}/versions", s.authed(s.handleListVersions))
	mux.HandleFunc("POST /api/v1/nodes/{id}/versions/{vid}/restore", s.authed(s.handleRestoreVersion))

	// Trash.
	mux.HandleFunc("GET /api/v1/trash", s.authed(s.handleListTrash))
	mux.HandleFunc("POST /api/v1/trash/{id}/restore", s.authed(s.handleRestoreTrash))
	mux.HandleFunc("DELETE /api/v1/trash/{id}", s.authed(s.handleDeleteTrash))
	mux.HandleFunc("DELETE /api/v1/trash", s.authed(s.handleEmptyTrash))

	// Sharing.
	mux.HandleFunc("GET /api/v1/nodes/{id}/shares", s.authed(s.handleListShares))
	mux.HandleFunc("POST /api/v1/nodes/{id}/shares", s.authed(s.handleCreateShare))
	mux.HandleFunc("DELETE /api/v1/shares/{id}", s.authed(s.handleDeleteShare))
	mux.HandleFunc("GET /api/v1/shared-with-me", s.authed(s.handleSharedWithMe))

	// Public links (anonymous; the token travels in the request body, never
	// the URL, so it does not end up in logs, history or Referer headers).
	mux.HandleFunc("POST /api/v1/public/node", s.public(s.handlePublicNode))
	mux.HandleFunc("POST /api/v1/public/download", s.public(s.handlePublicDownload))

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
