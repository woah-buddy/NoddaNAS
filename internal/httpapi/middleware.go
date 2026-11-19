package httpapi

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/woah-buddy/FrontDir/internal/auth"
	"github.com/woah-buddy/FrontDir/internal/domain"
	"github.com/woah-buddy/FrontDir/internal/secure"
	"github.com/woah-buddy/FrontDir/internal/service"
)

type ctxKey int

const infoKey ctxKey = 0

// reqInfo carries per-request facts between middleware layers.
type reqInfo struct {
	id     string
	userID string
}

func info(ctx context.Context) *reqInfo {
	if i, ok := ctx.Value(infoKey).(*reqInfo); ok {
		return i
	}
	return &reqInfo{}
}

func requestID(ctx context.Context) string { return info(ctx).id }

// statusWriter records the status code for access logs.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// observe assigns a request ID, recovers panics, and writes an access log.
// Logs record the matched route pattern rather than the raw URL, so file
// names and query strings never end up in log storage.
func (s *Server) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ri := &reqInfo{id: secure.NewID()[:16]}
		rid := ri.id
		w.Header().Set("X-Request-Id", rid)
		r = r.WithContext(context.WithValue(r.Context(), infoKey, ri))
		sw := &statusWriter{ResponseWriter: w}
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.log.ErrorContext(r.Context(), "panic", "request_id", rid, "panic", v, "stack", string(debug.Stack()))
				if sw.status == 0 {
					s.writeError(sw, r, domain.E("internal", "internal server error"))
				}
			}
			route := r.Pattern
			if route == "" {
				route = "unmatched"
			}
			s.log.InfoContext(r.Context(), "http", "request_id", rid, "method", r.Method, "route", route,
				"status", sw.status, "bytes", sw.bytes, "ms", time.Since(start).Milliseconds(),
				"ip", s.clientIP(r).String(), "user", ri.userID)
		}()
		next.ServeHTTP(sw, r)
	})
}

// securityHeaders applies defensive headers to every response. Handlers
// that serve the web UI or file content override the CSP with their own.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		next.ServeHTTP(w, r)
	})
}

// deadlines bounds how long any request may take to send or receive. The
// streaming handlers (uploads, downloads, WebDAV) extend these as data
// flows, so large transfers work while stalled connections are cut off.
func deadlines(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		_ = rc.SetReadDeadline(time.Now().Add(time.Minute))
		_ = rc.SetWriteDeadline(time.Now().Add(2 * time.Minute))
		next.ServeHTTP(w, r)
	})
}

// checkHost rejects requests for any host other than the configured public
// one. This blocks DNS-rebinding attacks and Host-header injection. Health
// endpoints are exempt so orchestrators can probe the container directly.
func (s *Server) checkHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			next.ServeHTTP(w, r)
			return
		}
		if !strings.EqualFold(r.Host, s.cfg.PublicURL.Host) {
			http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP returns the caller's address. X-Forwarded-For is honoured only
// when the direct peer is a configured trusted proxy, and then the
// right-most untrusted entry is used, so clients cannot spoof their IP to
// dodge rate limits.
func (s *Server) clientIP(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	peer = peer.Unmap()
	if !s.trusted(peer) {
		return peer
	}
	parts := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			break
		}
		a = a.Unmap()
		if !s.trusted(a) {
			return a
		}
		peer = a
	}
	return peer
}

func (s *Server) trusted(a netip.Addr) bool {
	for _, p := range s.cfg.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// limiter is a per-client-IP token bucket, used for unauthenticated and
// authentication endpoints (brute-force and abuse protection).
type limiter struct {
	mu      sync.Mutex
	r       rate.Limit
	burst   int
	clients map[netip.Addr]*limEntry
}

type limEntry struct {
	lim  *rate.Limiter
	seen time.Time
}

func newLimiter(perMinute, burst int) *limiter {
	burst = max(burst, perMinute/4)
	return &limiter{r: rate.Limit(float64(perMinute) / 60), burst: burst, clients: map[netip.Addr]*limEntry{}}
}

func (l *limiter) allow(ip netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	e, ok := l.clients[ip]
	if !ok {
		if len(l.clients) > 100_000 {
			l.sweep(now)
		}
		e = &limEntry{lim: rate.NewLimiter(l.r, l.burst)}
		l.clients[ip] = e
	}
	e.seen = now
	return e.lim.Allow()
}

func (l *limiter) sweep(now time.Time) {
	for ip, e := range l.clients {
		if now.Sub(e.seen) > 10*time.Minute {
			delete(l.clients, ip)
		}
	}
}

func (s *Server) rateLimited(l *limiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(s.clientIP(r)) {
			w.Header().Set("Retry-After", "60")
			s.writeError(w, r, domain.E(domain.CodeRateLimited, "too many requests; slow down"))
			return
		}
		next(w, r)
	}
}

// ---- route guards ------------------------------------------------------------
// Every route is registered through exactly one of these, so whether a
// route needs authentication is always an explicit decision.

type authedHandler func(w http.ResponseWriter, r *http.Request, p service.Principal)

// authed requires any valid credential (session or app password).
func (s *Server) authed(h authedHandler) http.HandlerFunc {
	return s.requireAuth(h, false)
}

// sessionOnly requires an interactive browser session. Used for managing
// credentials, so a stolen app password cannot create or revoke others.
func (s *Server) sessionOnly(h authedHandler) http.HandlerFunc {
	return s.requireAuth(h, true)
}

func (s *Server) requireAuth(h authedHandler, sessionOnly bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, method, err := s.auth.Authenticate(r)
		if err != nil || method == auth.MethodNone {
			if err == nil {
				err = domain.E(domain.CodeUnauthorized, "sign in required")
			}
			if !s.authFailures.allow(s.clientIP(r)) {
				err = domain.E(domain.CodeRateLimited, "too many failed sign-in attempts")
			}
			s.writeError(w, r, err)
			return
		}
		if sessionOnly && method != auth.MethodSession {
			s.writeError(w, r, domain.E(domain.CodeForbidden, "this action requires signing in with a browser"))
			return
		}
		info(r.Context()).userID = p.UserID
		h(w, r, p)
	}
}

// public marks a route as deliberately unauthenticated. It is always rate limited.
func (s *Server) public(h http.HandlerFunc) http.HandlerFunc {
	return s.rateLimited(s.publicLimit, h)
}
