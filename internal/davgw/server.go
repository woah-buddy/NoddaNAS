package davgw

import (
	"crypto/subtle"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"golang.org/x/net/webdav"
)

// MountName is the last path segment of the gateway URL. Finder and GNOME
// Files name the mounted volume after it.
const MountName = "FrontDir"

// CheckListen accepts only loopback addresses: plaintext must not leave the
// machine, so there is deliberately no way to serve it to a network.
func CheckListen(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return errors.New("listen address must be host:port, e.g. 127.0.0.1:8484")
	}
	if host == "localhost" {
		return nil
	}
	a, err := netip.ParseAddr(host)
	if err != nil || !a.IsLoopback() {
		return errors.New("the gateway serves decrypted files, so it listens on loopback only (127.0.0.1 or ::1)")
	}
	return nil
}

// Handler serves fs over WebDAV at /<token>/FrontDir/ on the given loopback
// address (as actually bound, host:port), behind the local-only guard.
func Handler(fs *FS, token, addr string, log *slog.Logger) http.Handler {
	_, port, _ := net.SplitHostPort(addr)
	prefix := "/" + token + "/" + MountName
	dav := &webdav.Handler{
		Prefix:     prefix,
		FileSystem: fs,
		LockSystem: webdav.NewMemLS(),
		Logger: func(r *http.Request, err error) {
			if err != nil && log != nil {
				log.Debug("webdav", "method", r.Method, "err", err)
			}
		},
	}
	return &guard{next: dav, token: token, prefix: prefix,
		hosts: map[string]bool{"127.0.0.1:" + port: true, "localhost:" + port: true, "[::1]:" + port: true}}
}

// guard admits only requests a local WebDAV client makes to this gateway.
type guard struct {
	next   http.Handler
	token  string
	prefix string
	hosts  map[string]bool
}

func (g *guard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	// Whatever is served is inert if a browser ever renders it.
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")

	// DNS rebinding: a page on evil.example resolving to 127.0.0.1 still
	// sends Host: evil.example.
	if !g.hosts[strings.ToLower(r.Host)] {
		http.Error(w, "wrong host", http.StatusMisdirectedRequest)
		return
	}
	// Browsers mark their requests; file managers and WebDAV clients do not.
	if r.Header.Get("Origin") != "" || (r.Header.Get("Sec-Fetch-Site") != "" && r.Header.Get("Sec-Fetch-Site") != "none") {
		http.Error(w, "browser requests are not accepted", http.StatusForbidden)
		return
	}
	// Windows probes the server root before mapping a drive; answering
	// OPTIONS anywhere reveals nothing but that WebDAV is spoken here.
	if r.Method == http.MethodOptions && !strings.HasPrefix(r.URL.Path, g.prefix) {
		h.Set("DAV", "1, 2")
		h.Set("MS-Author-Via", "DAV")
		h.Set("Allow", "OPTIONS")
		w.WriteHeader(http.StatusOK)
		return
	}
	seg, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if subtle.ConstantTimeCompare([]byte(seg), []byte(g.token)) != 1 ||
		!(rest == MountName || strings.HasPrefix(rest, MountName+"/")) {
		http.NotFound(w, r)
		return
	}
	g.next.ServeHTTP(w, r)
}
