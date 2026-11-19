package httpapi

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// uiCSP is the Content Security Policy for the web client. It allows only
// our own scripts and styles (no inline code, no third-party origins), and
// enforces Trusted Types with no policies at all, so the browser itself
// refuses any innerHTML-style string-to-DOM injection. The client is written
// against DOM APIs (textContent, createElement) for exactly this reason.
const uiCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob:; media-src 'self'; " +
	"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; manifest-src 'self'; " +
	"require-trusted-types-for 'script'; trusted-types 'none'"

func (s *Server) uiHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Security-Policy", uiCSP)
		w.Header().Set("Cache-Control", "no-cache")
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if st, err := fs.Stat(s.ui, name); name == "" || err != nil || st.IsDir() {
			// Client-side routes (/s, /trash, ...) all load the app shell.
			name = "index.html"
		}
		http.ServeFileFS(w, r, s.ui, name)
	})
}
