package httpapi

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// uiCSP is the Content Security Policy for the web client. It allows only
// our own scripts and styles (no inline code, no third-party origins), and
// enforces Trusted Types, so the browser itself refuses any innerHTML-style
// string-to-DOM injection. The client is written against DOM APIs
// (textContent, createElement) for exactly this reason.
//
// Exactly one Trusted Types policy may exist, "frontdir-sw", created once
// by app.js (no duplicates allowed). It only has createScriptURL, which
// returns the constant "/dl/sw.js" and throws for anything else: it is what
// registering the download worker requires. It cannot produce HTML, script
// or any other URL.
const uiCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob:; media-src 'self'; " +
	"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; manifest-src 'self'; " +
	"require-trusted-types-for 'script'; trusted-types frontdir-sw"

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
		if st, err := fs.Stat(s.ui, name); name == "" || !fs.ValidPath(name) || err != nil || st.IsDir() {
			// Client-side routes (/s, /trash, ...) all load the app shell.
			name = "index.html"
		}
		// name is a cleaned, fs.ValidPath-checked path into the embedded,
		// read-only UI file system, which has nothing else in it to reach.
		http.ServeFileFS(w, r, s.ui, name) // #nosec G703 -- see above
	})
}
