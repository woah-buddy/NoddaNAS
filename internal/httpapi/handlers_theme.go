package httpapi

import (
	"bytes"
	"net/http"
	"time"
)

// Theming endpoints. They are public because the sign-in page is themed
// too, and they are not rate limited because, like the other static assets,
// they serve constant in-memory bytes: the stylesheet the theme package
// generated from validated tokens and the logo it re-encoded at startup.
// Nothing here reflects request input.

type accentView struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type brandingView struct {
	Name          string       `json:"name"`
	Logo          bool         `json:"logo"`
	DefaultAccent string       `json:"defaultAccent"`
	Accents       []accentView `json:"accents"`
}

func (s *Server) handleBranding(w http.ResponseWriter, r *http.Request) {
	v := brandingView{Name: s.theme.Name, Logo: s.theme.Logo != nil, DefaultAccent: s.theme.DefaultAccent}
	for _, a := range s.theme.Accents {
		v.Accents = append(v.Accents, accentView{ID: a.ID, Label: a.Label})
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleThemeCSS(w http.ResponseWriter, r *http.Request) {
	css, etag := s.theme.CSS()
	serveConstant(w, r, "text/css; charset=utf-8", etag, css)
}

func (s *Server) handleLogo(w http.ResponseWriter, r *http.Request) {
	if s.theme.Logo == nil {
		writeJSON(w, http.StatusNotFound, map[string]errorBody{"error": {Code: "not_found", Message: "no logo configured"}})
		return
	}
	// Defense in depth: even opened directly, the logo is an inert image.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	serveConstant(w, r, "image/png", s.theme.LogoETag, s.theme.Logo)
}

// serveConstant serves bytes fixed at startup. Browsers revalidate with the
// ETag (a hash of the bytes), so a theme change shows up on the next load.
func serveConstant(w http.ResponseWriter, r *http.Request, ctype, etag string, body []byte) {
	h := w.Header()
	h.Set("Content-Type", ctype)
	h.Set("Cache-Control", "no-cache")
	h.Set("ETag", etag)
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(body))
}
