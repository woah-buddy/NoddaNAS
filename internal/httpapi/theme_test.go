package httpapi_test

import (
	"bytes"
	"encoding/json"
	"image"
	"image/png"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/woah-buddy/NoddaNAS/internal/httpapi"
	"github.com/woah-buddy/NoddaNAS/internal/theme"
	"github.com/woah-buddy/NoddaNAS/web"
)

// The theming endpoints need no database, so they are tested on a bare server.
func themeServer(t *testing.T, th *theme.Theme) http.Handler {
	t.Helper()
	pub, _ := url.Parse("https://files.example.test")
	return httpapi.New(nil, nil, httpapi.Config{PublicURL: pub, Theme: th}, slog.New(slog.DiscardHandler), web.Static()).Handler()
}

func get(h http.Handler, path string, hdr ...string) *http.Response {
	req := httptest.NewRequest("GET", "https://files.example.test"+path, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result()
}

func TestThemeEndpoints(t *testing.T) {
	var logo bytes.Buffer
	png.Encode(&logo, image.NewRGBA(image.Rect(0, 0, 8, 8)))
	th, err := theme.Load(theme.Options{
		Name: "Acme Files",
		Logo: append(logo.Bytes(), "<script>alert(1)</script>"...), // polyglot tail
		ThemeJSON: []byte(`{"accents": {"acme": {"label": "Acme",
			"light": {"accent": "#b3261e", "accentText": "#ffffff"},
			"dark": {"accent": "#ff8a80", "accentText": "#1a1a1a"}}}}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	h := themeServer(t, th)

	t.Run("stylesheet is typed, unsniffable and revalidated", func(t *testing.T) {
		resp := get(h, "/theme.css")
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/css; charset=utf-8" ||
			resp.Header.Get("X-Content-Type-Options") != "nosniff" || !bytes.Contains(body, []byte(`[data-accent="acme"]`)) {
			t.Fatalf("theme.css: %d %v", resp.StatusCode, resp.Header)
		}
		etag := resp.Header.Get("ETag")
		if r := get(h, "/theme.css", "If-None-Match", etag); etag == "" || r.StatusCode != http.StatusNotModified {
			t.Fatalf("revalidation: etag %q, status %d", etag, r.StatusCode)
		}
	})

	t.Run("branding metadata", func(t *testing.T) {
		resp := get(h, "/api/v1/branding")
		var b struct {
			Name    string
			Logo    bool
			Accents []struct{ ID, Label string }
		}
		json.NewDecoder(resp.Body).Decode(&b)
		if b.Name != "Acme Files" || !b.Logo || len(b.Accents) != 7 || b.Accents[6].ID != "acme" {
			t.Fatalf("branding: %+v", b)
		}
	})

	t.Run("logo is a re-encoded, sandboxed PNG", func(t *testing.T) {
		resp := get(h, "/branding/logo")
		body, _ := io.ReadAll(resp.Body)
		if resp.Header.Get("Content-Type") != "image/png" || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "sandbox") ||
			bytes.Contains(body, []byte("<script>")) {
			t.Fatalf("logo: %v", resp.Header)
		}
		if _, err := png.Decode(bytes.NewReader(body)); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("no logo configured", func(t *testing.T) {
		if resp := get(themeServer(t, nil), "/branding/logo"); resp.StatusCode != 404 {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})

	t.Run("theming does not loosen the UI's CSP", func(t *testing.T) {
		csp := get(h, "/").Header.Get("Content-Security-Policy")
		for _, want := range []string{"style-src 'self';", "script-src 'self';", "trusted-types 'none'"} {
			if !strings.Contains(csp, want) {
				t.Fatalf("UI CSP %q lacks %q", csp, want)
			}
		}
		if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
			t.Fatalf("UI CSP loosened: %q", csp)
		}
		if resp := get(h, "/theme-init.js"); !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/javascript") {
			t.Fatalf("theme-init.js: %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
		}
	})
}
