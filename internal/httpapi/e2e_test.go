package httpapi_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/woah-buddy/NoddaNAS/internal/auth"
	"github.com/woah-buddy/NoddaNAS/internal/blob/fsblob"
	"github.com/woah-buddy/NoddaNAS/internal/httpapi"
	"github.com/woah-buddy/NoddaNAS/internal/service"
	"github.com/woah-buddy/NoddaNAS/internal/testutil"
	"github.com/woah-buddy/NoddaNAS/web"
)

// ---- a minimal fake OpenID Connect provider ---------------------------------

type fakeIdP struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	mu     sync.Mutex
	codes  map[string]codeGrant
	next   idpUser // who "signs in" on the next authorize request
	signer jose.Signer
}

type idpUser struct {
	sub, email string
	verified   bool
	groups     []string
}

type codeGrant struct {
	user      idpUser
	nonce     string
	challenge string
	clientID  string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	f := &fakeIdP{key: key, codes: map[string]codeGrant{}}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "k1"}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	f.signer = signer
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize", "token_endpoint": f.srv.URL + "/token",
			"jwks_uri": f.srv.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
			"end_session_endpoint": f.srv.URL + "/logout",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
			http.Error(w, "PKCE required", 400)
			return
		}
		code := base64.RawURLEncoding.EncodeToString(randBytes(16))
		f.mu.Lock()
		f.codes[code] = codeGrant{user: f.next, nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), clientID: q.Get("client_id")}
		f.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		f.mu.Lock()
		g, ok := f.codes[r.PostForm.Get("code")]
		delete(f.codes, r.PostForm.Get("code"))
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		claims, _ := json.Marshal(map[string]any{
			"iss": f.srv.URL, "sub": g.user.sub, "aud": g.clientID, "exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(), "nonce": g.nonce, "email": g.user.email, "email_verified": g.user.verified,
			"name": g.user.sub, "groups": g.user.groups,
		})
		jws, _ := f.signer.Sign(claims)
		idt, _ := jws.CompactSerialize()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": idt, "expires_in": 3600})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// ---- harness ----------------------------------------------------------------------

type harness struct {
	t    *testing.T
	srv  *httptest.Server
	idp  *fakeIdP
	base string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	store := testutil.Postgres(t)
	blobs, err := fsblob.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(store, blobs, testutil.Keyring(t), service.DefaultConfig(), log)
	idp := newFakeIdP(t)

	h := &harness{t: t, idp: idp}
	// The handler is built after the TLS server starts, because the public
	// URL (with its random port) must be known first.
	var handler http.Handler
	h.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(h.srv.Close)
	h.base = h.srv.URL
	pub, _ := url.Parse(h.base)
	oidc := auth.NewOIDC(auth.OIDCConfig{
		Issuer: idp.srv.URL, ClientID: "noddanas", ClientSecret: "s3cret", RedirectURL: h.base + "/auth/callback",
		AllowedGroups: []string{"nas-users"},
	})
	am := auth.NewManager(store, svc, auth.Config{SessionIdle: time.Hour, SessionAbsolute: 24 * time.Hour}, oidc)
	api := httpapi.New(svc, am, httpapi.Config{PublicURL: pub, EnableWebDAV: true}, log, web.Static(), store, blobs)
	handler = api.Handler()
	return h
}

// browser is a cookie-carrying client that behaves like a same-origin web page.
type browser struct {
	h *harness
	c *http.Client
}

func (h *harness) browser() *browser {
	jar, _ := cookiejar.New(nil)
	c := *h.srv.Client() // copy: Client() returns a shared instance
	c.Jar = jar
	return &browser{h: h, c: &c}
}

func (h *harness) login(u idpUser) *browser {
	h.t.Helper()
	b := h.browser()
	h.idp.next = u
	resp, err := b.c.Get(h.base + "/auth/login?return_to=/files")
	if err != nil {
		h.t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Request.URL.Path != "/files" || resp.Request.URL.Query().Get("error") != "" {
		h.t.Fatalf("login for %s ended at %s", u.sub, resp.Request.URL)
	}
	return b
}

func (b *browser) do(method, path string, body io.Reader, hdr map[string]string) *http.Response {
	b.h.t.Helper()
	req, _ := http.NewRequest(method, b.h.base+path, body)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if body != nil && hdr["Content-Type"] == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := b.c.Do(req)
	if err != nil {
		b.h.t.Fatal(err)
	}
	return resp
}

func (b *browser) json(method, path string, in any, wantStatus int, out any) {
	b.h.t.Helper()
	var body io.Reader
	if in != nil {
		raw, _ := json.Marshal(in)
		body = bytes.NewReader(raw)
	}
	resp := b.do(method, path, body, nil)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		b.h.t.Fatalf("%s %s: status %d, want %d: %s", method, path, resp.StatusCode, wantStatus, raw)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			b.h.t.Fatalf("decode %s: %v", raw, err)
		}
	}
}

func status(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != want {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("%s %s: status %d, want %d: %s", resp.Request.Method, resp.Request.URL.Path, resp.StatusCode, want, raw)
	}
}

// ---- the test --------------------------------------------------------------------------

func TestEndToEnd(t *testing.T) {
	h := newHarness(t)
	alice := h.login(idpUser{sub: "alice", email: "alice@example.test", verified: true, groups: []string{"nas-users"}})
	bob := h.login(idpUser{sub: "bob", email: "bob@example.test", verified: true, groups: []string{"nas-users"}})

	var me struct {
		User struct {
			RootID string `json:"rootId"`
		} `json:"user"`
	}
	alice.json("GET", "/api/v1/me", nil, 200, &me)
	root := me.User.RootID

	t.Run("security headers", func(t *testing.T) {
		resp := alice.do("GET", "/api/v1/me", nil, nil)
		resp.Body.Close()
		for k, want := range map[string]string{
			"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
			"Cache-Control": "no-store", "Cross-Origin-Opener-Policy": "same-origin",
		} {
			if got := resp.Header.Get(k); got != want {
				t.Errorf("%s = %q, want %q", k, got, want)
			}
		}
		if !strings.Contains(resp.Header.Get("Strict-Transport-Security"), "max-age=") {
			t.Error("missing HSTS")
		}
		ui := alice.do("GET", "/", nil, nil)
		ui.Body.Close()
		if csp := ui.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") ||
			!strings.Contains(csp, "require-trusted-types-for 'script'") {
			t.Errorf("UI CSP = %q", csp)
		}
	})

	t.Run("CSRF and host checks", func(t *testing.T) {
		body := `{"name":"csrf"}`
		status(t, alice.do("POST", "/api/v1/nodes/"+root+"/folders", strings.NewReader(body),
			map[string]string{"Sec-Fetch-Site": "cross-site"}), 403)
		req, _ := http.NewRequest("POST", h.base+"/api/v1/nodes/"+root+"/folders", strings.NewReader(body))
		req.Header.Set("Origin", "https://evil.example")
		resp, _ := alice.c.Do(req)
		status(t, resp, 403)
		req, _ = http.NewRequest("GET", h.base+"/api/v1/me", nil)
		req.Host = "evil.example"
		resp, _ = alice.c.Do(req)
		status(t, resp, http.StatusMisdirectedRequest)
		// Anonymous and bad-credential requests are refused.
		resp, _ = h.srv.Client().Get(h.base + "/api/v1/me")
		status(t, resp, 401)
		req, _ = http.NewRequest("GET", h.base+"/api/v1/me", nil)
		req.Header.Set("Authorization", "Bearer ndn_forged")
		resp, _ = h.srv.Client().Do(req)
		status(t, resp, 401)
	})

	t.Run("open redirect is refused", func(t *testing.T) {
		b := h.browser()
		h.idp.next = idpUser{sub: "alice", email: "alice@example.test", verified: true, groups: []string{"nas-users"}}
		resp, err := b.c.Get(h.base + "/auth/login?return_to=//evil.example/x")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.Request.URL.Host != strings.TrimPrefix(h.base, "https://") || resp.Request.URL.Path != "/" {
			t.Fatalf("redirected to %s", resp.Request.URL)
		}
	})

	t.Run("access policy and forged callbacks", func(t *testing.T) {
		b := h.browser()
		h.idp.next = idpUser{sub: "mallory", email: "m@example.test", verified: true}
		resp, _ := b.c.Get(h.base + "/auth/login")
		resp.Body.Close()
		if resp.Request.URL.Query().Get("error") != "not_allowed" {
			t.Fatalf("user outside allowed groups signed in: %s", resp.Request.URL)
		}
		resp, _ = h.browser().c.Get(h.base + "/auth/callback?code=x&state=y")
		resp.Body.Close()
		if resp.Request.URL.Query().Get("error") != "signin" {
			t.Fatalf("forged callback not rejected: %s", resp.Request.URL)
		}
	})

	var fileID string
	t.Run("upload and safe download", func(t *testing.T) {
		payload := "<html><script>alert(document.cookie)</script></html>"
		var n struct{ ID string }
		resp := alice.do("POST", "/api/v1/nodes/"+root+"/upload?name=evil.html", strings.NewReader(payload),
			map[string]string{"Content-Type": "text/html"})
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 201 {
			t.Fatalf("upload: %d %s", resp.StatusCode, raw)
		}
		json.Unmarshal(raw, &n)
		fileID = n.ID
		for _, q := range []string{"", "?inline=1"} {
			resp = alice.do("GET", "/api/v1/nodes/"+fileID+"/content"+q, nil, nil)
			got, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(got) != payload {
				t.Fatalf("content mismatch")
			}
			if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
				t.Errorf("HTML served as %q", ct)
			}
			if cd := resp.Header.Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") {
				t.Errorf("Content-Disposition = %q", cd)
			}
			if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "sandbox") {
				t.Error("download not sandboxed")
			}
		}
		resp = alice.do("GET", "/api/v1/nodes/"+fileID+"/content", nil, map[string]string{"Range": "bytes=6-13"})
		got, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 206 || string(got) != "<script>" {
			t.Fatalf("range: %d %q", resp.StatusCode, got)
		}
		// Bob cannot see Alice's file at all.
		status(t, bob.do("GET", "/api/v1/nodes/"+fileID+"/content", nil, nil), 404)
	})

	t.Run("app passwords are scoped", func(t *testing.T) {
		var created struct{ Token string }
		alice.json("POST", "/api/v1/app-passwords", map[string]any{"name": "laptop", "readOnly": true}, 201, &created)
		api := func(method, path string, body io.Reader) *http.Response {
			req, _ := http.NewRequest(method, h.base+path, body)
			req.Header.Set("Authorization", "Bearer "+created.Token)
			resp, _ := h.srv.Client().Do(req)
			return resp
		}
		status(t, api("GET", "/api/v1/me", nil), 200)
		status(t, api("POST", "/api/v1/nodes/"+root+"/upload?name=x", strings.NewReader("x")), 403)
		// Credentials cannot mint more credentials.
		status(t, api("POST", "/api/v1/app-passwords", strings.NewReader(`{"name":"pivot"}`)), 403)
	})

	t.Run("webdav", func(t *testing.T) {
		var created struct{ Token string }
		alice.json("POST", "/api/v1/app-passwords", map[string]any{"name": "dav"}, 201, &created)
		dav := func(method, path string, body io.Reader, hdr map[string]string) *http.Response {
			req, _ := http.NewRequest(method, h.base+path, body)
			req.SetBasicAuth("alice", created.Token)
			for k, v := range hdr {
				req.Header.Set(k, v)
			}
			resp, err := h.srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			return resp
		}
		status(t, dav("MKCOL", "/dav/Notes", nil, nil), 201)
		status(t, dav("PUT", "/dav/Notes/todo.txt", strings.NewReader("buy milk"), nil), 201)
		status(t, dav("PUT", "/dav/Notes/x.html", strings.NewReader("<script>alert(1)</script>"), nil), 201)
		for _, name := range []string{"todo.txt", "x.html"} {
			resp := dav("GET", "/dav/Notes/"+name, nil, nil)
			resp.Body.Close()
			if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/octet-stream" ||
				!strings.Contains(resp.Header.Get("Content-Security-Policy"), "sandbox") {
				t.Fatalf("dav get %s: %d %q", name, resp.StatusCode, resp.Header.Get("Content-Type"))
			}
		}
		resp := dav("GET", "/dav/Notes/todo.txt", nil, nil)
		got, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(got) != "buy milk" {
			t.Fatalf("dav get: %q", got)
		}
		status(t, dav("PROPFIND", "/dav/Notes/", nil, map[string]string{"Depth": "1"}), 207)
		status(t, dav("MOVE", "/dav/Notes/todo.txt", nil, map[string]string{"Destination": h.base + "/dav/Notes/done.txt"}), 201)
		status(t, dav("DELETE", "/dav/Notes/done.txt", nil, nil), 204)
		var trash struct{ Items []struct{ Name string } }
		alice.json("GET", "/api/v1/trash", nil, 200, &trash)
		if len(trash.Items) != 1 || trash.Items[0].Name != "done.txt" {
			t.Fatalf("WebDAV delete should go to trash: %+v", trash)
		}
		// Session cookies are not accepted for WebDAV.
		status(t, alice.do("PROPFIND", "/dav/", nil, nil), 401)
	})

	t.Run("public link", func(t *testing.T) {
		var link struct {
			Token string
			URL   string
		}
		alice.json("POST", "/api/v1/nodes/"+fileID+"/shares", map[string]any{"type": "link"}, 201, &link)
		if !strings.Contains(link.URL, "/s#") {
			t.Fatalf("link token must travel in the URL fragment: %s", link.URL)
		}
		anon := h.browser()
		var info struct{ Node struct{ Name string } }
		anon.json("POST", "/api/v1/public/node", map[string]string{"token": link.Token}, 200, &info)
		if info.Node.Name != "evil.html" {
			t.Fatalf("public node = %+v", info)
		}
		form := url.Values{"token": {link.Token}}
		resp := anon.do("POST", "/api/v1/public/download", strings.NewReader(form.Encode()),
			map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
		status(t, resp, 200)
		anon.json("POST", "/api/v1/public/node", map[string]string{"token": link.Token, "nodeId": root}, 404, nil)
	})

	t.Run("logout ends the session", func(t *testing.T) {
		var out struct{ LogoutURL string }
		bob.json("POST", "/auth/logout", nil, 200, &out)
		if !strings.HasPrefix(out.LogoutURL, h.idp.srv.URL+"/logout") {
			t.Errorf("logout URL = %q", out.LogoutURL)
		}
		status(t, bob.do("GET", "/api/v1/me", nil, nil), 401)
	})
}
