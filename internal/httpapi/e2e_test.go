package httpapi_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crewjam/saml"
	jose "github.com/go-jose/go-jose/v4"

	"github.com/woah-buddy/NoddaNAS/internal/auth"
	"github.com/woah-buddy/NoddaNAS/internal/blob/fsblob"
	"github.com/woah-buddy/NoddaNAS/internal/client"
	"github.com/woah-buddy/NoddaNAS/internal/e2ee"
	"github.com/woah-buddy/NoddaNAS/internal/httpapi"
	"github.com/woah-buddy/NoddaNAS/internal/service"
	"github.com/woah-buddy/NoddaNAS/internal/store/postgres"
	"github.com/woah-buddy/NoddaNAS/internal/testutil"
	"github.com/woah-buddy/NoddaNAS/web"
)

const pass = "correct horse battery staple"

// ---- a minimal fake OpenID Connect provider ---------------------------------

type idpUser struct {
	sub, email string
	groups     []string
}

type fakeOIDC struct {
	srv    *httptest.Server
	mu     sync.Mutex
	codes  map[string][4]string
	users  map[string]idpUser
	next   idpUser
	signer jose.Signer
}

func newFakeOIDC(t *testing.T) *fakeOIDC {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "k1"}},
		(&jose.SignerOptions{}).WithType("JWT"))
	f := &fakeOIDC{codes: map[string][4]string{}, users: map[string]idpUser{}, signer: signer}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint": f.srv.URL + "/token", "jwks_uri": f.srv.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := e2ee.B64(randBytes(16))
		f.mu.Lock()
		f.users[code] = f.next
		f.codes[code] = [4]string{q.Get("nonce"), q.Get("code_challenge"), q.Get("client_id")}
		f.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		code := r.PostForm.Get("code")
		f.mu.Lock()
		g, ok := f.codes[code]
		u := f.users[code]
		delete(f.codes, code)
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != g[1] {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		claims, _ := json.Marshal(map[string]any{"iss": f.srv.URL, "sub": u.sub, "aud": g[2], "exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(), "nonce": g[0], "email": u.email, "email_verified": true, "name": u.sub, "groups": u.groups})
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

// ---- a real SAML IdP (crewjam/saml) that signs genuine assertions --------------

type samlIdP struct {
	srv  *httptest.Server
	idp  *saml.IdentityProvider
	mu   sync.Mutex
	next *saml.Session
	spMD *saml.EntityDescriptor
}

func (s *samlIdP) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := *s.next
	sess.ID, sess.CreateTime, sess.ExpireTime = e2ee.B64(randBytes(8)), time.Now(), time.Now().Add(time.Hour)
	return &sess
}

func (s *samlIdP) GetServiceProvider(r *http.Request, id string) (*saml.EntityDescriptor, error) {
	if s.spMD == nil || s.spMD.EntityID != id {
		return nil, os.ErrNotExist
	}
	return s.spMD, nil
}

func newSAMLIdP(t *testing.T) *samlIdP {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-idp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	s := &samlIdP{}
	mux := http.NewServeMux()
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	base, _ := url.Parse(s.srv.URL)
	s.idp = &saml.IdentityProvider{Key: key, Signer: key, Certificate: cert,
		MetadataURL: *base.JoinPath("/metadata"), SSOURL: *base.JoinPath("/sso"),
		ServiceProviderProvider: s, SessionProvider: s}
	mux.HandleFunc("/sso", s.idp.ServeSSO)
	return s
}

// ---- harness --------------------------------------------------------------------

type harness struct {
	t    *testing.T
	srv  *httptest.Server
	svc  *service.Service
	oidc *fakeOIDC
	saml *samlIdP
	am   *auth.Manager
	base string
}

// harnessOpts lets a test start a server on existing state, e.g. a
// restored backup, with the same identity provider as before.
type harnessOpts struct {
	store   *postgres.Store
	dataDir string
	oidc    *fakeOIDC
	logs    io.Writer // the server's JSON log stream
}

func newHarness(t *testing.T) *harness { return newHarnessWith(t, harnessOpts{}) }

func newHarnessWith(t *testing.T, o harnessOpts) *harness {
	t.Helper()
	if o.store == nil {
		o.store = testutil.Postgres(t)
	}
	if o.dataDir == "" {
		o.dataDir = t.TempDir()
	}
	if o.oidc == nil {
		o.oidc = newFakeOIDC(t)
	}
	if o.logs == nil {
		o.logs = io.Discard
	}
	store := o.store
	blobs, err := fsblob.New(o.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewJSONHandler(o.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg := service.DefaultConfig()
	cfg.AdminGroups = []string{"nas-admins"}
	svc := service.New(store, blobs, cfg, log)
	h := &harness{t: t, svc: svc, oidc: o.oidc, saml: newSAMLIdP(t)}
	var handler http.Handler
	h.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(h.srv.Close)
	h.base = h.srv.URL
	pub, _ := url.Parse(h.base)
	policy := auth.Policy{AllowedGroups: []string{"nas-users"}}
	oidc := auth.NewOIDC(auth.OIDCConfig{Issuer: h.oidc.srv.URL, ClientID: "noddanas", ClientSecret: "s3cret",
		RedirectURL: h.base + "/auth/callback", Policy: policy})
	idpMD, _ := xml.Marshal(h.saml.idp.Metadata())
	samlSP := auth.NewSAML(auth.SAMLConfig{MetadataURL: h.base + "/auth/saml/metadata", ACSURL: h.base + "/auth/saml/acs",
		IDPMetadata: idpMD, TrustEmail: true, Policy: policy})
	am := auth.NewManager(store, svc, auth.Config{SessionIdle: time.Hour, SessionAbsolute: 24 * time.Hour}, oidc, samlSP)
	h.am = am
	handler = httpapi.New(svc, am, httpapi.Config{PublicURL: pub, EnableWebDAV: true,
		RateLimits: httpapi.RateLimits{Login: 6000, Public: 6000, AuthFailures: 6000}}, log, web.Static(), store, blobs).Handler()

	// The IdP learns our SP metadata the way an administrator would: from our metadata URL.
	resp, err := h.srv.Client().Get(h.base + "/auth/saml/metadata")
	if err != nil {
		t.Fatal(err)
	}
	var md saml.EntityDescriptor
	if err := xml.NewDecoder(resp.Body).Decode(&md); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	h.saml.spMD = &md
	return h
}

func (h *harness) browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	c := *h.srv.Client()
	c.Jar = jar
	return &c
}

func (h *harness) loginOIDC(u idpUser) *http.Client {
	h.t.Helper()
	b := h.browser()
	h.oidc.next = u
	resp, err := b.Get(h.base + "/auth/login?return_to=/files")
	if err != nil {
		h.t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Request.URL.Path != "/files" {
		h.t.Fatalf("OIDC login for %s ended at %s", u.sub, resp.Request.URL)
	}
	return b
}

var samlRespRE = regexp.MustCompile(`name="SAMLResponse" value="([^"]+)"`)

// startSAML begins a SAML sign-in and returns the IdP's signed response.
func (h *harness) startSAML(b *http.Client, nameID, email string, groups []string) string {
	h.t.Helper()
	h.saml.mu.Lock()
	h.saml.next = &saml.Session{NameID: nameID, NameIDFormat: string(saml.PersistentNameIDFormat), UserEmail: email,
		UserName: nameID, UserCommonName: nameID, Groups: groups}
	h.saml.mu.Unlock()
	resp, err := b.Get(h.base + "/auth/saml/login?return_to=/files")
	if err != nil {
		h.t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := samlRespRE.FindSubmatch(page)
	if m == nil {
		h.t.Fatalf("IdP did not return a SAML response form: %.300s", page)
	}
	return strings.ReplaceAll(string(m[1]), "&#43;", "+")
}

func (h *harness) postACS(b *http.Client, samlResponse string) *http.Response {
	h.t.Helper()
	req, _ := http.NewRequest("POST", h.base+"/auth/saml/acs", strings.NewReader(url.Values{"SAMLResponse": {samlResponse}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site") // a real IdP form post is cross-site
	resp, err := b.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func status(t *testing.T, resp *http.Response, err error, want int) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("%s %s: status %d, want %d: %.300s", resp.Request.Method, resp.Request.URL.Path, resp.StatusCode, want, raw)
	}
}

func must[T any](t *testing.T) func(T, error) T {
	return func(v T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

// ---- the test --------------------------------------------------------------------------

func TestEndToEnd(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	aliceB := h.loginOIDC(idpUser{sub: "alice", email: "alice@example.test", groups: []string{"nas-users", "nas-admins"}})
	alice := client.New(h.base, aliceB, "")
	code := must[string](t)(alice.SetupKeys(ctx, pass))

	t.Run("SAML sign-in, tampering, replay and unsolicited responses", func(t *testing.T) {
		b := h.browser()
		good := h.startSAML(b, "saml-bob", "bob@example.test", []string{"nas-users"})

		// Tampered: change the NameID inside the signed assertion.
		raw, _ := base64.StdEncoding.DecodeString(good)
		forged := base64.StdEncoding.EncodeToString(bytes.ReplaceAll(raw, []byte("saml-bob"), []byte("saml-eve")))
		resp := h.postACS(b, forged)
		if resp.Request.URL.Query().Get("error") != "signin" {
			t.Fatalf("tampered assertion accepted: %s", resp.Request.URL)
		}
		// The failed attempt consumed the login request: even the genuine
		// response is now refused (single use).
		if resp := h.postACS(b, good); resp.Request.URL.Query().Get("error") != "signin" {
			t.Fatal("response accepted after its request was consumed")
		}
		// Unsolicited: a browser that never started a sign-in.
		if resp := h.postACS(h.browser(), good); resp.Request.URL.Query().Get("error") != "signin" {
			t.Fatal("unsolicited (IdP-initiated) response accepted")
		}
		// A fresh, genuine sign-in works, and its response cannot be replayed.
		good2 := h.startSAML(b, "saml-bob", "bob@example.test", []string{"nas-users"})
		if resp := h.postACS(b, good2); resp.Request.URL.Path != "/files" || resp.Request.URL.Query().Get("error") != "" {
			t.Fatalf("SAML login failed: %s", resp.Request.URL)
		}
		h.startSAML(b, "saml-bob", "bob@example.test", []string{"nas-users"}) // new request ID, new cookie
		if resp := h.postACS(b, good2); resp.Request.URL.Query().Get("error") != "signin" {
			t.Fatal("replayed SAML response accepted")
		}
		// The policy applies to SAML too.
		mb := h.browser()
		r := h.startSAML(mb, "saml-mallory", "m@example.test", nil)
		if resp := h.postACS(mb, r); resp.Request.URL.Query().Get("error") != "not_allowed" {
			t.Fatal("SAML user outside the allowed groups signed in")
		}
	})

	bobB := h.browser()
	h.postACS(bobB, h.startSAML(bobB, "saml-bob", "bob@example.test", []string{"nas-users"}))
	bob := client.New(h.base, bobB, "")
	must[string](t)(bob.SetupKeys(ctx, pass))

	me := must[*client.Me](t)(alice.Me(ctx))
	root := me.PersonalSpace.RootID
	docs := must[string](t)(alice.Mkdir(ctx, root, "Docs"))
	secret := "the plaintext the server must never see"
	f := must[*client.Node](t)(alice.Upload(ctx, docs, "report.txt", strings.NewReader(secret), int64(len(secret)), time.Now()))

	t.Run("round trip through the API; server holds only ciphertext", func(t *testing.T) {
		kids := must[[]*client.Node](t)(alice.List(ctx, docs))
		if len(kids) != 1 || kids[0].Name != "report.txt" || strings.Contains(kids[0].NameEnc, "report") {
			t.Fatalf("listing = %+v", kids)
		}
		var out bytes.Buffer
		must[*e2ee.Meta](t)(alice.Download(ctx, f.ID, &out))
		if out.String() != secret {
			t.Fatal("content mismatch")
		}
		var raw bytes.Buffer
		if err := alice.DownloadContainer(ctx, f.ID, &raw); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw.Bytes(), []byte("plaintext")) || bytes.Contains(raw.Bytes(), []byte("report")) {
			t.Fatal("container leaks plaintext")
		}
		// Duplicate names are caught by keyed hashes, case-insensitively.
		_, err := alice.Upload(ctx, docs, "REPORT.TXT", strings.NewReader("x"), 1, time.Now())
		if _, ok := err.(*client.ErrExists); !ok {
			t.Fatalf("duplicate upload: %v", err)
		}
	})

	t.Run("independent backup and restore of a single file", func(t *testing.T) {
		var backup bytes.Buffer
		if err := alice.DownloadContainer(ctx, f.ID, &backup); err != nil {
			t.Fatal(err)
		}
		f.Name = "report.txt"
		if err := alice.Trash(ctx, f); err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest("DELETE", h.base+"/api/v1/trash/"+f.ID, nil)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		resp, err := aliceB.Do(req)
		status(t, resp, err, http.StatusAccepted)
		if _, err := h.svc.RunMaintenance(ctx, 10); err != nil {
			t.Fatal(err)
		}
		// The file is gone from the server. Restore it from the backup alone.
		n := must[*client.Node](t)(alice.RestoreContainer(ctx, docs, backup.Bytes()))
		var out bytes.Buffer
		must[*e2ee.Meta](t)(alice.Download(ctx, n.ID, &out))
		if out.String() != secret || n.Name != "report.txt" {
			t.Fatalf("restored %q as %q", out.String(), n.Name)
		}
		// Bob cannot restore Alice's backup into his space.
		bme := must[*client.Me](t)(bob.Me(ctx))
		if _, err := bob.RestoreContainer(ctx, bme.PersonalSpace.RootID, backup.Bytes()); err == nil {
			t.Fatal("restored someone else's backup")
		}
		f = n
	})

	t.Run("user share with end-to-end keys", func(t *testing.T) {
		d := &client.Node{ID: docs, Name: "Docs", Kind: "folder"}
		if err := alice.ShareWithUser(ctx, d, "bob@example.test", "read"); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		must[*e2ee.Meta](t)(bob.Download(ctx, f.ID, &out))
		if out.String() != secret {
			t.Fatal("bob cannot read the shared file")
		}
		_, err := bob.Upload(ctx, docs, "x.txt", strings.NewReader("x"), 1, time.Now())
		if ae, ok := err.(*client.APIError); !ok || ae.Status != http.StatusForbidden {
			t.Fatalf("read share allowed a write: %v", err)
		}
	})

	t.Run("team folder with direct and group members", func(t *testing.T) {
		team := must[*client.Space](t)(alice.CreateTeam(ctx, "Operations"))
		bobUser := must[*e2ee.PublicUser](t)(alice.LookupUser(ctx, "bob@example.test"))
		if err := alice.AddMember(ctx, team.ID, bobUser.ID, "write"); err != nil {
			t.Fatal(err)
		}
		spaces := must[[]*client.Space](t)(bob.Spaces(ctx))
		var got *client.Space
		for _, s := range spaces {
			if s.ID == team.ID {
				got = s
			}
		}
		if got == nil || got.Name != "Operations" {
			t.Fatalf("bob's view of the team: %+v", got)
		}
		up := must[*client.Node](t)(bob.Upload(ctx, team.RootID, "runbook.md", strings.NewReader("step 1"), 6, time.Now()))
		var out bytes.Buffer
		must[*e2ee.Meta](t)(alice.Download(ctx, up.ID, &out))

		// Item 3: an admin maps an IdP group; a group member gets access at
		// once and the key as soon as a manager's client grants it.
		req, _ := http.NewRequest("PUT", h.base+"/api/v1/spaces/"+team.ID+"/groups/eng", strings.NewReader(`{"role":"read"}`))
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		resp, err := aliceB.Do(req)
		status(t, resp, err, http.StatusNoContent)
		carolB := h.loginOIDC(idpUser{sub: "carol", email: "carol@example.test", groups: []string{"nas-users", "eng"}})
		carol := client.New(h.base, carolB, "")
		must[string](t)(carol.SetupKeys(ctx, pass))
		if _, _, err := carol.NodeKey(ctx, up.ID); err == nil {
			t.Fatal("carol decrypted before being granted the key")
		}
		if n := must[int](t)(alice.GrantPending(ctx, team.ID)); n != 1 {
			t.Fatalf("granted %d", n)
		}
		out.Reset()
		must[*e2ee.Meta](t)(carol.Download(ctx, up.ID, &out))
		if out.String() != "step 1" {
			t.Fatal("carol cannot read after the grant")
		}
		// Bob (not an admin) cannot map groups.
		req, _ = http.NewRequest("PUT", h.base+"/api/v1/spaces/"+team.ID+"/groups/all", strings.NewReader(`{"role":"manage"}`))
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		resp, err = bobB.Do(req)
		status(t, resp, err, http.StatusForbidden)
	})

	t.Run("public link decrypts only with the fragment secret", func(t *testing.T) {
		link := must[string](t)(alice.CreateLink(ctx, f, "", 0, 0))
		frag := link[strings.Index(link, "#")+1:]
		token, secretB64, _ := strings.Cut(frag, ".")
		anon := h.srv.Client()
		body, _ := json.Marshal(map[string]string{"token": token})
		req, _ := http.NewRequest("POST", h.base+"/api/v1/public/node", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := anon.Do(req)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("public node: %v %v", err, resp.Status)
		}
		var view struct {
			Link struct{ ID, NodeID, LinkKey string }
		}
		json.NewDecoder(resp.Body).Decode(&view)
		resp.Body.Close()
		ls, _ := e2ee.UnB64(secretB64)
		nk, name, err := e2ee.OpenLinkKey(ls, view.Link.ID, view.Link.NodeID, view.Link.LinkKey)
		if err != nil || name != "report.txt" {
			t.Fatalf("link key: %v", err)
		}
		req, _ = http.NewRequest("POST", h.base+"/api/v1/public/download", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err = anon.Do(req)
		if err != nil || resp.StatusCode != 200 {
			t.Fatal("public download failed")
		}
		ct, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		p, _ := e2ee.ParsePrefix(bytes.NewReader(ct))
		k, err := p.Keys(nk)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := e2ee.DecryptVerify(bytes.NewReader(ct[p.BodyOffset():]), &out, p, k, alice.Account().Public()); err != nil || out.String() != secret {
			t.Fatalf("visitor decrypt: %v", err)
		}
		// A wrong secret cannot decrypt, even with the right token.
		if _, _, err := e2ee.OpenLinkKey(e2ee.NewLinkSecret(), view.Link.ID, view.Link.NodeID, view.Link.LinkKey); err == nil {
			t.Fatal("link key opened with the wrong secret")
		}
	})

	t.Run("WebDAV mirror decrypts offline into a full tree", func(t *testing.T) {
		var created struct{ Token string }
		req, _ := http.NewRequest("POST", h.base+"/api/v1/app-passwords", strings.NewReader(`{"name":"backup","readOnly":true}`))
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Content-Type", "application/json")
		resp, err := aliceB.Do(req)
		if err != nil || resp.StatusCode != 201 {
			t.Fatalf("app password: %v", err)
		}
		json.NewDecoder(resp.Body).Decode(&created)
		resp.Body.Close()
		dav := func(method, path string) *http.Response {
			req, _ := http.NewRequest(method, h.base+path, nil)
			req.SetBasicAuth("backup", created.Token)
			resp, err := h.srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			return resp
		}
		status(t, dav("PROPFIND", "/dav/"), nil, 207)
		status(t, dav("PUT", "/dav/"+me.PersonalSpace.ID+"/x.ndne"), nil, http.StatusMethodNotAllowed)

		// Mirror the space the way a sync tool would.
		mirror := t.TempDir()
		var fetch func(davPath, local string)
		fetch = func(davPath, local string) {
			os.MkdirAll(local, 0o700)
			get := func(name string) []byte {
				r := dav("GET", davPath+"/"+name)
				defer r.Body.Close()
				if r.StatusCode != 200 || r.Header.Get("Content-Type") != "application/octet-stream" {
					t.Fatalf("GET %s/%s: %d %s", davPath, name, r.StatusCode, r.Header.Get("Content-Type"))
				}
				b, _ := io.ReadAll(r.Body)
				os.WriteFile(filepath.Join(local, name), b, 0o600)
				return b
			}
			var fr client.FolderRecord
			json.Unmarshal(get("_noddanas-folder.json"), &fr)
			for _, ch := range fr.Children {
				if ch.Kind == "folder" {
					fetch(davPath+"/"+ch.ID, filepath.Join(local, ch.ID))
				} else {
					get(ch.ID + ".ndne")
				}
			}
		}
		fetch("/dav/"+me.PersonalSpace.ID, mirror)
		r := dav("GET", "/dav/"+me.PersonalSpace.ID+"/_noddanas-space.json")
		sb, _ := io.ReadAll(r.Body)
		r.Body.Close()
		os.WriteFile(filepath.Join(mirror, "_noddanas-space.json"), sb, 0o600)

		// Offline: key backup + recovery code, no server.
		kb := must[*client.KeyBackup](t)(alice.ExportKeys(ctx))
		kbJSON, _ := json.Marshal(kb)
		keys := must[*client.OfflineKeys](t)(client.UnlockBackup(kbJSON, code, true))
		out := t.TempDir()
		n, skipped, err := keys.DecryptTree(mirror, out, nil)
		if err != nil || n != 1 || len(skipped) != 0 {
			t.Fatalf("decrypt tree: %d files, skipped %v, %v", n, skipped, err)
		}
		got, err := os.ReadFile(filepath.Join(out, "Docs", "report.txt"))
		if err != nil || string(got) != secret {
			t.Fatalf("offline tree: %q %v", got, err)
		}

		// Restoring into a directory where a symlink stands in for a folder
		// of the backup cannot write through it to somewhere else.
		outside, trap := t.TempDir(), t.TempDir()
		if err := os.Symlink(outside, filepath.Join(trap, "Docs")); err != nil {
			t.Fatal(err)
		}
		if _, _, err := keys.DecryptTree(mirror, trap, nil); err == nil {
			t.Fatal("decrypt-tree followed a symlink out of the output directory")
		}
		if entries, _ := os.ReadDir(outside); len(entries) != 0 {
			t.Fatal("decrypt-tree wrote outside the output directory")
		}
		// A tampered folder record with a path-shaped ID is refused before
		// any path is built from it.
		recPath := filepath.Join(mirror, "_noddanas-folder.json")
		rec, _ := os.ReadFile(recPath)
		var fr map[string]any
		if err := json.Unmarshal(rec, &fr); err != nil {
			t.Fatal(err)
		}
		fr["children"].([]any)[0].(map[string]any)["id"] = "../../../etc"
		tampered, _ := json.Marshal(fr)
		os.WriteFile(recPath, tampered, 0o600)
		if _, _, err := keys.DecryptTree(mirror, t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), "malformed ID") {
			t.Fatalf("tampered ID: %v", err)
		}
	})

	t.Run("credential scoping and HTTP hardening", func(t *testing.T) {
		resp, err := h.srv.Client().Get(h.base + "/api/v1/me")
		status(t, resp, err, 401)
		// Keys can only be set up from an interactive session.
		var created struct{ Token string }
		req, _ := http.NewRequest("POST", h.base+"/api/v1/app-passwords", strings.NewReader(`{"name":"cli"}`))
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Content-Type", "application/json")
		resp, _ = bobB.Do(req)
		json.NewDecoder(resp.Body).Decode(&created)
		resp.Body.Close()
		req, _ = http.NewRequest("POST", h.base+"/api/v1/keys", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+created.Token)
		resp, err = h.srv.Client().Do(req)
		status(t, resp, err, 403)
		// CSRF and host checks.
		req, _ = http.NewRequest("POST", h.base+"/api/v1/nodes/"+root+"/folders", strings.NewReader(`{}`))
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		resp, err = aliceB.Do(req)
		status(t, resp, err, 403)
		req, _ = http.NewRequest("GET", h.base+"/api/v1/me", nil)
		req.Host = "evil.example"
		resp, err = aliceB.Do(req)
		status(t, resp, err, http.StatusMisdirectedRequest)
		// Downloads are always opaque, sandboxed attachments.
		req, _ = http.NewRequest("GET", h.base+"/api/v1/nodes/"+f.ID+"/content", nil)
		resp, _ = aliceB.Do(req)
		resp.Body.Close()
		if resp.Header.Get("Content-Type") != "application/octet-stream" || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "sandbox") {
			t.Fatalf("download headers: %v", resp.Header)
		}
		ui, _ := aliceB.Get(h.base + "/")
		ui.Body.Close()
		if !strings.Contains(ui.Header.Get("Content-Security-Policy"), "require-trusted-types-for 'script'") {
			t.Fatal("UI CSP missing Trusted Types")
		}
	})

	t.Run("shared by me and the link kill switches", func(t *testing.T) {
		call := func(b *http.Client, method, path, bearer string) (int, string) {
			t.Helper()
			req, _ := http.NewRequest(method, h.base+path, nil)
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			if bearer != "" {
				req.Header.Set("Authorization", "Bearer "+bearer)
			}
			resp, err := b.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			raw, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, string(raw)
		}
		must[string](t)(alice.CreateLink(ctx, f, "", 0, 0))
		code, body := call(aliceB, "GET", "/api/v1/shared-by-me", "")
		if code != 200 || !strings.Contains(body, `"type":"link"`) || !strings.Contains(body, `"status":"active"`) {
			t.Fatalf("shared-by-me: %d %.300s", code, body)
		}
		// The creator's list carries no key material.
		for _, field := range []string{"linkKey", "sealedKey", `"sig"`, "tokenHash"} {
			if strings.Contains(body, field) {
				t.Fatalf("shared-by-me exposes %s", field)
			}
		}

		// The global switch: administrators only, and never via an app password.
		var ap struct{ Token string }
		req, _ := http.NewRequest("POST", h.base+"/api/v1/app-passwords", strings.NewReader(`{"name":"kill-test"}`))
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Content-Type", "application/json")
		resp, _ := aliceB.Do(req)
		json.NewDecoder(resp.Body).Decode(&ap)
		resp.Body.Close()
		if code, _ := call(h.srv.Client(), "POST", "/api/v1/admin/links/revoke-all", ap.Token); code != 403 {
			t.Fatalf("admin kill switch via app password: %d", code)
		}
		if code, _ := call(bobB, "POST", "/api/v1/admin/links/revoke-all", ""); code != 403 {
			t.Fatalf("admin kill switch as non-admin: %d", code)
		}
		// Cross-site requests are refused before reaching it.
		req, _ = http.NewRequest("POST", h.base+"/api/v1/links/revoke-all", nil)
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		resp, _ = aliceB.Do(req)
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("cross-site kill switch: %d", resp.StatusCode)
		}

		// Alice's own switch.
		code, body = call(aliceB, "POST", "/api/v1/links/revoke-all", "")
		if code != 200 || strings.Contains(body, `"revoked":0`) {
			t.Fatalf("revoke mine: %d %s", code, body)
		}
		if _, body = call(aliceB, "GET", "/api/v1/shared-by-me", ""); strings.Contains(body, `"type":"link"`) {
			t.Fatal("links still listed after revocation")
		}
		if code, body = call(aliceB, "POST", "/api/v1/admin/links/revoke-all", ""); code != 200 || !strings.Contains(body, `"revoked":`) {
			t.Fatalf("admin revoke: %d %s", code, body)
		}
	})

	t.Run("operator offboarding ends sessions and app passwords", func(t *testing.T) {
		carolB := h.loginOIDC(idpUser{sub: "carol", email: "carol@example.test", groups: []string{"nas-users"}})
		var ap struct{ Token string }
		req, _ := http.NewRequest("POST", h.base+"/api/v1/app-passwords", strings.NewReader(`{"name":"laptop"}`))
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Content-Type", "application/json")
		resp, err := carolB.Do(req)
		status(t, resp, err, 201)
		req, _ = http.NewRequest("POST", h.base+"/api/v1/app-passwords", strings.NewReader(`{"name":"laptop"}`))
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Content-Type", "application/json")
		resp, _ = carolB.Do(req)
		json.NewDecoder(resp.Body).Decode(&ap)
		resp.Body.Close()
		carolApp := client.New(h.base, h.srv.Client(), ap.Token)
		me := must[*client.Me](t)(carolApp.Me(ctx))
		if _, err := client.New(h.base, carolB, "").Me(ctx); err != nil {
			t.Fatal(err)
		}

		n, err := h.am.RevokeUserCredentials(ctx, me.User.ID)
		if err != nil || n != 2 {
			t.Fatalf("revoked %d app passwords: %v", n, err)
		}
		if _, err := client.New(h.base, carolB, "").Me(ctx); err == nil {
			t.Fatal("browser session survived offboarding")
		}
		if _, err := carolApp.Me(ctx); err == nil {
			t.Fatal("app password survived offboarding")
		}
		if _, err := h.am.RevokeUserCredentials(ctx, ""); err == nil {
			t.Fatal("empty user accepted")
		}
	})
}
