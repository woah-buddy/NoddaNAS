package httpapi_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/woah-buddy/NoddaNAS/internal/auth"
	"github.com/woah-buddy/NoddaNAS/internal/blob/fsblob"
	"github.com/woah-buddy/NoddaNAS/internal/config"
	"github.com/woah-buddy/NoddaNAS/internal/httpapi"
	"github.com/woah-buddy/NoddaNAS/internal/service"
	"github.com/woah-buddy/NoddaNAS/internal/settings"
	"github.com/woah-buddy/NoddaNAS/internal/testutil"
	"github.com/woah-buddy/NoddaNAS/web"
)

// A server started with no sign-in method, set up through the one-time
// link, then administered from the web: the whole path a new deployment
// takes, against the real HTTP stack and a (fake) OpenID provider.
func TestSetupLinkAndWebSettings(t *testing.T) {
	store := testutil.Postgres(t)
	blobs, err := fsblob.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	idp := newFakeOIDC(t)
	var handler http.Handler
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	pub, _ := url.Parse(srv.URL)
	fixed := &config.Config{PublicURL: pub, WebSettings: true, SettingsKey: make([]byte, 32), Env: config.Values{}}
	rt, err := config.Build(fixed.Env, fixed)
	if err != nil {
		t.Fatal(err)
	}
	svc := service.New(store, blobs, rt.Service, log)
	am := auth.NewManager(store, svc, rt.Auth, nil, nil)
	sm, err := settings.New(fixed, store, svc, am, log)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := sm.Load(ctx); err != nil {
		t.Fatal(err)
	}
	api := httpapi.New(svc, am, httpapi.Config{PublicURL: pub, Settings: sm,
		RateLimits: httpapi.RateLimits{Login: 6000, Public: 6000, AuthFailures: 6000}}, log, web.Static(), store, blobs)
	sm.OnApply(func(rt *config.Runtime) { api.SetTheme(rt.Theme) })
	handler = api.Handler()

	browser := func() *http.Client {
		jar, _ := cookiejar.New(nil)
		c := *srv.Client()
		c.Jar = jar
		return &c
	}
	call := func(b *http.Client, method, path string, body any) (int, map[string]any) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			rd = strings.NewReader(string(raw))
		}
		req, _ := http.NewRequest(method, srv.URL+path, rd)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Content-Type", "application/json")
		resp, err := b.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out := map[string]any{}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	follow := func(b *http.Client, to string) *url.URL {
		t.Helper()
		resp, err := b.Get(to)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.Request.URL
	}

	// A new server says it needs setting up, and serves no sign-in.
	anon := browser()
	if code, m := call(anon, "GET", "/api/v1/auth/methods", nil); code != 200 || m["setup"] != true || m["oidc"] != false {
		t.Fatalf("methods: %d %v", code, m)
	}
	link, _, err := settings.NewSetupLink(ctx, store, fixed, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	token := link[strings.Index(link, "#")+1:]

	// The setup page: a wrong token gets nothing; the right one the sign-in settings.
	if code, _ := call(anon, "POST", "/api/v1/setup/view", map[string]any{"token": "x" + token[1:]}); code != 401 {
		t.Fatalf("wrong token: %d", code)
	}
	code, view := call(anon, "POST", "/api/v1/setup/view", map[string]any{"token": token})
	if code != 200 || view["setupMode"] != true {
		t.Fatalf("setup view: %d %v", code, view)
	}
	// A typo is caught by trying the provider before saving.
	code, m := call(anon, "POST", "/api/v1/setup/save", map[string]any{"token": token, "revision": view["revision"],
		"set": map[string]string{"OIDC_ISSUER": idp.srv.URL + "/typo", "OIDC_CLIENT_ID": "noddanas"}})
	if code != 400 || !strings.Contains(jsonString(m), "OIDC_ISSUER") {
		t.Fatalf("typo saved: %d %v", code, m)
	}
	code, m = call(anon, "POST", "/api/v1/setup/save", map[string]any{"token": token, "revision": view["revision"],
		"set": map[string]string{"OIDC_ISSUER": idp.srv.URL, "OIDC_CLIENT_ID": "noddanas", "OIDC_CLIENT_SECRET": "s3cret"}})
	if code != 200 || m["setupMode"] != false {
		t.Fatalf("setup save: %d %v", code, m)
	}

	// Finish by signing in through the link: a forced sign-in that makes
	// this person the first administrator.
	ada := browser()
	idp.next = idpUser{sub: "ada", email: "ada@example.test"}
	code, m = call(ada, "POST", "/api/v1/setup/login", map[string]any{"token": token, "method": "oidc"})
	if code != 200 {
		t.Fatalf("setup login: %d %v", code, m)
	}
	if end := follow(ada, m["redirect"].(string)); end.Path != "/admin" {
		t.Fatalf("setup sign-in ended at %s", end)
	}
	if p := idp.prompts[len(idp.prompts)-1]; p != "login" {
		t.Fatalf("setup sign-in was not forced (prompt=%q)", p)
	}
	if _, me := call(ada, "GET", "/api/v1/me", nil); me["user"].(map[string]any)["admin"] != true {
		t.Fatalf("setup did not make an administrator: %v", me)
	}
	if code, _ := call(anon, "POST", "/api/v1/setup/view", map[string]any{"token": token}); code != 401 {
		t.Fatalf("setup link still works after use: %d", code)
	}

	// The admin area: secrets are never sent back.
	code, view = call(ada, "GET", "/api/v1/admin/settings", nil)
	if code != 200 || strings.Contains(jsonString(view), "s3cret") {
		t.Fatalf("settings view: %d", code)
	}
	if _, s := call(ada, "GET", "/api/v1/admin/session", nil); s["recent"] != true {
		t.Fatalf("setup sign-in is not recent: %v", s)
	}
	code, m = call(ada, "PUT", "/api/v1/admin/settings", map[string]any{"revision": view["revision"],
		"set": map[string]string{"DEFAULT_QUOTA": "2GiB", "BRAND_NAME": "Acme Files"}})
	if code != 200 || svc.Config().DefaultQuota != 2<<30 {
		t.Fatalf("update: %d %v", code, m)
	}
	if _, b := call(anon, "GET", "/api/v1/branding", nil); b["name"] != "Acme Files" {
		t.Fatalf("branding not live: %v", b)
	}

	// Someone else signs in normally: not an administrator.
	bob := browser()
	idp.next = idpUser{sub: "bob", email: "bob@example.test"}
	if end := follow(bob, srv.URL+"/auth/login?return_to=/files"); end.Path != "/files" {
		t.Fatalf("bob: %s", end)
	}
	if code, _ := call(bob, "GET", "/api/v1/admin/settings", nil); code != 403 {
		t.Fatalf("non-admin settings: %d", code)
	}
	code, users := call(ada, "GET", "/api/v1/admin/users", nil)
	list := users["users"].([]any)
	if code != 200 || len(list) != 2 {
		t.Fatalf("users: %d %v", code, users)
	}
	var bobID string
	for _, u := range list {
		if u.(map[string]any)["displayName"] == "bob" {
			bobID = u.(map[string]any)["id"].(string)
		}
	}
	if code, m := call(ada, "PUT", "/api/v1/admin/users/"+bobID+"/quota", map[string]string{"size": "1GiB"}); code != 204 {
		t.Fatalf("quota: %d %v", code, m)
	}
	if code, _ := call(ada, "PUT", "/api/v1/admin/users/"+bobID+"/admin", map[string]bool{"admin": true}); code != 204 {
		t.Fatalf("appoint: %d", code)
	}

	// Bob is now an administrator but has not confirmed it's him.
	_, view = call(bob, "GET", "/api/v1/admin/settings", nil)
	code, m = call(bob, "PUT", "/api/v1/admin/settings", map[string]any{"revision": view["revision"], "set": map[string]string{"MAX_VERSIONS": "5"}})
	if code != 403 || jsonString(m["error"].(map[string]any)["code"]) != `"reauth_required"` {
		t.Fatalf("change without re-authentication: %d %v", code, m)
	}
	// An IdP that does not really re-authenticate is caught by auth_time.
	idp.authAge = time.Hour
	if end := follow(bob, srv.URL+"/auth/reauth?return_to=/admin"); end.Path != "/" || end.Query().Get("error") != "signin" {
		t.Fatalf("stale auth_time accepted: %s", end)
	}
	idp.authAge = 0
	if end := follow(bob, srv.URL+"/auth/reauth?return_to=/admin"); end.Path != "/admin" {
		t.Fatalf("re-authentication: %s", end)
	}
	if p := idp.prompts[len(idp.prompts)-1]; p != "login" {
		t.Fatalf("re-authentication not forced: %q", p)
	}
	if code, m := call(bob, "PUT", "/api/v1/admin/settings", map[string]any{"revision": view["revision"],
		"set": map[string]string{"MAX_VERSIONS": "5"}}); code != 200 {
		t.Fatalf("change after re-authentication: %d %v", code, m)
	}
	// Ada's view is now stale: the conflict is reported, not overwritten.
	if code, _ := call(ada, "PUT", "/api/v1/admin/settings", map[string]any{"revision": view["revision"],
		"set": map[string]string{"MAX_VERSIONS": "7"}}); code != 412 {
		t.Fatalf("lost update: %d", code)
	}
}

func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
