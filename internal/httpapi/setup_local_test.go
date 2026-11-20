package httpapi_test

import (
	"context"
	"encoding/base32"
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

	"github.com/woah-buddy/FrontDir/internal/auth"
	"github.com/woah-buddy/FrontDir/internal/blob/fsblob"
	"github.com/woah-buddy/FrontDir/internal/config"
	"github.com/woah-buddy/FrontDir/internal/httpapi"
	"github.com/woah-buddy/FrontDir/internal/secure"
	"github.com/woah-buddy/FrontDir/internal/service"
	"github.com/woah-buddy/FrontDir/internal/settings"
	"github.com/woah-buddy/FrontDir/internal/testutil"
	"github.com/woah-buddy/FrontDir/web"
)

// A server with no identity provider at all, set up with a local
// administrator through the one-time setup link.
func TestSetupWithLocalAdmin(t *testing.T) {
	store := testutil.Postgres(t)
	blobs, err := fsblob.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
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
	sealer, _ := secure.NewSealer(fixed.SettingsKey, "frontdir/totp-secrets/v1")
	am.SetLocalSealer(sealer)
	base := time.Unix(secure.TOTPStep(time.Now())*30+15, 0).UTC()
	am.SetClock(func() time.Time { return base })
	sm, err := settings.New(fixed, store, svc, am, log)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := sm.Load(ctx); err != nil {
		t.Fatal(err)
	}
	handler = httpapi.New(svc, am, httpapi.Config{PublicURL: pub, Settings: sm,
		RateLimits: httpapi.RateLimits{Login: 6000, Public: 6000, AuthFailures: 6000}}, log, web.Static(), store, blobs).Handler()
	jar, _ := cookiejar.New(nil)
	b := *srv.Client()
	b.Jar = jar
	call := func(method, path string, body any) (int, map[string]any) {
		t.Helper()
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(string(raw)))
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

	if code, m := call("GET", "/api/v1/auth/methods", nil); code != 200 || m["setup"] != true || m["local"] != false {
		t.Fatalf("methods before setup: %v", m)
	}
	link, _, err := settings.NewSetupLink(ctx, store, fixed, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	token := link[strings.Index(link, "#")+1:]
	if code, _ := call("POST", "/api/v1/setup/local", map[string]string{"token": "x" + token[1:], "email": "root@example.test"}); code != 401 {
		t.Fatalf("wrong setup token: %d", code)
	}
	code, inv := call("POST", "/api/v1/setup/local", map[string]string{"token": token, "email": "root@example.test", "displayName": "Root"})
	if code != http.StatusCreated {
		t.Fatalf("setup local: %d %v", code, inv)
	}
	// Local accounts are on now, and the setup link is used up.
	if _, m := call("GET", "/api/v1/auth/methods", nil); m["local"] != true || m["setup"] != false {
		t.Fatalf("methods after setup: %v", m)
	}
	if code, _ := call("POST", "/api/v1/setup/local", map[string]string{"token": token, "email": "second@example.test"}); code != 401 {
		t.Fatalf("setup link reused: %d", code)
	}
	_, en := call("POST", "/api/v1/auth/local/enroll", map[string]string{"token": inv["token"].(string), "password": "a long and lovely passphrase"})
	secret, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(en["secret"].(string))
	if code, _ := call("POST", "/api/v1/auth/local/enroll/finish", map[string]string{"ticket": en["ticket"].(string),
		"code": secure.TOTPCode(secret, secure.TOTPStep(base))}); code != 200 {
		t.Fatalf("enrol: %d", code)
	}
	// Without an identity provider, the local account administers, and its
	// fresh sign-in counts for changes.
	if code, m := call("GET", "/api/v1/me", nil); code != 200 || m["user"].(map[string]any)["admin"] != true {
		t.Fatalf("me: %v", m)
	}
	_, v := call("GET", "/api/v1/admin/settings", nil)
	rev, _ := v["revision"].(float64)
	if code, m := call("PUT", "/api/v1/admin/settings", map[string]any{"revision": rev, "set": map[string]string{"TEAM_CREATION": "false"}}); code >= 300 {
		t.Fatalf("admin change after local sign-in: %d %v", code, m)
	}
}
