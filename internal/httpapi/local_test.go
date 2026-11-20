package httpapi_test

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/woah-buddy/FrontDir/internal/secure"
	"github.com/woah-buddy/FrontDir/internal/testutil"
)

// Local accounts end to end: an administrator creates one, its owner sets a
// password and an authenticator through the invite, signs in with both,
// and every way around them fails.
func TestLocalAccounts(t *testing.T) {
	store, schema := testutil.PostgresSchema(t)
	h := newHarnessWith(t, harnessOpts{store: store, local: true})
	// Hold the sign-in clock in the middle of the current 30-second step, so
	// codes computed here stay valid however long the test takes.
	base := time.Unix(secure.TOTPStep(time.Now())*30+15, 0).UTC()
	h.am.SetClock(func() time.Time { return base })
	sql := func(q string, args ...any) int64 { t.Helper(); return testutil.Exec(t, schema, q, args...) }
	post := func(b *http.Client, path string, body any) (int, map[string]any) {
		t.Helper()
		raw, _ := json.Marshal(body)
		resp, err := b.Post(h.base+path, "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out := map[string]any{}
		b2, _ := io.ReadAll(resp.Body)
		json.Unmarshal(b2, &out)
		return resp.StatusCode, out
	}
	get := func(b *http.Client, path string) int {
		t.Helper()
		resp, err := b.Get(h.base + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	errMsg := func(m map[string]any) string {
		e, _ := m["error"].(map[string]any)
		s, _ := e["message"].(string)
		return s
	}

	// An administrator (from the IdP) creates the account, after confirming
	// who they are.
	admin := idpUser{sub: "boss", email: "boss@example.test", groups: []string{"nas-users", "nas-admins"}}
	ab := h.loginOIDC(admin)
	if code, m := post(ab, "/api/v1/admin/local-accounts", map[string]any{"email": "carol@example.test"}); code != http.StatusForbidden && code != 401 {
		t.Fatalf("stale admin session created an account: %d %v", code, m)
	}
	h.reauth(ab, admin)
	// With an identity provider configured, local administrators need the setting.
	if code, _ := post(ab, "/api/v1/admin/local-accounts", map[string]any{"email": "carol@example.test", "admin": true}); code != http.StatusBadRequest {
		t.Fatalf("local admin without the setting: %d", code)
	}
	code, m := post(ab, "/api/v1/admin/local-accounts", map[string]any{"email": "Carol@Example.test", "displayName": "Carol"})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, m)
	}
	invite := m["token"].(string)
	if code, _ := post(ab, "/api/v1/admin/local-accounts", map[string]any{"email": "carol@example.test"}); code != http.StatusConflict {
		t.Fatalf("duplicate email: %d", code)
	}

	// The invite: password rules, then the authenticator, confirmed by a code.
	cb := h.browser()
	if code, m := post(cb, "/api/v1/auth/local/invite", map[string]string{"token": invite}); code != 200 || m["email"] != "carol@example.test" {
		t.Fatalf("invite view: %d %v", code, m)
	}
	for _, weak := range []string{"short", "password1234", "aaaaaaaaaaaaaaaa", "carol-is-great-123"} {
		if code, _ := post(cb, "/api/v1/auth/local/enroll", map[string]string{"token": invite, "password": weak}); code != http.StatusBadRequest {
			t.Errorf("weak password %q accepted: %d", weak, code)
		}
	}
	password := "correct horse battery staple"
	code, en := post(cb, "/api/v1/auth/local/enroll", map[string]string{"token": invite, "password": password})
	if code != 200 || en["qr"] == "" || !strings.HasPrefix(en["uri"].(string), "otpauth://totp/") {
		t.Fatalf("enroll: %d %v", code, en)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(en["secret"].(string))
	if err != nil {
		t.Fatal(err)
	}
	// TOTP steps: each code works once, and only one step either side of
	// now is accepted, so the test uses now-1, now and now+1 in turn.
	step := secure.TOTPStep(base)
	codeAt := func(d int64) string { return secure.TOTPCode(secret, step+d) }
	if code, _ := post(cb, "/api/v1/auth/local/enroll/finish", map[string]string{"ticket": en["ticket"].(string), "code": "000000"}); code != 401 {
		t.Fatalf("wrong first code: %d", code)
	}
	if get(cb, "/api/v1/me") != 401 {
		t.Fatal("signed in before the authenticator was confirmed")
	}
	code, fin := post(cb, "/api/v1/auth/local/enroll/finish", map[string]string{"ticket": en["ticket"].(string), "code": codeAt(-1)})
	if code != 200 {
		t.Fatalf("finish: %d %v", code, fin)
	}
	recovery := fin["recoveryCodes"].([]any)
	if len(recovery) != 10 || get(cb, "/api/v1/me") != 200 {
		t.Fatalf("after enrolment: %d codes", len(recovery))
	}
	if code, _ := post(h.browser(), "/api/v1/auth/local/invite", map[string]string{"token": invite}); code != 401 {
		t.Fatal("invite works twice")
	}

	// Signing in: wrong passwords and unknown emails look the same.
	login := func(email, pw string) (int, map[string]any) {
		return post(h.browser(), "/api/v1/auth/local/login", map[string]string{"email": email, "password": pw})
	}
	c1, m1 := login("carol@example.test", "wrong password here")
	c2, m2 := login("nobody@example.test", "wrong password here")
	if c1 != 401 || c2 != 401 || errMsg(m1) != errMsg(m2) {
		t.Fatalf("enumeration: %d %q vs %d %q", c1, errMsg(m1), c2, errMsg(m2))
	}
	b := h.browser()
	code, tk := post(b, "/api/v1/auth/local/login", map[string]string{"email": "CAROL@example.test", "password": password})
	if code != 200 {
		t.Fatalf("password step: %d %v", code, tk)
	}
	if get(b, "/api/v1/me") != 401 {
		t.Fatal("a password alone signed in")
	}
	// The code used at enrolment is spent.
	if code, _ := post(b, "/api/v1/auth/local/code", map[string]string{"ticket": tk["ticket"].(string), "code": codeAt(-1)}); code != 401 {
		t.Fatalf("replayed code: %d", code)
	}
	if code, _ := post(b, "/api/v1/auth/local/code", map[string]string{"ticket": tk["ticket"].(string), "code": codeAt(0)}); code != 200 || get(b, "/api/v1/me") != 200 {
		t.Fatalf("code step: %d", code)
	}
	// "Confirm it's you" with password and the next code.
	if code, _ := post(b, "/api/v1/auth/local/reauth", map[string]string{"password": "nope nope nope", "code": codeAt(1)}); code != 401 {
		t.Fatalf("reauth with a wrong password: %d", code)
	}
	if code, _ := post(b, "/api/v1/auth/local/reauth", map[string]string{"password": password, "code": codeAt(1)}); code != 204 {
		t.Fatalf("reauth: %d", code)
	}
	// Recovery codes: each works once.
	rb := h.browser()
	_, tk = post(rb, "/api/v1/auth/local/login", map[string]string{"email": "carol@example.test", "password": password})
	if code, _ := post(rb, "/api/v1/auth/local/code", map[string]string{"ticket": tk["ticket"].(string), "code": strings.ToLower(recovery[0].(string))}); code != 200 {
		t.Fatalf("recovery code: %d", code)
	}
	_, tk = post(h.browser(), "/api/v1/auth/local/login", map[string]string{"email": "carol@example.test", "password": password})
	if code, _ := post(h.browser(), "/api/v1/auth/local/code", map[string]string{"ticket": tk["ticket"].(string), "code": recovery[0].(string)}); code != 401 {
		t.Fatalf("recovery code reused: %d", code)
	}
	// A ticket allows a handful of guesses, then it is gone.
	gb := h.browser()
	_, tk = post(gb, "/api/v1/auth/local/login", map[string]string{"email": "carol@example.test", "password": password})
	for range 5 {
		post(gb, "/api/v1/auth/local/code", map[string]string{"ticket": tk["ticket"].(string), "code": "123456"})
	}
	sql(`UPDATE local_logins SET totp_last_step = 0, failed_attempts = 0`) // as if time had moved on
	if code, _ := post(gb, "/api/v1/auth/local/code", map[string]string{"ticket": tk["ticket"].(string), "code": codeAt(0)}); code != 401 {
		t.Fatalf("ticket survived its guesses: %d", code)
	}
	// The TOTP secret is not stored in the clear.
	if n := sql(`UPDATE local_logins SET login = login WHERE totp_secret LIKE 'sealed:v1:%' AND password_hash LIKE '$argon2id$%'`); n != 1 {
		t.Fatal("credentials not sealed and hashed")
	}

	// Lockout: ten wrong passwords lock the account, even for the right one.
	for range 10 {
		login("carol@example.test", "wrong password again")
	}
	if code, _ := login("carol@example.test", password); code != 401 {
		t.Fatalf("locked account accepted its password: %d", code)
	}
	sql(`UPDATE local_logins SET locked_until = NULL, failed_attempts = 0`)

	// An administrator's reset stops everything at once and issues a link.
	carolID := ""
	{
		var me map[string]any
		resp, _ := b.Get(h.base + "/api/v1/me")
		json.NewDecoder(resp.Body).Decode(&me)
		resp.Body.Close()
		carolID = me["user"].(map[string]any)["id"].(string)
		if me["user"].(map[string]any)["local"] != true {
			t.Fatal("me does not say local")
		}
	}
	code, rs := post(ab, "/api/v1/admin/users/"+carolID+"/local-reset", nil)
	if code != 200 {
		t.Fatalf("reset: %d %v", code, rs)
	}
	if get(b, "/api/v1/me") != 401 {
		t.Fatal("session survived the reset")
	}
	if code, _ := login("carol@example.test", password); code != 401 {
		t.Fatal("old password works after the reset")
	}
	nb := h.browser()
	code, m = post(nb, "/api/v1/auth/local/invite", map[string]string{"token": rs["token"].(string)})
	if code != 200 || m["reset"] != true {
		t.Fatalf("reset link: %d %v", code, m)
	}
	_, en = post(nb, "/api/v1/auth/local/enroll", map[string]string{"token": rs["token"].(string), "password": "a different long passphrase"})
	secret2, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(en["secret"].(string))
	if code, _ := post(nb, "/api/v1/auth/local/enroll/finish", map[string]string{"ticket": en["ticket"].(string),
		"code": secure.TOTPCode(secret2, step)}); code != 200 {
		t.Fatalf("re-enrol: %d", code)
	}
	// Offboarding disables the account until it is reset again.
	h.reauth(ab, admin)
	if code, _ := post(ab, "/api/v1/admin/users/"+carolID+"/revoke-access", nil); code != 200 {
		t.Fatalf("revoke: %d", code)
	}
	if code, _ := login("carol@example.test", "a different long passphrase"); code != 401 {
		t.Fatal("revoked local account can still sign in")
	}

	// Local administrators count only while allowed.
	cfg := h.svc.Config()
	cfg.LocalAdmins = true
	h.svc.SetConfig(cfg)
	h.reauth(ab, admin)
	code, m = post(ab, "/api/v1/admin/local-accounts", map[string]any{"email": "dana@example.test", "admin": true})
	if code != http.StatusCreated {
		t.Fatalf("local admin: %d %v", code, m)
	}
	db := h.browser()
	_, en = post(db, "/api/v1/auth/local/enroll", map[string]string{"token": m["token"].(string), "password": "a lovely long passphrase"})
	secret3, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(en["secret"].(string))
	post(db, "/api/v1/auth/local/enroll/finish", map[string]string{"ticket": en["ticket"].(string), "code": secure.TOTPCode(secret3, step)})
	if get(db, "/api/v1/admin/users") != 200 {
		t.Fatal("local administrator refused")
	}
	cfg.LocalAdmins = false
	h.svc.SetConfig(cfg)
	if get(db, "/api/v1/admin/users") != http.StatusForbidden {
		t.Fatal("local administrator kept rights after they were disallowed")
	}

	// Turning local accounts off stops their sign-in.
	cfg.LocalAccounts = false
	h.svc.SetConfig(cfg)
	if code, _ := login("dana@example.test", "a lovely long passphrase"); code != http.StatusForbidden {
		t.Fatalf("local sign-in while off: %d", code)
	}
}
