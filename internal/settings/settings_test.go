package settings

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/woah-buddy/NoddaNAS/internal/auth"
	"github.com/woah-buddy/NoddaNAS/internal/blob/fsblob"
	"github.com/woah-buddy/NoddaNAS/internal/config"
	"github.com/woah-buddy/NoddaNAS/internal/domain"
	"github.com/woah-buddy/NoddaNAS/internal/secure"
	"github.com/woah-buddy/NoddaNAS/internal/service"
	"github.com/woah-buddy/NoddaNAS/internal/store/postgres"
	"github.com/woah-buddy/NoddaNAS/internal/testutil"
)

func TestSecretBox(t *testing.T) {
	key := make([]byte, 32)
	b, _ := newSecretBox(key)
	sealed := b.seal("OIDC_CLIENT_SECRET", "hunter2")
	if !strings.HasPrefix(sealed, encPrefix) || strings.Contains(sealed, "hunter2") {
		t.Fatalf("not sealed: %s", sealed)
	}
	if pt, err := b.open("OIDC_CLIENT_SECRET", sealed); err != nil || pt != "hunter2" {
		t.Fatalf("open: %q %v", pt, err)
	}
	if b.seal("OIDC_CLIENT_SECRET", "hunter2") == sealed {
		t.Fatal("nonce reused")
	}
	// Bound to its setting name, and to the key.
	if _, err := b.open("OTHER", sealed); err == nil {
		t.Fatal("ciphertext moved to another setting decrypted")
	}
	other := make([]byte, 32)
	other[0] = 1
	b2, _ := newSecretBox(other)
	if _, err := b2.open("OIDC_CLIENT_SECRET", sealed); err == nil {
		t.Fatal("decrypted with the wrong key")
	}
	if _, err := b.open("OIDC_CLIENT_SECRET", "hunter2"); !errors.Is(err, errNotEncrypted) {
		t.Fatalf("plaintext accepted: %v", err)
	}
}

type fixture struct {
	t     *testing.T
	ctx   context.Context
	store *postgres.Store
	svc   *service.Service
	am    *auth.Manager
	fixed *config.Config
	m     *Manager
}

func newFixture(t *testing.T, env config.Values) *fixture {
	t.Helper()
	st := testutil.Postgres(t)
	blobs, err := fsblob.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	pub, _ := url.Parse("https://files.example.com")
	fixed := &config.Config{PublicURL: pub, WebSettings: true, SettingsKey: make([]byte, 32), Env: env}
	rt, err := config.Build(env, fixed)
	if err != nil {
		t.Fatal(err)
	}
	svc := service.New(st, blobs, rt.Service, log)
	am := auth.NewManager(st, svc, rt.Auth, nil, nil)
	f := &fixture{t: t, ctx: context.Background(), store: st, svc: svc, am: am, fixed: fixed}
	f.m = f.manager()
	return f
}

func (f *fixture) manager() *Manager {
	f.t.Helper()
	m, err := New(f.fixed, f.store, f.svc, f.am, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		f.t.Fatal(err)
	}
	m.CheckOIDC = func(_ context.Context, c auth.OIDCConfig) error {
		if strings.Contains(c.Issuer, "broken") {
			return errors.New("could not read the discovery document: the host name could not be resolved")
		}
		return nil
	}
	m.CheckSAML = func(context.Context, auth.SAMLConfig) (string, error) { return "https://idp.example.com/saml", nil }
	if err := m.Load(f.ctx); err != nil {
		f.t.Fatal(err)
	}
	return m
}

// person signs someone in (as the IdP would) and returns a principal with a
// recent sign-in.
func (f *fixture) person(sub, email string, groups ...string) service.Principal {
	f.t.Helper()
	u, err := f.svc.LoginUser(f.ctx, service.Identity{Issuer: "https://id.example.com", Subject: sub, Email: email,
		EmailVerified: true, Name: sub, Groups: groups})
	if err != nil {
		f.t.Fatal(err)
	}
	return service.Principal{UserID: u.ID, ReauthAt: time.Now()}
}

func (f *fixture) update(p service.Principal, set map[string]string, confirm ...string) (*View, error) {
	f.t.Helper()
	v, err := f.m.View(f.ctx, p)
	if err != nil {
		return nil, err
	}
	return f.m.Update(f.ctx, p, UpdateRequest{Revision: v.Revision, Set: set, Confirm: confirm})
}

func wantField(t *testing.T, err error, key string) {
	t.Helper()
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeInvalid || de.Detail[key] == "" {
		t.Fatalf("want a field error on %s, got %v (%+v)", key, err, de)
	}
}

func field(v *View, key string) Field {
	for _, f := range v.Fields {
		if f.Key == key {
			return f
		}
	}
	return Field{}
}

var envOIDC = config.Values{"OIDC_ISSUER": "https://id.example.com", "OIDC_CLIENT_ID": "env-client"}

func TestUpdateRules(t *testing.T) {
	f := newFixture(t, config.Values{"OIDC_ISSUER": "https://id.example.com", "OIDC_CLIENT_ID": "env-client", "MAX_VERSIONS": "3",
		"ADMIN_GROUPS": "nas-admins"})
	admin := f.person("ada", "ada@example.com", "nas-admins")
	user := f.person("bob", "bob@example.com")

	// Administrators only; changes need a recent sign-in.
	if _, err := f.m.View(f.ctx, user); domain.CodeOf(err) != domain.CodeForbidden {
		t.Fatalf("non-admin view: %v", err)
	}
	stale := admin
	stale.ReauthAt = time.Time{}
	if _, err := f.update(stale, map[string]string{"DEFAULT_QUOTA": "5GiB"}); domain.CodeOf(err) != domain.CodeReauth {
		t.Fatalf("change without a recent sign-in: %v", err)
	}

	v, err := f.update(admin, map[string]string{"DEFAULT_QUOTA": "5GiB", "LINK_MAX_TTL": "90d"})
	if err != nil {
		t.Fatal(err)
	}
	if f.svc.Config().DefaultQuota != 5<<30 || f.svc.Config().LinkMaxTTL != 90*24*time.Hour {
		t.Fatalf("not applied: %+v", f.svc.Config())
	}
	if fq := field(v, "DEFAULT_QUOTA"); fq.Source != config.SourceWeb || fq.Value != "5GiB" || fq.Locked {
		t.Fatalf("view: %+v", fq)
	}
	// Set in the environment: locked, as is all of OIDC.
	if fv := field(v, "MAX_VERSIONS"); !fv.Locked || fv.Source != config.SourceServer {
		t.Fatalf("env setting not locked: %+v", fv)
	}
	_, err = f.update(admin, map[string]string{"MAX_VERSIONS": "50"})
	wantField(t, err, "MAX_VERSIONS")
	_, err = f.update(admin, map[string]string{"OIDC_SCOPES": "openid"})
	wantField(t, err, "OIDC_SCOPES")
	// Validation is the same as for the environment.
	_, err = f.update(admin, map[string]string{"LINK_DEFAULT_TTL": "100d"})
	wantField(t, err, "LINK_DEFAULT_TTL")
	// A stale revision is refused (two administrators at once).
	_, err = f.m.Update(f.ctx, admin, UpdateRequest{Revision: 0, Set: map[string]string{"DEFAULT_QUOTA": "6GiB"}})
	if domain.CodeOf(err) != domain.CodePrecondition {
		t.Fatalf("stale revision: %v", err)
	}
	// Empty returns to the default.
	if _, err = f.update(admin, map[string]string{"DEFAULT_QUOTA": ""}); err != nil || f.svc.Config().DefaultQuota != 10<<30 {
		t.Fatalf("reset to default: %v", err)
	}

	// Lockout guards: not out of sign-in, not out of administration.
	_, err = f.update(admin, map[string]string{"ALLOWED_GROUPS": "nas-users"})
	wantField(t, err, "ALLOWED_GROUPS")
	_, err = f.update(admin, map[string]string{"ALLOWED_EMAIL_DOMAINS": "other.example"})
	wantField(t, err, "ALLOWED_EMAIL_DOMAINS")
	if _, err = f.update(admin, map[string]string{"ALLOWED_GROUPS": "nas-admins, nas-users"}); err != nil {
		t.Fatalf("policy that keeps the admin in: %v", err)
	}
}

func TestAdminGroupsApplyImmediatelyAndGuardSelf(t *testing.T) {
	f := newFixture(t, envOIDC)
	// The first administrator was appointed (e.g. through the setup link).
	ada := f.person("ada", "ada@example.com", "staff")
	if err := f.store.SetAdminGranted(f.ctx, ada.UserID, true, nil); err != nil {
		t.Fatal(err)
	}
	carol := f.person("carol", "carol@example.com", "it")
	if u, _ := f.svc.UserByID(f.ctx, carol.UserID); u.Admin {
		t.Fatal("carol is admin before her group is")
	}
	if _, err := f.update(ada, map[string]string{"ADMIN_GROUPS": "it"}); err != nil {
		t.Fatal(err)
	}
	if u, _ := f.svc.UserByID(f.ctx, carol.UserID); !u.Admin {
		t.Fatal("administrator groups did not apply until the next sign-in")
	}
	// Carol is an administrator only through her group: she cannot remove it.
	_, err := f.update(carol, map[string]string{"ADMIN_GROUPS": "other"})
	wantField(t, err, "ADMIN_GROUPS")
	// Ada (appointed) can, and Carol loses administrator rights at once.
	if _, err := f.update(ada, map[string]string{"ADMIN_GROUPS": ""}); err != nil {
		t.Fatal(err)
	}
	if u, _ := f.svc.UserByID(f.ctx, carol.UserID); u.Admin {
		t.Fatal("removing the group did not remove administrator rights")
	}
	// Nobody changes their own appointment.
	if err := f.svc.AdminSetAdmin(f.ctx, ada, ada.UserID, false); domain.CodeOf(err) != domain.CodeForbidden {
		t.Fatalf("self demotion: %v", err)
	}
	if err := f.svc.AdminSetAdmin(f.ctx, ada, carol.UserID, true); err != nil {
		t.Fatal(err)
	}
	// An appointment survives the next sign-in without the group.
	carolU, _ := f.svc.LoginUser(f.ctx, service.Identity{Issuer: "https://id.example.com", Subject: "carol", Email: "carol@example.com", EmailVerified: true})
	if !carolU.Admin {
		t.Fatal("appointment lost at sign-in")
	}
}

func TestSignInChangesAreCheckedAndConfirmed(t *testing.T) {
	f := newFixture(t, config.Values{})
	// Setup mode: no sign-in method.
	if !f.m.SetupMode() {
		t.Fatal("not in setup mode")
	}
	link, _, err := NewSetupLink(f.ctx, f.store, f.fixed, time.Now())
	if err != nil || !strings.HasPrefix(link, "https://files.example.com/setup#") {
		t.Fatalf("link %q %v", link, err)
	}
	token := strings.TrimPrefix(link, "https://files.example.com/setup#")
	if _, err := f.m.SetupView(f.ctx, secure.NewToken()); domain.CodeOf(err) != domain.CodeUnauthorized {
		t.Fatalf("wrong token: %v", err)
	}
	v, err := f.m.SetupView(f.ctx, token)
	if err != nil || field(v, "DEFAULT_QUOTA").Key != "" || field(v, "OIDC_ISSUER").Key == "" {
		t.Fatalf("setup view: %v", err)
	}
	if _, err := f.m.SetupLogin(f.ctx, token); domain.CodeOf(err) != domain.CodePrecondition {
		t.Fatalf("setup sign-in before a method exists: %v", err)
	}
	// The setup link changes sign-in settings only.
	_, err = f.m.SetupSave(f.ctx, token, UpdateRequest{Revision: v.Revision, Set: map[string]string{"DEFAULT_QUOTA": "1GiB"}})
	wantField(t, err, "DEFAULT_QUOTA")
	// The IdP is tried before saving.
	_, err = f.m.SetupSave(f.ctx, token, UpdateRequest{Revision: v.Revision,
		Set: map[string]string{"OIDC_ISSUER": "https://broken.example.com", "OIDC_CLIENT_ID": "c"}})
	wantField(t, err, "OIDC_ISSUER")
	v, err = f.m.SetupSave(f.ctx, token, UpdateRequest{Revision: v.Revision,
		Set: map[string]string{"OIDC_ISSUER": "https://id.example.com", "OIDC_CLIENT_ID": "c", "OIDC_CLIENT_SECRET": "s3cret-value"}})
	if err != nil || f.m.SetupMode() {
		t.Fatalf("setup save: %v", err)
	}
	if fs := field(v, "OIDC_CLIENT_SECRET"); fs.Value != "" || !fs.IsSet {
		t.Fatalf("secret shown or lost: %+v", fs)
	}
	if oidc, _ := f.am.Methods(); !oidc {
		t.Fatal("sign-in not applied")
	}
	// The secret is encrypted in the database.
	_, doc, _ := f.store.GetSettings(f.ctx)
	if !strings.HasPrefix(doc["OIDC_CLIENT_SECRET"], encPrefix) || strings.Contains(doc["OIDC_CLIENT_SECRET"], "s3cret") {
		t.Fatalf("secret stored as %q", doc["OIDC_CLIENT_SECRET"])
	}
	// A restarted server decrypts it ...
	if f.manager().Runtime().OIDC.ClientSecret != "s3cret-value" {
		t.Fatal("secret did not survive a restart")
	}
	// ... but not without the settings key, and says what to do.
	key := f.fixed.SettingsKey
	f.fixed.SettingsKey = nil
	m, _ := New(f.fixed, f.store, f.svc, f.am, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err := m.Load(f.ctx); err == nil || !strings.Contains(err.Error(), "settings reset OIDC_CLIENT_SECRET") {
		t.Fatalf("load without key: %v", err)
	}
	f.fixed.SettingsKey = key

	// Signing in through the link makes the first administrator, once.
	hash, err := f.m.SetupLogin(f.ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	ada := f.person("ada", "ada@example.com")
	if ok, err := f.m.ClaimSetup(f.ctx, hash, ada.UserID); !ok || err != nil {
		t.Fatalf("claim: %v %v", ok, err)
	}
	if u, _ := f.svc.UserByID(f.ctx, ada.UserID); !u.Admin || !u.AdminGranted {
		t.Fatal("setup did not make an administrator")
	}
	eve := f.person("eve", "eve@example.com")
	if ok, _ := f.m.ClaimSetup(f.ctx, hash, eve.UserID); ok {
		t.Fatal("setup link claimed twice")
	}
	if _, err := f.m.SetupView(f.ctx, token); domain.CodeOf(err) != domain.CodeUnauthorized {
		t.Fatal("setup link still works after use")
	}

	// Sign-in cannot be switched off from the web.
	_, err = f.update(ada, map[string]string{"OIDC_ISSUER": ""})
	wantField(t, err, "OIDC_ISSUER")
	// Replacing the identity provider strands existing accounts: confirm first.
	_, err = f.update(ada, map[string]string{"OIDC_ISSUER": "https://new-id.example.com"})
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeConfirm || de.Detail["confirm"] != "orphans" ||
		!strings.Contains(de.Message, "2 accounts") || !strings.Contains(de.Message, "your own account") {
		t.Fatalf("orphaning change not confirmed: %v", err)
	}
	// Adding SAML next to OIDC strands nobody.
	if _, err = f.update(ada, map[string]string{"SAML_IDP_METADATA_URL": "https://idp.example.com/md"}); err != nil {
		t.Fatalf("adding SAML: %v", err)
	}
	if _, err = f.update(ada, map[string]string{"OIDC_ISSUER": "https://new-id.example.com"}, "orphans"); err != nil {
		t.Fatalf("confirmed change: %v", err)
	}

	// Break-glass reset from the shell, picked up by a watching server.
	removed, err := Reset(f.ctx, f.store, []string{"saml"}, time.Now())
	if err != nil || len(removed) != 1 {
		t.Fatalf("reset: %v %v", removed, err)
	}
	ctx, cancel := context.WithTimeout(f.ctx, 2*time.Second)
	defer cancel()
	go f.m.Watch(ctx, 20*time.Millisecond)
	for f.m.Runtime().SAML != nil && ctx.Err() == nil {
		time.Sleep(20 * time.Millisecond)
	}
	if f.m.Runtime().SAML != nil {
		t.Fatal("reset not picked up")
	}
}

func TestReadOnlyWebSettings(t *testing.T) {
	f := newFixture(t, envOIDC)
	f.fixed.WebSettings = false
	f.m = f.manager()
	admin := f.person("ada", "ada@example.com")
	_ = f.store.SetAdminGranted(f.ctx, admin.UserID, true, nil)
	v, _ := f.m.View(f.ctx, admin)
	if !v.ReadOnly || !field(v, "DEFAULT_QUOTA").Locked {
		t.Fatal("not read-only")
	}
	if _, err := f.update(admin, map[string]string{"DEFAULT_QUOTA": "1GiB"}); domain.CodeOf(err) != domain.CodeForbidden {
		t.Fatalf("read-only change: %v", err)
	}
}
