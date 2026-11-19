// Package settings runs the settings that administrators can change in the
// web admin area: it stores them, merges them with the server environment,
// validates them with the same code that validates the environment
// (config.Build), applies them while the server runs, and guards the
// changes that could lock people out.
//
// Rules, in order:
//
//   - Reading settings needs administrator rights; changing them also needs
//     a recent sign-in (service.RequireFreshAdmin).
//   - A setting set in the server environment is locked on the web, and
//     FRONTDIR_WEB_SETTINGS=false locks all of them.
//   - Every change is validated as a whole, sign-in changes are tried
//     against the identity provider before they are saved, and changes that
//     would lock out the person making them are refused.
//   - Changes that would strand existing accounts (switching or removing
//     an identity provider) need explicit confirmation.
//   - Secrets are encrypted in the database (secretbox.go) and never shown
//     again; every change is written to the audit log (secrets as
//     "set"/"cleared", never their value).
//   - Saved settings that no longer validate stop the server from starting,
//     with instructions, rather than being skipped: skipping a broken
//     "allowed groups" would open sign-in to everyone.
package settings

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/woah-buddy/FrontDir/internal/auth"
	"github.com/woah-buddy/FrontDir/internal/config"
	"github.com/woah-buddy/FrontDir/internal/domain"
	"github.com/woah-buddy/FrontDir/internal/service"
	"github.com/woah-buddy/FrontDir/internal/theme"
)

// Store persists web settings and the setup link.
type Store interface {
	GetSettings(ctx context.Context) (int64, map[string]string, error)
	SettingsRevision(ctx context.Context) (int64, error)
	PutSettings(ctx context.Context, prevRev int64, doc map[string]string, by string, now time.Time) (int64, error)
	PutSetupToken(ctx context.Context, hash string, expires time.Time) error
	SetupTokenValid(ctx context.Context, hash string, now time.Time) (bool, error)
	ClaimSetup(ctx context.Context, hash, userID string, now time.Time) (bool, error)
	DeleteSetupToken(ctx context.Context) error
}

// Manager owns the effective settings of a running server.
type Manager struct {
	fixed *config.Config
	store Store
	svc   *service.Service
	auth  *auth.Manager
	log   *slog.Logger
	box   *secretBox // nil without a settings key
	now   func() time.Time

	// Live checks against the identity provider (replaceable in tests).
	CheckOIDC func(context.Context, auth.OIDCConfig) error
	CheckSAML func(context.Context, auth.SAMLConfig) (string, error)

	mu     sync.Mutex
	rev    int64
	stored map[string]string // as in the database (secrets encrypted)
	web    config.Values     // decrypted
	hooks  []func(*config.Runtime)
	rt     atomic.Pointer[config.Runtime]
}

// New returns a Manager. Call Load before serving.
func New(fixed *config.Config, store Store, svc *service.Service, am *auth.Manager, log *slog.Logger) (*Manager, error) {
	m := &Manager{fixed: fixed, store: store, svc: svc, auth: am, log: log,
		now: func() time.Time { return time.Now().UTC() }, CheckOIDC: auth.CheckOIDC, CheckSAML: auth.CheckSAML}
	if fixed.SettingsKey != nil {
		b, err := newSecretBox(fixed.SettingsKey)
		if err != nil {
			return nil, err
		}
		m.box = b
	}
	return m, nil
}

// OnApply registers f to receive every new runtime configuration (and the
// current one, if loaded).
func (m *Manager) OnApply(f func(*config.Runtime)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hooks = append(m.hooks, f)
	if rt := m.rt.Load(); rt != nil {
		f(rt)
	}
}

// Runtime returns the effective runtime configuration.
func (m *Manager) Runtime() *config.Runtime { return m.rt.Load() }

// SetupMode reports whether no sign-in method is configured yet.
func (m *Manager) SetupMode() bool {
	rt := m.rt.Load()
	return rt == nil || !rt.SignIn()
}

// Load reads the saved settings and applies them.
func (m *Manager) Load(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loadLocked(ctx)
}

func (m *Manager) loadLocked(ctx context.Context) error {
	rev, stored, err := m.store.GetSettings(ctx)
	if err != nil {
		return fmt.Errorf("read saved settings: %w", err)
	}
	web, err := m.decrypt(stored)
	if err != nil {
		return err
	}
	merged, _ := config.Merge(m.fixed.Env, web)
	rt, err := config.Build(merged, m.fixed)
	if err != nil {
		var b strings.Builder
		for _, fe := range config.FieldErrors(err) {
			fmt.Fprintf(&b, "\n  %s: %s", fe.Key, fe.Msg)
		}
		return fmt.Errorf("settings saved in the web admin area are not valid:%s\n"+
			"Set them in the server environment instead, or clear them with `frontdir settings reset KEY`", b.String())
	}
	m.rev, m.stored, m.web = rev, stored, web
	m.applyLocked(ctx, rt, true)
	return nil
}

func (m *Manager) decrypt(stored map[string]string) (config.Values, error) {
	web := config.Values{}
	for k, v := range stored {
		s, ok := config.Lookup(k)
		if !ok {
			m.log.Warn("ignoring a saved setting this version does not know", "key", k)
			continue
		}
		if s.Secret() {
			if m.box == nil {
				return nil, fmt.Errorf("the web settings hold an encrypted %s but FRONTDIR_SETTINGS_KEY is not set: "+
					"restore the settings key, or clear the value with `frontdir settings reset %s` and enter it again", k, k)
			}
			pt, err := m.box.open(k, v)
			if err != nil {
				return nil, fmt.Errorf("saved setting %s: %v: restore the original settings key, "+
					"or clear the value with `frontdir settings reset %s` and enter it again", k, err, k)
			}
			v = pt
		}
		web[k] = v
	}
	return web, nil
}

func (m *Manager) applyLocked(ctx context.Context, rt *config.Runtime, adminGroupsChanged bool) {
	m.svc.SetConfig(rt.Service)
	m.auth.Reconfigure(rt.Auth, rt.OIDC, rt.SAML)
	m.rt.Store(rt)
	for _, h := range m.hooks {
		h(rt)
	}
	if adminGroupsChanged {
		if n, err := m.svc.ApplyAdminGroups(ctx); err != nil {
			m.log.ErrorContext(ctx, "apply administrator groups", "err", err)
		} else if n > 0 {
			m.log.InfoContext(ctx, "audit", "event", "admins.recomputed", "changed", n)
		}
	}
}

// Watch picks up changes saved by other replicas.
func (m *Manager) Watch(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		rev, err := m.store.SettingsRevision(ctx)
		if err != nil {
			m.log.DebugContext(ctx, "check settings revision", "err", err)
			continue
		}
		m.mu.Lock()
		if rev != m.rev {
			if err := m.loadLocked(ctx); err != nil {
				m.log.ErrorContext(ctx, "settings changed elsewhere could not be applied; keeping the current ones", "err", err)
			} else {
				m.log.InfoContext(ctx, "settings reloaded", "revision", rev)
			}
		}
		m.mu.Unlock()
	}
}

// ---- viewing ---------------------------------------------------------------------------

// Field is one setting as the admin area shows it.
type Field struct {
	Key     string        `json:"key"`
	Group   string        `json:"group"`
	Kind    string        `json:"kind"`
	Label   string        `json:"label"`
	Help    string        `json:"help"`
	Default string        `json:"default,omitempty"`
	Value   string        `json:"value"` // empty for secrets and images
	IsSet   bool          `json:"isSet"`
	Source  config.Source `json:"source"`
	Locked  bool          `json:"locked"`
	Env     string        `json:"env"` // the environment variable that sets it
}

// Group is a section of settings.
type Group struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	FromServer bool   `json:"fromServer"` // a sign-in method configured in the environment
}

// SignInInfo is what to register at the identity provider.
type SignInInfo struct {
	OIDCRedirectURI string `json:"oidcRedirectUri"`
	SAMLMetadataURL string `json:"samlMetadataUrl"`
	SAMLACSURL      string `json:"samlAcsUrl"`
}

// View is the settings page.
type View struct {
	Revision        int64      `json:"revision"`
	ReadOnly        bool       `json:"readOnly"`
	CanStoreSecrets bool       `json:"canStoreSecrets"`
	SetupMode       bool       `json:"setupMode"`
	Groups          []Group    `json:"groups"`
	Fields          []Field    `json:"fields"`
	SignIn          SignInInfo `json:"signIn"`
}

// View returns the settings (administrators).
func (m *Manager) View(ctx context.Context, p service.Principal) (*View, error) {
	if err := m.svc.RequireAdmin(ctx, p); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.viewLocked(nil), nil
}

func (m *Manager) viewLocked(only func(config.Setting) bool) *View {
	merged, src := config.Merge(m.fixed.Env, m.web)
	v := &View{Revision: m.rev, ReadOnly: !m.fixed.WebSettings, CanStoreSecrets: m.box != nil, SetupMode: m.SetupMode()}
	if pub := m.fixed.PublicURL; pub != nil {
		v.SignIn = SignInInfo{OIDCRedirectURI: pub.String() + "/auth/callback",
			SAMLMetadataURL: pub.String() + "/auth/saml/metadata", SAMLACSURL: pub.String() + "/auth/saml/acs"}
	}
	seen := map[string]bool{}
	for _, s := range config.Registry {
		if only != nil && !only(s) {
			continue
		}
		f := Field{Key: s.Key, Group: s.Group, Kind: s.Kind, Label: s.Label, Help: s.Help, Default: s.Default,
			Source: src[s.Key], Locked: config.Locked(m.fixed.Env, s.Key) || !m.fixed.WebSettings, Env: s.Env,
			IsSet: merged[s.Key] != ""}
		if !s.Secret() && s.Kind != "image" {
			f.Value = merged[s.Key]
		}
		v.Fields = append(v.Fields, f)
		seen[s.Group] = true
	}
	for _, g := range config.Groups {
		if seen[g.ID] {
			v.Groups = append(v.Groups, Group{ID: g.ID, Label: g.Label, FromServer: config.GroupFromServer(m.fixed.Env, g.ID)})
		}
	}
	return v
}

// ---- changing ----------------------------------------------------------------------------

// UpdateRequest changes settings. Set maps keys to new values; an empty
// value returns the setting to its default (or clears a secret). Keys not
// in Set are left alone, which is how a stored secret is kept.
type UpdateRequest struct {
	Revision int64             `json:"revision"`
	Set      map[string]string `json:"set"`
	Confirm  []string          `json:"confirm"`
}

// actor is who is changing settings: an administrator, or the holder of
// the setup link (no account yet, so no self-lockout checks).
type actor struct {
	id     string
	user   *domain.User
	groups []string
}

// Update changes settings (administrators, after a recent sign-in).
func (m *Manager) Update(ctx context.Context, p service.Principal, req UpdateRequest) (*View, error) {
	if err := m.svc.RequireFreshAdmin(ctx, p); err != nil {
		return nil, err
	}
	u, groups, err := m.svc.UserAndGroups(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.updateLocked(ctx, &actor{id: p.UserID, user: u, groups: groups}, req, nil); err != nil {
		return nil, err
	}
	return m.viewLocked(nil), nil
}

// Errors that carry per-field messages (Detail maps key to message) or ask
// for confirmation (Detail["confirm"] names what to confirm).
func invalid(fields map[string]string) error {
	return &domain.Error{Code: domain.CodeInvalid, Message: "some settings need attention", Detail: fields}
}

func needConfirm(what, msg string) error {
	return &domain.Error{Code: domain.CodeConfirm, Message: msg, Detail: map[string]string{"confirm": what}}
}

func (m *Manager) updateLocked(ctx context.Context, a *actor, req UpdateRequest, allowed func(config.Setting) bool) error {
	if !m.fixed.WebSettings {
		return domain.E(domain.CodeForbidden, "settings are read-only on the web (FRONTDIR_WEB_SETTINGS=false); change them in the server environment")
	}
	if req.Revision != m.rev {
		return domain.E(domain.CodePrecondition, "settings were changed by someone else; reload and try again")
	}
	if len(req.Set) == 0 || len(req.Set) > len(config.Registry) {
		return domain.E(domain.CodeInvalid, "nothing to change")
	}
	fields := map[string]string{}
	next := m.web.Clone()
	var changed []string
	groups := map[string]bool{}
	for k, v := range req.Set {
		s, ok := config.Lookup(k)
		switch {
		case !ok:
			fields[k] = "unknown setting"
			continue
		case allowed != nil && !allowed(s):
			fields[k] = "cannot be changed here"
			continue
		case config.Locked(m.fixed.Env, k):
			fields[k] = "set by the server (" + s.Env + "); change it there"
			continue
		}
		v = strings.TrimSpace(v)
		if s.Kind == "image" && v != "" {
			// Keep only what would be served: the re-encoded pixels.
			img, err := base64.StdEncoding.DecodeString(v)
			if err == nil {
				img, err = theme.SanitizeLogo(img)
			}
			if err != nil {
				fields[k] = err.Error()
				continue
			}
			v = base64.StdEncoding.EncodeToString(img)
		}
		if s.Secret() && v != "" && m.box == nil {
			fields[k] = "cannot be stored: the server has no settings key (FRONTDIR_SETTINGS_KEY_FILE; scripts/init-secrets.sh creates one)"
			continue
		}
		if v == "" {
			delete(next, k)
		} else {
			next[k] = v
		}
		if next[k] != m.web[k] {
			changed = append(changed, k)
			groups[s.Group] = true
		}
	}
	if len(fields) > 0 {
		return invalid(fields)
	}
	if len(changed) == 0 {
		return nil
	}
	sort.Strings(changed)

	merged, _ := config.Merge(m.fixed.Env, next)
	rt, err := config.Build(merged, m.fixed)
	if err != nil {
		fes := config.FieldErrors(err)
		if len(fes) == 0 {
			return err
		}
		for _, fe := range fes {
			fields[fe.Key] = fe.Msg
		}
		return invalid(fields)
	}
	old := m.rt.Load()
	samlEntity, err := m.checkSignIn(ctx, old, rt, groups, fields)
	if err != nil {
		return err
	}
	m.checkSelf(a, old, rt, groups, fields)
	if len(fields) > 0 {
		return invalid(fields)
	}
	if err := m.checkOrphans(ctx, a, old, rt, samlEntity, req.Confirm); err != nil {
		return err
	}

	stored := map[string]string{}
	for k, v := range next {
		s, _ := config.Lookup(k)
		switch {
		case !s.Secret():
			stored[k] = v
		case v == m.web[k] && m.stored[k] != "":
			stored[k] = m.stored[k]
		default:
			stored[k] = m.box.seal(k, v)
		}
	}
	rev, err := m.store.PutSettings(ctx, m.rev, stored, a.id, m.now())
	if err != nil {
		return err
	}
	m.rev, m.stored, m.web = rev, stored, next
	m.applyLocked(ctx, rt, !slices.Equal(old.Service.AdminGroups, rt.Service.AdminGroups))
	m.audit(ctx, a, changed, next)
	return nil
}

// checkSignIn keeps at least one sign-in method on and tries changed ones
// against the identity provider. It returns the SAML IdP's entity ID ("" if
// SAML is off or unknown).
func (m *Manager) checkSignIn(ctx context.Context, old, rt *config.Runtime, groups map[string]bool, fields map[string]string) (string, error) {
	if old.SignIn() && !rt.SignIn() {
		key := "SAML_IDP_METADATA_URL"
		if groups["oidc"] {
			key = "OIDC_ISSUER"
		}
		fields[key] = "at least one sign-in method must stay on (to turn sign-in off entirely, use the server environment)"
		return "", nil
	}
	if groups["oidc"] && rt.OIDC != nil {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := m.CheckOIDC(cctx, *rt.OIDC)
		cancel()
		if err != nil {
			fields["OIDC_ISSUER"] = "the identity provider check failed: " + err.Error()
		}
	}
	if rt.SAML == nil {
		return "", nil
	}
	if !groups["saml"] {
		id, _ := m.auth.SAMLIdPEntityID(ctx) // unchanged; unknown if the IdP is unreachable
		return id, nil
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	id, err := m.CheckSAML(cctx, *rt.SAML)
	if err != nil {
		key := "SAML_IDP_METADATA"
		if rt.SAML.IDPMetadataURL != "" {
			key = "SAML_IDP_METADATA_URL"
		}
		fields[key] = "the identity provider check failed: " + err.Error()
	}
	return id, nil
}

// checkSelf refuses changes that would stop the administrator making them
// from signing in, or from being an administrator.
func (m *Manager) checkSelf(a *actor, old, rt *config.Runtime, groups map[string]bool, fields map[string]string) {
	if a.user == nil || !groups["access"] {
		return
	}
	id := service.Identity{Email: a.user.Email, EmailVerified: a.user.Email != "", Groups: a.groups}
	if old.Policy.Check(id) == nil && rt.Policy.Check(id) != nil {
		key := "ALLOWED_GROUPS"
		if slices.Equal(old.Policy.AllowedGroups, rt.Policy.AllowedGroups) {
			key = "ALLOWED_EMAIL_DOMAINS"
		}
		fields[key] = "this would stop you from signing in: your account does not match it"
	}
	if a.user.Admin && !a.user.AdminGranted && !slices.ContainsFunc(a.groups, func(g string) bool {
		return slices.Contains(rt.Service.AdminGroups, g)
	}) {
		fields["ADMIN_GROUPS"] = "you would no longer be an administrator: keep one of your groups here, " +
			"or have another administrator appoint you under People first"
	}
}

// checkOrphans asks for confirmation before a change leaves existing
// accounts without a way to sign in (their identity provider is replaced
// or turned off). Accounts are tied to the issuer that created them, so a
// new identity provider creates new, empty accounts; nobody can take over
// an existing account this way.
func (m *Manager) checkOrphans(ctx context.Context, a *actor, old, rt *config.Runtime, samlEntity string, confirm []string) error {
	reach := func(r *config.Runtime, saml string) map[string]bool {
		out := map[string]bool{}
		if r.OIDC != nil {
			out[r.OIDC.Issuer] = true
		}
		if r.SAML != nil && saml != "" {
			out["saml:"+saml] = true
		}
		return out
	}
	oldSAML := ""
	if old.SAML != nil {
		oldSAML, _ = m.auth.SAMLIdPEntityID(ctx)
	}
	before, after := reach(old, oldSAML), reach(rt, samlEntity)
	counts, err := m.svc.IssuerCounts(ctx)
	if err != nil {
		return err
	}
	var lost int64
	self := false
	for iss, n := range counts {
		if before[iss] && !after[iss] {
			lost += n
			self = self || a.user != nil && a.user.Issuer == iss
		}
	}
	if lost == 0 || slices.Contains(confirm, "orphans") {
		return nil
	}
	who := fmt.Sprintf("%d accounts sign", lost)
	if lost == 1 {
		who = "1 account signs"
	}
	msg := who + " in through the identity provider you are replacing or turning off. " +
		"They will not be able to sign in until it is configured again; their files stay, encrypted. " +
		"People who sign in through the new provider get new accounts."
	if self {
		msg += " This includes your own account."
	}
	return needConfirm("orphans", msg)
}

func (m *Manager) audit(ctx context.Context, a *actor, changed []string, next config.Values) {
	desc := map[string]string{}
	for _, k := range changed {
		s, _ := config.Lookup(k)
		v := next[k]
		switch {
		case v == "":
			desc[k] = "(default)"
		case s.Secret():
			desc[k] = "(set)"
		case s.Kind == "json" || s.Kind == "xml" || s.Kind == "image":
			desc[k] = "(changed)"
		default:
			desc[k] = v
		}
	}
	m.log.InfoContext(ctx, "audit", "event", "settings.changed", "user", a.id, "revision", m.rev, "changes", desc)
}

// ---- operator commands (no running server needed) ----------------------------------------

// Reset clears saved settings: keys, whole groups (e.g. "oidc"), or
// everything ("all"). It does not validate, so it works when the saved
// settings stop the server from starting. Running servers pick it up.
func Reset(ctx context.Context, store Store, names []string, now time.Time) ([]string, error) {
	if len(names) == 0 {
		return nil, errors.New("name settings (e.g. OIDC_CLIENT_SECRET), groups (e.g. oidc) or all")
	}
	drop, all := map[string]bool{}, slices.Contains(names, "all")
	for _, n := range names {
		found := false
		for _, s := range config.Registry {
			if n == "all" || strings.EqualFold(n, s.Key) || strings.EqualFold(n, s.Group) {
				drop[s.Key], found = true, true
			}
		}
		if !found && n != "all" {
			return nil, fmt.Errorf("unknown setting or group %q", n)
		}
	}
	for attempt := 0; ; attempt++ {
		rev, doc, err := store.GetSettings(ctx)
		if err != nil {
			return nil, err
		}
		var removed []string
		for k := range doc {
			if drop[k] || all {
				removed = append(removed, k)
				delete(doc, k)
			}
		}
		sort.Strings(removed)
		if len(removed) == 0 {
			return nil, nil
		}
		_, err = store.PutSettings(ctx, rev, doc, "cli", now)
		if err == nil || !errors.Is(err, domain.ErrPrecondition) || attempt == 3 {
			return removed, err
		}
	}
}

// Describe lists every setting with where its value comes from, for
// `frontdir settings show`. Secrets are never printed.
func Describe(ctx context.Context, fixed *config.Config, store Store) ([]string, error) {
	_, doc, err := store.GetSettings(ctx)
	if err != nil {
		return nil, err
	}
	web := config.Values{}
	for k, v := range doc {
		web[k] = v
	}
	merged, src := config.Merge(fixed.Env, web)
	var out []string
	for _, s := range config.Registry {
		v := merged[s.Key]
		switch {
		case v == "" && s.Default != "":
			v = "(default: " + s.Default + ")"
		case v == "":
			v = "(not set)"
		case s.Secret():
			v = "(set, hidden)"
		case len(v) > 80 || strings.ContainsAny(v, "\n"):
			v = fmt.Sprintf("(%d bytes)", len(v))
		}
		out = append(out, fmt.Sprintf("%-24s %-8s %s", s.Key, src[s.Key], v))
	}
	return out, nil
}
