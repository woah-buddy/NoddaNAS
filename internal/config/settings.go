package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/woah-buddy/NoddaNAS/internal/auth"
	"github.com/woah-buddy/NoddaNAS/internal/service"
	"github.com/woah-buddy/NoddaNAS/internal/theme"
)

// Settings that an administrator can change from the web admin area as well
// as from the server's environment.
//
// The split follows who owns a decision. Things only the person running the
// server can know or should decide (where the database is, which address
// and port to serve, TLS, proxies, the settings key itself) are server-only.
// Things an app owner decides (quotas, link lifetimes, who may sign in,
// which identity provider, branding) are settings.
//
// One parser and validator (Build) serves both sources, so a value means
// the same thing and is held to the same rules wherever it was set.
//
// Precedence: a non-empty environment variable wins and locks the setting
// in the web admin area; otherwise the web value; otherwise the default.
// Sign-in settings lock as a group: OIDC is configured entirely in the
// environment (NODDANAS_OIDC_ISSUER is set) or entirely on the web, and the
// same for SAML, so a deployment never runs on a mix nobody reviewed whole.

// Setting describes one changeable setting.
type Setting struct {
	Key     string // name in the admin API and the settings store
	Env     string // environment variable that sets it (and locks it on the web)
	File    bool   // Env names a file whose content is the value
	Group   string
	Kind    string // text, list, bool, size, duration, int, url, secret, json, xml, image
	Label   string
	Help    string
	Default string // shown when unset; Build applies the same defaults
	Max     int    // longest accepted value in bytes
}

// Secret reports whether the setting's value is never shown again once set.
func (s Setting) Secret() bool { return s.Kind == "secret" }

// Groups in display order.
var Groups = []struct{ ID, Label string }{
	{"storage", "Storage"},
	{"sharing", "Sharing"},
	{"access", "Who can sign in"},
	{"sessions", "Sessions"},
	{"oidc", "OpenID Connect sign-in"},
	{"saml", "SAML sign-in"},
	{"branding", "Branding"},
}

// signInGroups are configured as a whole from one source. The anchor is the
// setting that switches the method on.
var signInGroups = map[string]string{"oidc": "OIDC_ISSUER", "saml": "SAML_IDP_METADATA_URL|SAML_IDP_METADATA"}

// Registry lists every changeable setting.
var Registry = []Setting{
	{Key: "DEFAULT_QUOTA", Env: "NODDANAS_DEFAULT_QUOTA", Group: "storage", Kind: "size", Default: "10GiB", Max: 32,
		Label: "Default personal storage", Help: "Storage for each new person's personal folder. Existing folders keep theirs; change those under People."},
	{Key: "DEFAULT_TEAM_QUOTA", Env: "NODDANAS_DEFAULT_TEAM_QUOTA", Group: "storage", Kind: "size", Default: "50GiB", Max: 32,
		Label: "Default team folder storage", Help: "Storage for each new team folder."},
	{Key: "MAX_FILE_SIZE", Env: "NODDANAS_MAX_FILE_SIZE", Group: "storage", Kind: "size", Default: "50GiB", Max: 32,
		Label: "Largest file", Help: "Uploads larger than this are refused."},
	{Key: "MAX_VERSIONS", Env: "NODDANAS_MAX_VERSIONS", Group: "storage", Kind: "int", Default: "10", Max: 8,
		Label: "Versions kept per file", Help: "Including the current one (1 to 1000). Lowering it removes older versions as files change."},
	{Key: "TRASH_RETENTION", Env: "NODDANAS_TRASH_RETENTION", Group: "storage", Kind: "duration", Default: "30d", Max: 32,
		Label: "Keep deleted items for", Help: "Items in the trash are deleted for good after this long (at least 1h)."},
	{Key: "TEAM_CREATION", Env: "NODDANAS_TEAM_CREATION", Group: "storage", Kind: "bool", Default: "true", Max: 8,
		Label: "Everyone can create team folders", Help: "If off, only administrators can."},

	{Key: "LINK_DEFAULT_TTL", Env: "NODDANAS_LINK_DEFAULT_TTL", Group: "sharing", Kind: "duration", Default: "30d", Max: 32,
		Label: "Public links expire after", Help: "Used when the person sharing does not choose."},
	{Key: "LINK_MAX_TTL", Env: "NODDANAS_LINK_MAX_TTL", Group: "sharing", Kind: "duration", Default: "365d", Max: 32,
		Label: "Longest public link lifetime", Help: "Nobody can create a link that lasts longer."},

	{Key: "ALLOWED_GROUPS", Env: "NODDANAS_ALLOWED_GROUPS", Group: "access", Kind: "list", Max: 4096,
		Label: "Allowed groups", Help: "Only members of one of these identity-provider groups can sign in. Empty: no group needed."},
	{Key: "ALLOWED_EMAIL_DOMAINS", Env: "NODDANAS_ALLOWED_EMAIL_DOMAINS", Group: "access", Kind: "list", Max: 4096,
		Label: "Allowed email domains", Help: "Only people with a verified email in one of these domains can sign in. Empty: any."},
	{Key: "ADMIN_GROUPS", Env: "NODDANAS_ADMIN_GROUPS", Group: "access", Kind: "list", Max: 4096,
		Label: "Administrator groups", Help: "Members of these identity-provider groups are administrators. You can also make people administrators under People."},

	{Key: "SESSION_IDLE", Env: "NODDANAS_SESSION_IDLE", Group: "sessions", Kind: "duration", Default: "12h", Max: 32,
		Label: "Sign out after inactivity", Help: "Between 5m and 30d."},
	{Key: "SESSION_MAX_AGE", Env: "NODDANAS_SESSION_MAX_AGE", Group: "sessions", Kind: "duration", Default: "7d", Max: 32,
		Label: "Sign out after", Help: "However active the session is (15m to 365d)."},

	{Key: "OIDC_ISSUER", Env: "NODDANAS_OIDC_ISSUER", Group: "oidc", Kind: "url", Max: 2048,
		Label: "Issuer URL", Help: "Your identity provider's issuer, e.g. https://id.example.com/realms/main. Empty turns OIDC sign-in off."},
	{Key: "OIDC_CLIENT_ID", Env: "NODDANAS_OIDC_CLIENT_ID", Group: "oidc", Kind: "text", Max: 512,
		Label: "Client ID", Help: "From the client you registered for NoddaNAS."},
	{Key: "OIDC_CLIENT_SECRET", Env: "NODDANAS_OIDC_CLIENT_SECRET", Group: "oidc", Kind: "secret", Max: 1024,
		Label: "Client secret", Help: "Stored encrypted and never shown again. Leave empty for a public client."},
	{Key: "OIDC_SCOPES", Env: "NODDANAS_OIDC_SCOPES", Group: "oidc", Kind: "list", Default: "openid, email, profile", Max: 1024,
		Label: "Scopes", Help: "Must include openid."},
	{Key: "OIDC_GROUPS_CLAIM", Env: "NODDANAS_OIDC_GROUPS_CLAIM", Group: "oidc", Kind: "text", Default: "groups", Max: 128,
		Label: "Groups claim", Help: "The ID-token claim that lists the person's groups."},

	{Key: "SAML_IDP_METADATA_URL", Env: "NODDANAS_SAML_IDP_METADATA_URL", Group: "saml", Kind: "url", Max: 2048,
		Label: "IdP metadata URL", Help: "An https URL. Set this or the metadata XML below; both empty turns SAML sign-in off."},
	{Key: "SAML_IDP_METADATA", Env: "NODDANAS_SAML_IDP_METADATA_FILE", File: true, Group: "saml", Kind: "xml", Max: 1 << 20,
		Label: "IdP metadata XML", Help: "Paste the metadata document if your IdP has no metadata URL."},
	{Key: "SAML_ENTITY_ID", Env: "NODDANAS_SAML_ENTITY_ID", Group: "saml", Kind: "text", Max: 1024,
		Label: "Our entity ID", Help: "Defaults to our metadata URL. Change it only if your IdP requires a specific value."},
	{Key: "SAML_TRUST_EMAIL", Env: "NODDANAS_SAML_TRUST_EMAIL", Group: "saml", Kind: "bool", Default: "false", Max: 8,
		Label: "Trust asserted emails", Help: "Turn on only if your IdP verifies email addresses. Needed for sharing by email."},
	{Key: "SAML_EMAIL_ATTRIBUTES", Env: "NODDANAS_SAML_EMAIL_ATTRIBUTES", Group: "saml", Kind: "list", Max: 2048,
		Label: "Email attributes", Help: "Empty: common names (email, mail, ...)."},
	{Key: "SAML_NAME_ATTRIBUTES", Env: "NODDANAS_SAML_NAME_ATTRIBUTES", Group: "saml", Kind: "list", Max: 2048,
		Label: "Name attributes", Help: "Empty: common names (displayName, cn, ...)."},
	{Key: "SAML_GROUP_ATTRIBUTES", Env: "NODDANAS_SAML_GROUP_ATTRIBUTES", Group: "saml", Kind: "list", Max: 2048,
		Label: "Group attributes", Help: "Empty: common names (groups, memberOf, ...)."},

	{Key: "BRAND_NAME", Env: "NODDANAS_BRAND_NAME", Group: "branding", Kind: "text", Default: "NoddaNAS", Max: 256,
		Label: "Name", Help: "Shown in the header and the browser tab."},
	{Key: "THEME", Env: "NODDANAS_THEME_FILE", File: true, Group: "branding", Kind: "json", Max: 64 << 10,
		Label: "Theme", Help: "Color tokens as JSON (docs/THEMING.md). Every color is checked for readable contrast."},
	{Key: "BRAND_LOGO", Env: "NODDANAS_BRAND_LOGO_FILE", File: true, Group: "branding", Kind: "image", Max: 700 << 10,
		Label: "Logo", Help: "PNG or JPEG, up to 512 KiB and 1 megapixel. It is re-encoded, so only the pixels are kept."},
}

var registryIndex = func() map[string]Setting {
	m := map[string]Setting{}
	for _, s := range Registry {
		m[s.Key] = s
	}
	return m
}()

// Lookup returns the setting with key k.
func Lookup(k string) (Setting, bool) {
	s, ok := registryIndex[k]
	return s, ok
}

// Values maps setting keys to raw values. An absent or empty value means
// "not set here". A logo is base64 of the image bytes.
type Values map[string]string

// Clone copies v.
func (v Values) Clone() Values {
	out := make(Values, len(v))
	for k, x := range v {
		out[k] = x
	}
	return out
}

// Source says where a setting's effective value comes from.
type Source string

const (
	SourceDefault Source = "default"
	SourceWeb     Source = "web"
	SourceServer  Source = "server" // the environment; locked on the web
)

// Merge applies precedence: environment, then web, then default (absent).
// It also reports where each setting comes from.
func Merge(env, web Values) (Values, map[string]Source) {
	out, src := Values{}, map[string]Source{}
	for _, s := range Registry {
		anchor, grouped := signInGroups[s.Group]
		switch {
		case grouped && groupSet(env, anchor):
			if env[s.Key] != "" {
				out[s.Key] = env[s.Key]
			}
			src[s.Key] = SourceServer
		case env[s.Key] != "":
			out[s.Key], src[s.Key] = env[s.Key], SourceServer
		case grouped && groupSet(web, anchor) || !grouped && web[s.Key] != "":
			if web[s.Key] != "" {
				out[s.Key] = web[s.Key]
			}
			src[s.Key] = SourceWeb
			if web[s.Key] == "" {
				src[s.Key] = SourceDefault
			}
		default:
			src[s.Key] = SourceDefault
		}
	}
	return out, src
}

func groupSet(v Values, anchor string) bool {
	for _, k := range strings.Split(anchor, "|") {
		if v[k] != "" {
			return true
		}
	}
	return false
}

// GroupFromServer reports whether a sign-in group is configured in the
// environment (and therefore locked on the web as a whole).
func GroupFromServer(env Values, group string) bool {
	anchor, ok := signInGroups[group]
	return ok && groupSet(env, anchor)
}

// Locked reports whether the environment sets key (directly or through its
// sign-in group).
func Locked(env Values, key string) bool {
	s, ok := Lookup(key)
	if !ok {
		return true
	}
	if GroupFromServer(env, s.Group) {
		return true
	}
	return env[key] != ""
}

// FieldError is a problem with one setting. The admin API reports it next to
// the field; at startup it names the environment variable.
type FieldError struct {
	Key string
	Msg string
}

func (e *FieldError) Error() string {
	if s, ok := Lookup(e.Key); ok {
		return s.Env + ": " + e.Msg
	}
	return e.Key + ": " + e.Msg
}

// FieldErrors extracts every FieldError from err (which may be joined).
func FieldErrors(err error) []*FieldError {
	var out []*FieldError
	var walk func(error)
	walk = func(err error) {
		switch e := err.(type) {
		case nil:
		case *FieldError:
			out = append(out, e)
		case interface{ Unwrap() []error }:
			for _, x := range e.Unwrap() {
				walk(x)
			}
		default:
			var fe *FieldError
			if errors.As(err, &fe) {
				out = append(out, fe)
			}
		}
	}
	walk(err)
	return out
}

// Runtime is everything derived from the changeable settings. The server
// swaps a whole Runtime at once when settings change.
type Runtime struct {
	OIDC    *auth.OIDCConfig // nil if OIDC sign-in is off
	SAML    *auth.SAMLConfig // nil if SAML sign-in is off
	Policy  auth.Policy
	Auth    auth.Config
	Service service.Config
	Theme   *theme.Theme
}

// SignIn reports whether at least one sign-in method is configured.
func (r *Runtime) SignIn() bool { return r.OIDC != nil || r.SAML != nil }

// Build validates v and derives the runtime configuration. Every problem is
// reported (as a FieldError), not just the first. It does no network I/O.
func Build(v Values, fixed *Config) (*Runtime, error) {
	b := &builder{v: v}
	for k, x := range v {
		s, ok := Lookup(k)
		if !ok {
			b.fail(k, "unknown setting")
			continue
		}
		b.shape(s, x)
	}
	if len(b.errs) > 0 {
		// Malformed input (oversized, control characters): stop before
		// interpreting any of it.
		return nil, errors.Join(b.errs...)
	}
	rt := &Runtime{}
	rt.Policy = auth.Policy{AllowedGroups: b.list("ALLOWED_GROUPS"), AllowedEmailDomains: b.domains("ALLOWED_EMAIL_DOMAINS")}

	rt.Auth = auth.Config{
		SessionIdle:     b.duration("SESSION_IDLE", 12*time.Hour, 5*time.Minute, 30*24*time.Hour),
		SessionAbsolute: b.duration("SESSION_MAX_AGE", 7*24*time.Hour, 15*time.Minute, 365*24*time.Hour),
	}
	if rt.Auth.SessionIdle > rt.Auth.SessionAbsolute {
		b.fail("SESSION_IDLE", "must not be longer than the maximum session age (%s)", fmtDuration(rt.Auth.SessionAbsolute))
	}

	sc := service.DefaultConfig()
	sc.DefaultQuota = b.size("DEFAULT_QUOTA", sc.DefaultQuota, 0)
	sc.DefaultTeamQuota = b.size("DEFAULT_TEAM_QUOTA", sc.DefaultTeamQuota, 0)
	sc.MaxFileSize = b.size("MAX_FILE_SIZE", sc.MaxFileSize, 1<<20)
	sc.MaxVersions = int(b.integer("MAX_VERSIONS", int64(sc.MaxVersions), 1, 1000))
	sc.TrashRetention = b.duration("TRASH_RETENTION", sc.TrashRetention, time.Hour, 100*365*24*time.Hour)
	sc.TeamCreation = b.boolean("TEAM_CREATION", sc.TeamCreation)
	sc.AdminGroups = b.list("ADMIN_GROUPS")
	sc.LinkDefaultTTL = b.duration("LINK_DEFAULT_TTL", sc.LinkDefaultTTL, time.Hour, 100*365*24*time.Hour)
	sc.LinkMaxTTL = b.duration("LINK_MAX_TTL", sc.LinkMaxTTL, time.Hour, 100*365*24*time.Hour)
	if sc.LinkDefaultTTL > sc.LinkMaxTTL {
		b.fail("LINK_DEFAULT_TTL", "must not be longer than the longest link lifetime (%s)", fmtDuration(sc.LinkMaxTTL))
	}
	rt.Service = sc

	rt.OIDC = b.oidc(rt.Policy, fixed)
	rt.SAML = b.saml(rt.Policy, fixed)
	rt.Theme = b.theme()
	if len(b.errs) > 0 {
		return nil, errors.Join(b.errs...)
	}
	return rt, nil
}

type builder struct {
	v    Values
	errs []error
}

func (b *builder) fail(key, format string, args ...any) {
	b.errs = append(b.errs, &FieldError{Key: key, Msg: fmt.Sprintf(format, args...)})
}

// shape applies the checks every value of a kind must pass before it is
// interpreted: a size bound, valid UTF-8, and no control characters (line
// breaks are allowed only in documents: JSON and XML).
func (b *builder) shape(s Setting, x string) {
	if len(x) > s.Max {
		b.fail(s.Key, "is too long (at most %d bytes)", s.Max)
		return
	}
	if !utf8.ValidString(x) {
		b.fail(s.Key, "is not valid UTF-8")
		return
	}
	doc := s.Kind == "json" || s.Kind == "xml"
	for _, r := range x {
		if doc && (r == '\n' || r == '\r' || r == '\t') {
			continue
		}
		if unicode.IsControl(r) || r >= 0x202A && r <= 0x202E || r >= 0x2066 && r <= 0x2069 {
			b.fail(s.Key, "contains control or text-direction characters")
			return
		}
	}
}

func (b *builder) str(key string) string { return strings.TrimSpace(b.v[key]) }

func (b *builder) list(key string) []string {
	var out []string
	for _, s := range strings.Split(b.v[key], ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	if len(out) > 100 {
		b.fail(key, "lists more than 100 entries")
		return nil
	}
	return out
}

func (b *builder) domains(key string) []string {
	ds := b.list(key)
	for i, d := range ds {
		d = strings.ToLower(strings.TrimPrefix(d, "@"))
		if strings.ContainsAny(d, "@/ :") || !strings.Contains(d, ".") && d != "localhost" {
			b.fail(key, "%q is not a domain name", d)
		}
		ds[i] = d
	}
	return ds
}

func (b *builder) boolean(key string, def bool) bool {
	s := b.str(key)
	if s == "" {
		return def
	}
	v, err := strconv.ParseBool(s)
	if err != nil {
		b.fail(key, "must be true or false")
		return def
	}
	return v
}

func (b *builder) integer(key string, def, lo, hi int64) int64 {
	s := b.str(key)
	if s == "" {
		return def
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < lo || n > hi {
		b.fail(key, "must be a whole number from %d to %d", lo, hi)
		return def
	}
	return n
}

func (b *builder) duration(key string, def, lo, hi time.Duration) time.Duration {
	s := b.str(key)
	if s == "" {
		return def
	}
	d, err := ParseDuration(s)
	if err != nil || d < lo || d > hi {
		b.fail(key, "must be a duration like 12h or 30d, from %s to %s", fmtDuration(lo), fmtDuration(hi))
		return def
	}
	return d
}

func (b *builder) size(key string, def, lo int64) int64 {
	s := b.str(key)
	if s == "" {
		return def
	}
	n, err := ParseSize(s)
	if err != nil {
		b.fail(key, "%v", err)
		return def
	}
	if n < lo {
		b.fail(key, "must be at least %s", FormatSize(lo))
		return def
	}
	return n
}

// checkURL accepts https URLs, or plain http to a loopback host if loopback is
// allowed. No credentials, query or fragment: an issuer or metadata URL with
// those is a mistake (or an attempt to smuggle something).
func (b *builder) checkURL(key, raw string, loopback bool) bool {
	u, err := url.Parse(raw)
	switch {
	case err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" && key == "OIDC_ISSUER" || u.Fragment != "":
		b.fail(key, "must be a URL like https://id.example.com/...")
	case u.Scheme == "https":
		return true
	case u.Scheme == "http" && loopback && isLoopback(u.Hostname()):
		return true
	default:
		b.fail(key, "must use https")
	}
	return false
}

func (b *builder) oidc(policy auth.Policy, fixed *Config) *auth.OIDCConfig {
	issuer := b.str("OIDC_ISSUER")
	if issuer == "" {
		return nil
	}
	// Plain http only for an IdP on loopback in a localhost deployment.
	b.checkURL("OIDC_ISSUER", issuer, fixed != nil && fixed.PublicURL != nil && isLoopback(fixed.PublicURL.Hostname()))
	o := &auth.OIDCConfig{
		Issuer: issuer, ClientID: b.str("OIDC_CLIENT_ID"), ClientSecret: b.str("OIDC_CLIENT_SECRET"),
		GroupsClaim: b.str("OIDC_GROUPS_CLAIM"), Scopes: b.list("OIDC_SCOPES"), Policy: policy,
	}
	if o.ClientID == "" {
		b.fail("OIDC_CLIENT_ID", "is required when an issuer is set")
	}
	if len(o.Scopes) > 0 && !containsFold(o.Scopes, "openid") {
		b.fail("OIDC_SCOPES", "must include openid")
	}
	if strings.ContainsAny(o.GroupsClaim, " ,") {
		b.fail("OIDC_GROUPS_CLAIM", "must be a single claim name")
	}
	if fixed != nil && fixed.PublicURL != nil {
		o.RedirectURL = fixed.PublicURL.String() + "/auth/callback"
		o.PostLogoutRedirectURL = fixed.PublicURL.String() + "/"
		o.AllowLoopback = isLoopback(fixed.PublicURL.Hostname())
	}
	return o
}

func (b *builder) saml(policy auth.Policy, fixed *Config) *auth.SAMLConfig {
	mdURL, md := b.str("SAML_IDP_METADATA_URL"), b.str("SAML_IDP_METADATA")
	if mdURL == "" && md == "" {
		return nil
	}
	sc := &auth.SAMLConfig{
		EntityID: b.str("SAML_ENTITY_ID"), IDPMetadataURL: mdURL,
		TrustEmail:      b.boolean("SAML_TRUST_EMAIL", false),
		EmailAttributes: b.list("SAML_EMAIL_ATTRIBUTES"),
		NameAttributes:  b.list("SAML_NAME_ATTRIBUTES"),
		GroupAttributes: b.list("SAML_GROUP_ATTRIBUTES"),
		Policy:          policy,
	}
	switch {
	case mdURL != "" && md != "":
		b.fail("SAML_IDP_METADATA_URL", "set the metadata URL or the metadata XML, not both")
	case mdURL != "":
		// Metadata carries the IdP's signing key: never over plain http.
		b.checkURL("SAML_IDP_METADATA_URL", mdURL, false)
	default:
		if _, err := auth.ParseSAMLMetadata([]byte(md)); err != nil {
			b.fail("SAML_IDP_METADATA", "is not usable IdP metadata: %v", err)
		}
		sc.IDPMetadata = []byte(md)
	}
	if fixed != nil {
		if fixed.PublicURL != nil {
			sc.MetadataURL = fixed.PublicURL.String() + "/auth/saml/metadata"
			sc.ACSURL = fixed.PublicURL.String() + "/auth/saml/acs"
			sc.AllowLoopback = isLoopback(fixed.PublicURL.Hostname())
		}
		sc.Key, sc.Certificate = fixed.SAMLKey, fixed.SAMLCert
	}
	return sc
}

func (b *builder) theme() *theme.Theme {
	var o theme.Options
	ok := true
	if name := b.str("BRAND_NAME"); name != "" {
		if _, err := theme.Load(theme.Options{Name: name}); err != nil {
			b.fail("BRAND_NAME", "%v", err)
			ok = false
		}
		o.Name = name
	}
	if js := b.str("THEME"); js != "" {
		if _, err := theme.Load(theme.Options{ThemeJSON: []byte(js)}); err != nil {
			b.fail("THEME", "%v", err)
			ok = false
		}
		o.ThemeJSON = []byte(js)
	}
	if s := b.str("BRAND_LOGO"); s != "" {
		img, err := base64.StdEncoding.DecodeString(s)
		if err == nil {
			_, err = theme.SanitizeLogo(img)
		}
		if err != nil {
			b.fail("BRAND_LOGO", "%v", err)
			ok = false
		}
		o.Logo = img
	}
	if !ok {
		return nil
	}
	th, err := theme.Load(o)
	if err != nil {
		b.fail("THEME", "%v", err)
		return nil
	}
	return th
}

func containsFold(ss []string, x string) bool {
	for _, s := range ss {
		if strings.EqualFold(s, x) {
			return true
		}
	}
	return false
}

// ParseDuration accepts Go durations ("12h", "90m") plus whole days ("30d").
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 || n > 100*366 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return d, nil
}

func fmtDuration(d time.Duration) string {
	switch {
	case d%(24*time.Hour) == 0:
		return strconv.FormatInt(int64(d/(24*time.Hour)), 10) + "d"
	case d%time.Hour == 0:
		return strconv.FormatInt(int64(d/time.Hour), 10) + "h"
	case d%time.Minute == 0:
		return strconv.FormatInt(int64(d/time.Minute), 10) + "m"
	}
	return d.String()
}

// FormatSize renders bytes in the largest binary unit that divides them.
func FormatSize(n int64) string {
	for _, u := range []struct {
		s string
		m int64
	}{{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}} {
		if n >= u.m && n%u.m == 0 {
			return strconv.FormatInt(n/u.m, 10) + u.s
		}
	}
	return strconv.FormatInt(n, 10)
}
