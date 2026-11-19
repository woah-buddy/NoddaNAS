package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/woah-buddy/FrontDir/internal/domain"
	"github.com/woah-buddy/FrontDir/internal/secure"
	"github.com/woah-buddy/FrontDir/internal/service"
)

// OIDCConfig configures the OpenID Connect relying party.
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string // e.g. https://files.example.com/auth/callback
	Scopes       []string

	GroupsClaim string // claim holding group names; defaults to "groups"
	Policy      Policy

	PostLogoutRedirectURL string

	// AllowLoopback lets the server reach an IdP on a loopback address
	// (localhost deployments only; see NewIdPClient).
	AllowLoopback bool
}

// Policy restricts who may sign in. If both lists are empty, anyone the IdP
// authenticates may sign in, which is only appropriate for an IdP you control.
type Policy struct {
	AllowedGroups       []string // require one of these groups
	AllowedEmailDomains []string // require a verified email in one of these domains
}

// Open reports whether the policy admits everyone.
func (p Policy) Open() bool { return len(p.AllowedGroups) == 0 && len(p.AllowedEmailDomains) == 0 }

// Check applies the policy to an asserted identity.
func (p Policy) Check(id service.Identity) error {
	if len(p.AllowedGroups) > 0 &&
		!slices.ContainsFunc(id.Groups, func(g string) bool { return slices.Contains(p.AllowedGroups, g) }) {
		return ErrNotAllowed
	}
	if len(p.AllowedEmailDomains) > 0 {
		_, domainPart, ok := strings.Cut(strings.ToLower(id.Email), "@")
		if !id.EmailVerified || !ok || !slices.Contains(p.AllowedEmailDomains, domainPart) {
			return ErrNotAllowed
		}
	}
	return nil
}

// OIDC is a lazily-initialized OIDC client. Discovery happens on first use,
// so FrontDir starts (and passes health checks) even if the IdP container is
// still booting.
type OIDC struct {
	raw    OIDCConfig // as given, to detect changes
	cfg    OIDCConfig // with defaults applied
	client *http.Client

	mu         sync.Mutex
	verifier   *oidc.IDTokenVerifier
	oauth      *oauth2.Config
	endSession string
}

// NewOIDC returns a client for cfg.
func NewOIDC(cfg OIDCConfig) *OIDC {
	raw := cfg
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	return &OIDC{raw: raw, cfg: cfg, client: NewIdPClient(cfg.AllowLoopback)}
}

func (o *OIDC) init(ctx context.Context) (*oidc.IDTokenVerifier, *oauth2.Config, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.verifier != nil {
		return o.verifier, o.oauth, nil
	}
	ctx = oidc.ClientContext(ctx, o.client)
	p, err := oidc.NewProvider(ctx, o.cfg.Issuer)
	if err != nil {
		return nil, nil, fmt.Errorf("oidc discovery: %w", err)
	}
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
	}
	_ = p.Claims(&meta)
	o.endSession = meta.EndSession
	o.verifier = p.Verifier(&oidc.Config{ClientID: o.cfg.ClientID})
	o.oauth = &oauth2.Config{
		ClientID: o.cfg.ClientID, ClientSecret: o.cfg.ClientSecret, RedirectURL: o.cfg.RedirectURL,
		Endpoint: p.Endpoint(), Scopes: o.cfg.Scopes,
	}
	return o.verifier, o.oauth, nil
}

// SafeReturnTo accepts only same-site relative paths, which prevents the
// login flow from being used as an open redirect.
func SafeReturnTo(s string) string {
	if s == "" || !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.ContainsAny(s, "\\\r\n\t") {
		return "/"
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return "/"
	}
	return s
}

// BeginLogin starts an OIDC authorization-code flow. It returns the IdP URL
// to redirect to and a short-lived cookie binding the flow to this browser.
func (m *Manager) BeginLogin(ctx context.Context, o LoginOptions) (string, *http.Cookie, error) {
	op := m.st().oidc
	if op == nil {
		return "", nil, errors.New("oidc not configured")
	}
	_, oc, err := op.init(ctx)
	if err != nil {
		return "", nil, err
	}
	token := secure.NewToken()
	req := &LoginRequest{
		TokenHash: secure.HashToken(secure.PurposeLogin, token),
		Kind:      "oidc",
		State:     secure.NewToken(), // CSRF protection for the callback
		Nonce:     secure.NewToken(), // binds the ID token to this flow (replay protection)
		Verifier:  oauth2.GenerateVerifier(),
		ReturnTo:  SafeReturnTo(o.ReturnTo),
		Reauth:    o.Reauth,
		Setup:     o.Setup,
		ExpiresAt: m.now().Add(loginTTL),
	}
	if err := m.store.CreateLoginRequest(ctx, req); err != nil {
		return "", nil, err
	}
	opts := []oauth2.AuthCodeOption{oidc.Nonce(req.Nonce), oauth2.S256ChallengeOption(req.Verifier)}
	if o.Reauth {
		// Ask for a fresh authentication; the ID token's auth_time
		// (required by the spec when max_age is sent) is checked on return.
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "login"), oauth2.SetAuthURLParam("max_age", "0"))
	}
	u := oc.AuthCodeURL(req.State, opts...)
	// SameSite=Lax: the cookie must accompany the top-level GET redirect back
	// from the IdP, which is a cross-site navigation.
	c := &http.Cookie{Name: LoginCookie, Value: token, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: 600}
	return u, c, nil
}

// ClearLoginCookie removes the login-flow cookie.
func ClearLoginCookie() *http.Cookie {
	return &http.Cookie{Name: LoginCookie, Value: "", Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: -1}
}

// ErrLoginFailed is deliberately vague towards the browser; details are logged.
var ErrLoginFailed = domain.E(domain.CodeUnauthorized, "sign-in failed; please try again")

// CompleteLogin handles the IdP's redirect back, returning the signed-in
// user and where to send them.
func (m *Manager) CompleteLogin(r *http.Request) (*LoginResult, error) {
	ctx := r.Context()
	op := m.st().oidc
	if op == nil {
		return nil, errors.New("oidc not configured")
	}
	verifier, oc, err := op.init(ctx)
	if err != nil {
		return nil, err
	}
	c, err := r.Cookie(LoginCookie)
	if err != nil || !secure.ValidToken(c.Value) {
		return nil, fmt.Errorf("%w (missing login cookie)", ErrLoginFailed)
	}
	// Consumed atomically: a login request can complete at most once.
	req, err := m.store.ConsumeLoginRequest(ctx, secure.HashToken(secure.PurposeLogin, c.Value), m.now())
	if err != nil || req.Kind != "oidc" {
		return nil, fmt.Errorf("%w (unknown or expired login request)", ErrLoginFailed)
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		return nil, fmt.Errorf("%w (idp error %.64q)", ErrLoginFailed, e)
	}
	if !secure.Equal(q.Get("state"), req.State) {
		return nil, fmt.Errorf("%w (state mismatch)", ErrLoginFailed)
	}
	ctx = oidc.ClientContext(ctx, op.client)
	tok, err := oc.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(req.Verifier))
	if err != nil {
		return nil, fmt.Errorf("%w (code exchange: %v)", ErrLoginFailed, err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("%w (no id_token)", ErrLoginFailed)
	}
	// Verifies signature (against the IdP's published keys), issuer,
	// audience and expiry.
	idt, err := verifier.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("%w (id_token: %v)", ErrLoginFailed, err)
	}
	if !secure.Equal(idt.Nonce, req.Nonce) {
		return nil, fmt.Errorf("%w (nonce mismatch)", ErrLoginFailed)
	}
	var claims map[string]json.RawMessage
	if err := idt.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w (claims: %v)", ErrLoginFailed, err)
	}
	id := service.Identity{
		Issuer:        idt.Issuer,
		Subject:       idt.Subject,
		Email:         claimString(claims, "email"),
		EmailVerified: claimBool(claims, "email_verified"),
		Name:          firstNonEmpty(claimString(claims, "name"), claimString(claims, "preferred_username")),
		Groups:        claimStrings(claims, op.cfg.GroupsClaim),
	}
	res := &LoginResult{ReturnTo: req.ReturnTo, Setup: req.Setup}
	if req.Reauth {
		// The spec requires auth_time when max_age was requested. If the
		// IdP sends it, it must show an authentication after this sign-in
		// started. Some IdPs omit it; then the confirmation rests on the
		// IdP honouring prompt=login, which is logged.
		if at, ok := claimTime(claims, "auth_time"); ok {
			if at.Before(req.Started().Add(-time.Minute)) {
				return nil, fmt.Errorf("%w (the identity provider did not authenticate again: auth_time is before the request)", ErrLoginFailed)
			}
		} else {
			m.log.WarnContext(ctx, "identity provider sent no auth_time for a re-authentication; relying on it honouring prompt=login")
		}
		res.ReauthAt = m.now()
	}
	if err := op.cfg.Policy.Check(id); err != nil {
		return nil, err
	}
	if res.User, err = m.svc.LoginUser(ctx, id); err != nil {
		return nil, err
	}
	return res, nil
}

// claimTime reads a NumericDate claim.
func claimTime(c map[string]json.RawMessage, k string) (time.Time, bool) {
	var n json.Number
	if json.Unmarshal(c[k], &n) != nil {
		return time.Time{}, false
	}
	f, err := n.Float64()
	if err != nil || f <= 0 {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0).UTC(), true
}

// ErrNotAllowed is shown when the IdP authenticated someone who is not
// permitted to use this FrontDir instance.
var ErrNotAllowed = domain.E(domain.CodeForbidden, "your account is not permitted to use this service")

// LogoutURL returns the IdP's RP-initiated logout URL, or "" if the IdP
// does not support it.
func (m *Manager) LogoutURL(ctx context.Context) string {
	op := m.st().oidc
	if op == nil {
		return ""
	}
	if _, _, err := op.init(ctx); err != nil || op.endSession == "" {
		return ""
	}
	u, err := url.Parse(op.endSession)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("client_id", op.cfg.ClientID)
	if op.cfg.PostLogoutRedirectURL != "" {
		q.Set("post_logout_redirect_uri", op.cfg.PostLogoutRedirectURL)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// claimStrings reads a claim that is a list of strings (or a single string).
func claimStrings(c map[string]json.RawMessage, k string) []string {
	var list []string
	if json.Unmarshal(c[k], &list) == nil {
		return list
	}
	if s := claimString(c, k); s != "" {
		return []string{s}
	}
	return nil
}

func claimString(c map[string]json.RawMessage, k string) string {
	var s string
	_ = json.Unmarshal(c[k], &s)
	return s
}

// claimBool accepts true or "true": some IdPs encode email_verified as a string.
func claimBool(c map[string]json.RawMessage, k string) bool {
	var b bool
	if json.Unmarshal(c[k], &b) == nil {
		return b
	}
	return claimString(c, k) == "true"
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
