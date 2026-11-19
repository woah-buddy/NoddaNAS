package auth

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"

	"github.com/woah-buddy/FrontDir/internal/secure"
	"github.com/woah-buddy/FrontDir/internal/service"
)

// SAML 2.0 single sign-on (service-provider side).
//
// SAML is notoriously easy to get wrong (XML signature wrapping, replay,
// unsolicited responses). FrontDir relies on crewjam/saml for XML signature
// validation and assertion checks (signature required, audience, issuer,
// destination, validity window, InResponseTo) and adds its own rules:
//
//   - Only SP-initiated sign-in. Unsolicited (IdP-initiated) responses are
//     refused, which prevents login CSRF.
//   - Every response must answer an AuthnRequest that this browser started
//     (bound by a __Host- cookie) and that has not been used before: the
//     request record is consumed atomically, so a captured response cannot
//     be replayed.
//   - Only the HTTP-POST binding is accepted at the ACS. The artifact
//     binding would make the server call out based on request input.
//   - Asserted emails are treated as verified only if the operator says the
//     IdP verifies them (SAML has no email_verified attribute).

// SAMLConfig configures the SAML service provider.
type SAMLConfig struct {
	EntityID       string // our entity ID (defaults to the metadata URL)
	MetadataURL    string // our metadata URL: <public>/auth/saml/metadata
	ACSURL         string // our assertion consumer service: <public>/auth/saml/acs
	IDPMetadata    []byte // IdP metadata XML (from a file) ...
	IDPMetadataURL string // ... or an https URL to fetch it from

	// Optional SP key pair: signs AuthnRequests and decrypts encrypted assertions.
	Key         crypto.Signer
	Certificate *x509.Certificate

	EmailAttributes []string
	NameAttributes  []string
	GroupAttributes []string
	TrustEmail      bool // treat asserted emails as verified

	Policy Policy

	// AllowLoopback lets the server fetch metadata from a loopback address
	// (localhost deployments only; see NewIdPClient).
	AllowLoopback bool
}

// Default attribute names cover common IdPs (Entra ID, Okta, Shibboleth, Keycloak).
var (
	DefaultSAMLEmailAttrs = []string{"email", "mail", "urn:oid:0.9.2342.19200300.100.1.3",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"}
	DefaultSAMLNameAttrs = []string{"displayName", "name", "cn", "urn:oid:2.16.840.1.113730.3.1.241",
		"urn:oid:2.5.4.3", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"}
	DefaultSAMLGroupAttrs = []string{"groups", "memberOf", "eduPersonAffiliation", "urn:oid:1.3.6.1.4.1.5923.1.1.1.1",
		"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"}
)

// SAMLCookie binds an in-flight SAML sign-in to the browser. It must be
// SameSite=None: the IdP returns the user with a cross-site POST.
const SAMLCookie = "__Host-fd_saml"

// SAML is a lazily-initialized service provider (IdP metadata is fetched
// on first use, so FrontDir starts even if the IdP is down).
type SAML struct {
	raw    SAMLConfig // as given, to detect changes
	cfg    SAMLConfig // with defaults applied
	client *http.Client
	mu     sync.Mutex
	sp     *saml.ServiceProvider
}

// NewSAML returns a SAML service provider for cfg.
func NewSAML(cfg SAMLConfig) *SAML {
	raw := cfg
	if len(cfg.EmailAttributes) == 0 {
		cfg.EmailAttributes = DefaultSAMLEmailAttrs
	}
	if len(cfg.NameAttributes) == 0 {
		cfg.NameAttributes = DefaultSAMLNameAttrs
	}
	if len(cfg.GroupAttributes) == 0 {
		cfg.GroupAttributes = DefaultSAMLGroupAttrs
	}
	if cfg.EntityID == "" {
		cfg.EntityID = cfg.MetadataURL
	}
	return &SAML{raw: raw, cfg: cfg, client: NewIdPClient(cfg.AllowLoopback)}
}

func (s *SAML) provider(ctx context.Context) (*saml.ServiceProvider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sp != nil {
		return s.sp, nil
	}
	var md *saml.EntityDescriptor
	var err error
	switch {
	case len(s.cfg.IDPMetadata) > 0:
		md, err = samlsp.ParseMetadata(s.cfg.IDPMetadata)
	case s.cfg.IDPMetadataURL != "":
		var u *url.URL
		u, err = url.Parse(s.cfg.IDPMetadataURL)
		if err == nil {
			md, err = samlsp.FetchMetadata(ctx, s.client, *u)
		}
	default:
		err = errors.New("no IdP metadata configured")
	}
	if err == nil {
		_, err = checkIdPMetadata(md)
	}
	if err != nil {
		return nil, fmt.Errorf("saml: IdP metadata: %w", err)
	}
	acs, err1 := url.Parse(s.cfg.ACSURL)
	meta, err2 := url.Parse(s.cfg.MetadataURL)
	if err1 != nil || err2 != nil {
		return nil, errors.New("saml: invalid SP URLs")
	}
	sp := &saml.ServiceProvider{
		EntityID: s.cfg.EntityID, Key: s.cfg.Key, Certificate: s.cfg.Certificate,
		MetadataURL: *meta, AcsURL: *acs, IDPMetadata: md,
		AuthnNameIDFormat: saml.PersistentNameIDFormat,
		AllowIDPInitiated: false,
		HTTPClient:        s.client,
	}
	if s.cfg.Key != nil {
		sp.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	}
	s.sp = sp
	return sp, nil
}

// Metadata returns our SP metadata XML for registering with the IdP.
func (s *SAML) Metadata(ctx context.Context) (*saml.EntityDescriptor, error) {
	sp, err := s.provider(ctx)
	if err != nil {
		return nil, err
	}
	return sp.Metadata(), nil
}

// BeginSAMLLogin starts SP-initiated sign-in: it records the AuthnRequest
// ID server-side and returns the IdP redirect plus the binding cookie.
func (m *Manager) BeginSAMLLogin(ctx context.Context, o LoginOptions) (string, *http.Cookie, error) {
	sm := m.st().saml
	if sm == nil {
		return "", nil, errors.New("saml not configured")
	}
	sp, err := sm.provider(ctx)
	if err != nil {
		return "", nil, err
	}
	req, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(saml.HTTPRedirectBinding),
		saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return "", nil, err
	}
	if o.Reauth {
		force := true
		req.ForceAuthn = &force // checked against AuthnInstant on return
	}
	u, err := req.Redirect("", sp)
	if err != nil {
		return "", nil, err
	}
	token := secure.NewToken()
	if err := m.store.CreateLoginRequest(ctx, &LoginRequest{
		TokenHash: secure.HashToken(secure.PurposeLogin, token), Kind: "saml", State: req.ID,
		ReturnTo: SafeReturnTo(o.ReturnTo), Reauth: o.Reauth, Setup: o.Setup, ExpiresAt: m.now().Add(loginTTL),
	}); err != nil {
		return "", nil, err
	}
	// SameSite=None is required: the IdP returns the user with a cross-site
	// POST, and a Lax or Strict cookie would not be sent with it. The cookie
	// is still Secure, HttpOnly, __Host- prefixed, valid for 10 minutes, and
	// useless on its own (it only binds one pending sign-in to this browser).
	c := &http.Cookie{Name: SAMLCookie, Value: token, Path: "/", Secure: true, HttpOnly: true, // #nosec G124 -- see above
		SameSite: http.SameSiteNoneMode, MaxAge: 600}
	return u.String(), c, nil
}

// ClearSAMLCookie removes the SAML binding cookie.
func ClearSAMLCookie() *http.Cookie {
	return &http.Cookie{Name: SAMLCookie, Value: "", Path: "/", Secure: true, HttpOnly: true, // #nosec G124 -- deletes the cookie above; attributes match it
		SameSite: http.SameSiteNoneMode, MaxAge: -1}
}

// CompleteSAMLLogin validates the IdP's POST to the assertion consumer
// service and signs the user in.
func (m *Manager) CompleteSAMLLogin(r *http.Request) (*LoginResult, error) {
	ctx := r.Context()
	sm := m.st().saml
	if sm == nil {
		return nil, errors.New("saml not configured")
	}
	sp, err := sm.provider(ctx)
	if err != nil {
		return nil, err
	}
	c, err := r.Cookie(SAMLCookie)
	if err != nil || !secure.ValidToken(c.Value) {
		return nil, fmt.Errorf("%w (missing SAML login cookie; unsolicited responses are not accepted)", ErrLoginFailed)
	}
	req, err := m.store.ConsumeLoginRequest(ctx, secure.HashToken(secure.PurposeLogin, c.Value), m.now())
	if err != nil || req.Kind != "saml" {
		return nil, fmt.Errorf("%w (unknown, used or expired SAML request)", ErrLoginFailed)
	}
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("%w (bad form)", ErrLoginFailed)
	}
	if r.PostForm.Get("SAMLart") != "" || r.PostForm.Get("SAMLResponse") == "" {
		return nil, fmt.Errorf("%w (only the HTTP-POST binding is accepted)", ErrLoginFailed)
	}
	assertion, err := sp.ParseResponse(r, []string{req.State})
	if err != nil {
		var ire *saml.InvalidResponseError
		if errors.As(err, &ire) {
			err = ire.PrivateErr
		}
		return nil, fmt.Errorf("%w (assertion: %v)", ErrLoginFailed, err)
	}
	if assertion.Subject == nil || assertion.Subject.NameID == nil || strings.TrimSpace(assertion.Subject.NameID.Value) == "" {
		return nil, fmt.Errorf("%w (assertion has no NameID)", ErrLoginFailed)
	}
	if assertion.Issuer.Value != sp.IDPMetadata.EntityID {
		return nil, fmt.Errorf("%w (unexpected issuer)", ErrLoginFailed)
	}
	attrs := samlAttributes(assertion)
	id := service.Identity{
		Issuer:  "saml:" + assertion.Issuer.Value,
		Subject: assertion.Subject.NameID.Value,
		Email:   first(attrs, sm.cfg.EmailAttributes),
		Name:    first(attrs, sm.cfg.NameAttributes),
		Groups:  all(attrs, sm.cfg.GroupAttributes),
	}
	id.EmailVerified = sm.cfg.TrustEmail && id.Email != ""
	res := &LoginResult{ReturnTo: req.ReturnTo, Setup: req.Setup}
	if req.Reauth {
		// We sent ForceAuthn; the assertion must record an authentication
		// that happened after this sign-in started.
		fresh := false
		for _, st := range assertion.AuthnStatements {
			fresh = fresh || !st.AuthnInstant.Before(req.Started().Add(-time.Minute))
		}
		if !fresh {
			return nil, fmt.Errorf("%w (the identity provider did not authenticate again: AuthnInstant is before the request)", ErrLoginFailed)
		}
		res.ReauthAt = m.now()
	}
	if err := sm.cfg.Policy.Check(id); err != nil {
		return nil, err
	}
	if res.User, err = m.svc.LoginUser(ctx, id); err != nil {
		return nil, err
	}
	return res, nil
}

func samlAttributes(a *saml.Assertion) map[string][]string {
	out := map[string][]string{}
	for _, st := range a.AttributeStatements {
		for _, at := range st.Attributes {
			for _, v := range at.Values {
				val := strings.TrimSpace(v.Value)
				if val == "" {
					continue
				}
				out[at.Name] = append(out[at.Name], val)
				if at.FriendlyName != "" {
					out[at.FriendlyName] = append(out[at.FriendlyName], val)
				}
			}
		}
	}
	return out
}

func first(attrs map[string][]string, names []string) string {
	for _, n := range names {
		if v := attrs[n]; len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

func all(attrs map[string][]string, names []string) []string {
	var out []string
	for _, n := range names {
		for _, v := range attrs[n] {
			if !slices.Contains(out, v) {
				out = append(out, v)
			}
		}
	}
	return out
}
