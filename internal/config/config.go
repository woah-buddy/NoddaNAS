// Package config loads NoddaNAS settings from the environment and defines
// the settings an administrator can also change on the web (settings.go).
//
// Every secret can be supplied either directly (NAME) or, preferably, as a
// path to a file (NAME_FILE), which is how Docker and Kubernetes secrets are
// mounted. File-based secrets stay out of `docker inspect`, process listings
// and crash dumps of the environment.
package config

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/woah-buddy/NoddaNAS/internal/auth"
	"github.com/woah-buddy/NoddaNAS/internal/service"
	"github.com/woah-buddy/NoddaNAS/internal/theme"
)

// Config is the server's configuration: the server-only settings, plus the
// changeable settings as the environment sets them (Env) and the runtime
// built from the environment alone (OIDC through Theme). At serve time the
// settings manager merges in web values and rebuilds the runtime.
type Config struct {
	PublicURL      *url.URL
	Listen         string
	DatabaseURL    string
	DataDir        string
	TrustedProxies []netip.Prefix
	WebDAV         bool
	Worker         bool
	AutoMigrate    bool
	LogLevel       string
	TLSCertFile    string
	TLSKeyFile     string

	// SAML service-provider key pair (optional; signs AuthnRequests and
	// decrypts encrypted assertions). Server-only: it is a private key.
	SAMLKey  crypto.Signer
	SAMLCert *x509.Certificate

	// SettingsKey encrypts secrets saved from the web admin area (nil if
	// not configured: the web admin area then cannot store secrets).
	SettingsKey []byte
	// WebSettings is false when every setting is read-only on the web.
	WebSettings bool

	Env Values // changeable settings as set in the environment

	OIDC    *auth.OIDCConfig // nil if OIDC sign-in is not configured in the environment
	SAML    *auth.SAMLConfig // nil if SAML sign-in is not configured in the environment
	Policy  auth.Policy
	Auth    auth.Config
	Service service.Config
	Theme   *theme.Theme // never nil after a successful Load
}

// Load reads the configuration from the environment, failing closed on
// anything missing or unsafe. Having no sign-in method is not an error: the
// server then starts in setup mode (see `noddanas setup-link`).
func Load() (*Config, error) {
	var errs []error
	req := func(name string) string {
		v, err := secret(name)
		if err != nil {
			errs = append(errs, err)
		} else if v == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
		return v
	}

	c := &Config{
		Listen:      env("NODDANAS_LISTEN", ":8080"),
		DataDir:     env("NODDANAS_DATA_DIR", "/data"),
		WebDAV:      envBool(&errs, "NODDANAS_WEBDAV", true),
		Worker:      envBool(&errs, "NODDANAS_WORKER", true),
		AutoMigrate: envBool(&errs, "NODDANAS_AUTO_MIGRATE", true),
		WebSettings: envBool(&errs, "NODDANAS_WEB_SETTINGS", true),
		LogLevel:    env("NODDANAS_LOG_LEVEL", "info"),
		TLSCertFile: os.Getenv("NODDANAS_TLS_CERT_FILE"),
		TLSKeyFile:  os.Getenv("NODDANAS_TLS_KEY_FILE"),
	}
	c.DatabaseURL = req("NODDANAS_DATABASE_URL")

	pub := req("NODDANAS_PUBLIC_URL")
	if pub != "" {
		u, err := url.Parse(pub)
		switch {
		case err != nil || u.Host == "" || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.User != nil:
			errs = append(errs, errors.New("NODDANAS_PUBLIC_URL must be an origin like https://files.example.com"))
		case u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())):
			errs = append(errs, errors.New("NODDANAS_PUBLIC_URL must use https (plain http is allowed only for localhost)"))
		default:
			u.Path = ""
			c.PublicURL = u
		}
	}

	for _, s := range list("NODDANAS_TRUSTED_PROXIES") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				errs = append(errs, fmt.Errorf("NODDANAS_TRUSTED_PROXIES: invalid %q", s))
				continue
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		c.TrustedProxies = append(c.TrustedProxies, p.Masked())
	}

	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		errs = append(errs, errors.New("set both NODDANAS_TLS_CERT_FILE and NODDANAS_TLS_KEY_FILE, or neither"))
	}
	if err := loadSAMLKeyPair(c); err != nil {
		errs = append(errs, err)
	}
	if key, err := secret("NODDANAS_SETTINGS_KEY"); err != nil {
		errs = append(errs, err)
	} else if key != "" {
		if c.SettingsKey, err = ParseSettingsKey(key); err != nil {
			errs = append(errs, fmt.Errorf("NODDANAS_SETTINGS_KEY: %w", err))
		}
	}

	var err error
	if c.Env, err = envValues(); err != nil {
		errs = append(errs, err)
	} else if rt, err := Build(c.Env, c); err != nil {
		errs = append(errs, err)
	} else {
		c.OIDC, c.SAML, c.Policy, c.Auth, c.Service, c.Theme = rt.OIDC, rt.SAML, rt.Policy, rt.Auth, rt.Service, rt.Theme
		if !rt.SignIn() && !c.WebSettings {
			errs = append(errs, errors.New("no sign-in method is configured, and NODDANAS_WEB_SETTINGS=false means none can be set up on the web: "+
				"set NODDANAS_OIDC_ISSUER and/or NODDANAS_SAML_IDP_METADATA_URL (or _FILE)"))
		}
	}
	return c, errors.Join(errs...)
}

// envValues reads every changeable setting from the environment. Files
// named by *_FILE variables are read (with a size bound); a logo becomes
// base64. Sign-in settings must come as a whole: a stray OIDC or SAML
// variable without the one that switches the method on is an error, not
// something to quietly mix with values saved on the web.
func envValues() (Values, error) {
	v := Values{}
	var errs []error
	for _, s := range Registry {
		var val string
		switch {
		case s.Secret():
			x, err := secret(s.Env)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			val = x
		case s.File:
			name := os.Getenv(s.Env)
			if name == "" {
				continue
			}
			b, err := readLimited(name, int64(s.Max))
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", s.Env, err))
				continue
			}
			if s.Kind == "image" {
				val = base64.StdEncoding.EncodeToString(b)
			} else {
				val = string(b)
			}
		default:
			val = os.Getenv(s.Env)
		}
		if val = strings.TrimSpace(val); val != "" {
			v[s.Key] = val
		}
	}
	for group, anchor := range signInGroups {
		if groupSet(v, anchor) {
			continue
		}
		for _, s := range Registry {
			if s.Group == group && v[s.Key] != "" {
				errs = append(errs, fmt.Errorf("%s is set but sign-in method %q is not switched on in the environment (%s): "+
					"configure it entirely in the environment or entirely in the web admin area", s.Env, group, anchorEnv(anchor)))
			}
		}
	}
	return v, errors.Join(errs...)
}

func anchorEnv(anchor string) string {
	var names []string
	for _, k := range strings.Split(anchor, "|") {
		s, _ := Lookup(k)
		names = append(names, s.Env)
	}
	return strings.Join(names, " or ")
}

// ParseSettingsKey decodes a 256-bit key given as base64 (standard or URL
// alphabet, padded or not) or hex.
func ParseSettingsKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, errors.New("must be 32 random bytes, base64- or hex-encoded (scripts/init-secrets.sh creates one)")
}

// readLimited reads a whole file but refuses anything over max bytes, so a
// misconfigured path (a huge file, /dev/zero) cannot exhaust memory.
func readLimited(name string, max int64) ([]byte, error) {
	f, err := os.Open(name) // #nosec G304 G703 -- path chosen by the operator in configuration
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("file is larger than %d KiB", max>>10)
	}
	return b, nil
}

func loadSAMLKeyPair(c *Config) error {
	keyFile, certFile := os.Getenv("NODDANAS_SAML_SP_KEY_FILE"), os.Getenv("NODDANAS_SAML_SP_CERT_FILE")
	if (keyFile == "") != (certFile == "") {
		return errors.New("set both NODDANAS_SAML_SP_KEY_FILE and NODDANAS_SAML_SP_CERT_FILE, or neither")
	}
	if keyFile == "" {
		return nil
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("SAML SP key pair: %w", err)
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return errors.New("SAML SP key cannot sign")
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	c.SAMLKey, c.SAMLCert = signer, cert
	return nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// secret reads NAME, or the file named by NAME_FILE (but not both).
func secret(name string) (string, error) {
	v, file := os.Getenv(name), os.Getenv(name+"_FILE")
	switch {
	case v != "" && file != "":
		return "", fmt.Errorf("set only one of %s and %s_FILE", name, name)
	case file != "":
		b, err := os.ReadFile(file) // #nosec G304 G703 -- path chosen by the operator in configuration
		if err != nil {
			return "", fmt.Errorf("%s_FILE: %w", name, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return v, nil
}

func list(name string) []string {
	var out []string
	for _, s := range strings.Split(os.Getenv(name), ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// envBool reads a boolean. Anything other than empty or a recognised
// boolean is an error: a typo must not silently become the default.
func envBool(errs *[]error, name string, def bool) bool {
	s := strings.TrimSpace(os.Getenv(name))
	if s == "" {
		return def
	}
	v, err := strconv.ParseBool(s)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s must be true or false", name))
		return def
	}
	return v
}

// ParseSize accepts plain bytes or a binary-unit suffix: KiB, MiB, GiB, TiB.
func ParseSize(s string) (int64, error) {
	units := []struct {
		suffix string
		mult   int64
	}{{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"B", 1}}
	s = strings.TrimSpace(s)
	mult := int64(1)
	for _, u := range units {
		if v, ok := strings.CutSuffix(s, u.suffix); ok {
			s, mult = strings.TrimSpace(v), u.mult
			break
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 || n > (1<<62)/mult {
		return 0, fmt.Errorf("invalid size %q (use e.g. 10GiB)", s)
	}
	return n * mult, nil
}
