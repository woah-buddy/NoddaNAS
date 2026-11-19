// Package config loads NoddaNAS settings from the environment.
//
// Every secret can be supplied either directly (NAME) or, preferably, as a
// path to a file (NAME_FILE), which is how Docker and Kubernetes secrets are
// mounted. File-based secrets stay out of `docker inspect`, process listings
// and crash dumps of the environment.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/woah-buddy/NoddaNAS/internal/auth"
	"github.com/woah-buddy/NoddaNAS/internal/service"
)

// Config is the complete runtime configuration.
type Config struct {
	PublicURL      *url.URL
	Listen         string
	DatabaseURL    string
	DataDir        string
	KeyringFile    string
	TrustedProxies []netip.Prefix
	WebDAV         bool
	Worker         bool
	AutoMigrate    bool
	LogLevel       string
	TLSCertFile    string
	TLSKeyFile     string
	OIDC           auth.OIDCConfig
	Auth           auth.Config
	Service        service.Config
}

// Load reads the configuration, failing closed on anything missing or unsafe.
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
		KeyringFile: env("NODDANAS_KEYRING_FILE", "/run/secrets/noddanas_keyring"),
		WebDAV:      envBool("NODDANAS_WEBDAV", true),
		Worker:      envBool("NODDANAS_WORKER", true),
		AutoMigrate: envBool("NODDANAS_AUTO_MIGRATE", true),
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

	c.OIDC = auth.OIDCConfig{
		Issuer:              req("NODDANAS_OIDC_ISSUER"),
		ClientID:            req("NODDANAS_OIDC_CLIENT_ID"),
		AllowedGroups:       list("NODDANAS_OIDC_ALLOWED_GROUPS"),
		GroupsClaim:         os.Getenv("NODDANAS_OIDC_GROUPS_CLAIM"),
		AllowedEmailDomains: lower(list("NODDANAS_OIDC_ALLOWED_EMAIL_DOMAINS")),
	}
	if s, err := secret("NODDANAS_OIDC_CLIENT_SECRET"); err != nil {
		errs = append(errs, err)
	} else {
		c.OIDC.ClientSecret = s
	}
	if scopes := list("NODDANAS_OIDC_SCOPES"); len(scopes) > 0 {
		c.OIDC.Scopes = scopes
	}
	if c.PublicURL != nil {
		c.OIDC.RedirectURL = c.PublicURL.String() + "/auth/callback"
		c.OIDC.PostLogoutRedirectURL = c.PublicURL.String() + "/"
	}

	c.Auth = auth.Config{
		SessionIdle:     envDuration(&errs, "NODDANAS_SESSION_IDLE", 12*time.Hour),
		SessionAbsolute: envDuration(&errs, "NODDANAS_SESSION_MAX_AGE", 7*24*time.Hour),
	}

	sc := service.DefaultConfig()
	sc.DefaultQuota = envSize(&errs, "NODDANAS_DEFAULT_QUOTA", sc.DefaultQuota)
	sc.MaxFileSize = envSize(&errs, "NODDANAS_MAX_FILE_SIZE", sc.MaxFileSize)
	sc.MaxVersions = int(envInt(&errs, "NODDANAS_MAX_VERSIONS", int64(sc.MaxVersions), 1, 1000))
	sc.TrashRetention = envDuration(&errs, "NODDANAS_TRASH_RETENTION", sc.TrashRetention)
	sc.LinkDefaultTTL = envDuration(&errs, "NODDANAS_LINK_DEFAULT_TTL", sc.LinkDefaultTTL)
	sc.LinkMaxTTL = envDuration(&errs, "NODDANAS_LINK_MAX_TTL", sc.LinkMaxTTL)
	c.Service = sc

	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		errs = append(errs, errors.New("set both NODDANAS_TLS_CERT_FILE and NODDANAS_TLS_KEY_FILE, or neither"))
	}
	return c, errors.Join(errs...)
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
		b, err := os.ReadFile(file)
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

func lower(ss []string) []string {
	for i := range ss {
		ss[i] = strings.ToLower(ss[i])
	}
	return ss
}

func envBool(name string, def bool) bool {
	v, err := strconv.ParseBool(os.Getenv(name))
	if err != nil {
		return def
	}
	return v
}

func envInt(errs *[]error, name string, def, lo, hi int64) int64 {
	s := os.Getenv(name)
	if s == "" {
		return def
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < lo || n > hi {
		*errs = append(*errs, fmt.Errorf("%s must be an integer between %d and %d", name, lo, hi))
		return def
	}
	return n
}

// envDuration accepts Go durations ("12h") plus a "d" suffix for days ("30d").
func envDuration(errs *[]error, name string, def time.Duration) time.Duration {
	s := os.Getenv(name)
	if s == "" {
		return def
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		if n, err := strconv.Atoi(days); err == nil && n > 0 {
			return time.Duration(n) * 24 * time.Hour
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		*errs = append(*errs, fmt.Errorf("%s must be a positive duration like 12h or 30d", name))
		return def
	}
	return d
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

func envSize(errs *[]error, name string, def int64) int64 {
	s := os.Getenv(name)
	if s == "" {
		return def
	}
	n, err := ParseSize(s)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s: %w", name, err))
		return def
	}
	return n
}
