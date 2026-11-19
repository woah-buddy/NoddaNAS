package config

import (
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// fixedInCompose lists settings that the Docker Compose setup deliberately
// does not let .env change, and why. Everything else the server reads must
// be passed through, or setting it in .env would be silently ignored.
var fixedInCompose = map[string]string{
	"NODDANAS_LISTEN":        "Caddy proxies to port 8080",
	"NODDANAS_DATA_DIR":      "the noddanas-data volume is mounted at /data",
	"NODDANAS_TLS_CERT_FILE": "Caddy terminates TLS",
	"NODDANAS_TLS_KEY_FILE":  "Caddy terminates TLS",
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// settingsRead returns every NODDANAS_* variable this package reads (each
// appears as a whole string literal in config.go).
func settingsRead(t *testing.T) []string {
	t.Helper()
	seen := map[string]bool{}
	for _, m := range regexp.MustCompile(`"(NODDANAS_[A-Z0-9_]+)"`).FindAllStringSubmatch(readFile(t, "config.go"), -1) {
		seen[m[1]] = true
	}
	var out []string
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	if len(out) < 30 {
		t.Fatalf("found only %d settings in config.go; the pattern is out of date", len(out))
	}
	return out
}

// noddanasService returns the noddanas service's section of compose.yaml.
func noddanasService(t *testing.T) string {
	t.Helper()
	compose := readFile(t, "../../deploy/compose/compose.yaml")
	start := strings.Index(compose, "\n  noddanas:\n")
	if start < 0 {
		t.Fatal("no noddanas service in compose.yaml")
	}
	rest := compose[start+1:]
	if end := regexp.MustCompile(`\n  [a-z][a-z0-9-]*:\n`).FindStringIndex(rest[1:]); end != nil {
		rest = rest[:end[0]+1]
	}
	return rest
}

func TestComposePassesEverySetting(t *testing.T) {
	compose := noddanasService(t)
	wired := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s+(NODDANAS_[A-Z0-9_]+):`).FindAllStringSubmatch(compose, -1) {
		wired[m[1]] = true
	}
	read := map[string]bool{}
	for _, v := range settingsRead(t) {
		read[v] = true
		inCompose := wired[v] || wired[v+"_FILE"]
		if _, fixed := fixedInCompose[v]; fixed {
			if inCompose {
				t.Errorf("%s is listed as fixed but compose.yaml sets it", v)
			}
			continue
		}
		if !inCompose {
			t.Errorf("%s is not passed through deploy/compose/compose.yaml: setting it in .env would be silently ignored", v)
		}
	}
	for v := range wired {
		if !read[v] && !read[strings.TrimSuffix(v, "_FILE")] {
			t.Errorf("compose.yaml sets %s, which the server does not read (typo?)", v)
		}
	}
}

func TestEnvExampleExplainsEveryVariable(t *testing.T) {
	compose := readFile(t, "../../deploy/compose/compose.yaml")
	example := readFile(t, "../../deploy/compose/.env.example")
	for _, m := range regexp.MustCompile(`\$\{([A-Z0-9_]+)`).FindAllStringSubmatch(compose, -1) {
		if !regexp.MustCompile(`(?m)^#?` + m[1] + `=`).MatchString(example) {
			t.Errorf("compose.yaml reads ${%s} but .env.example does not mention it", m[1])
		}
	}
}

func TestAdminGuideDocumentsEverySetting(t *testing.T) {
	guide := readFile(t, "../../docs/ADMIN_GUIDE.md")
	for _, v := range settingsRead(t) {
		if !regexp.MustCompile("`" + v + "(_FILE)?`").MatchString(guide) {
			t.Errorf("%s is not documented (in full, as `%s`) in docs/ADMIN_GUIDE.md", v, v)
		}
	}
}

// Compose passes every optional setting even when .env leaves it out, as an
// empty string. Empty must therefore mean exactly what unset means.
func TestEmptyComposeSettingsMeanDefaults(t *testing.T) {
	base := map[string]string{
		"NODDANAS_PUBLIC_URL": "https://files.example.com", "NODDANAS_DATABASE_URL": "postgres://x",
		"NODDANAS_OIDC_ISSUER": "https://idp.example.com", "NODDANAS_OIDC_CLIENT_ID": "c",
	}
	load := func(extra map[string]string) *Config {
		t.Helper()
		for _, v := range settingsRead(t) {
			os.Unsetenv(v)
			os.Unsetenv(v + "_FILE")
		}
		for k, v := range base {
			t.Setenv(k, v)
		}
		for k, v := range extra {
			t.Setenv(k, v)
		}
		c, err := Load()
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		return c
	}
	// Every setting compose.yaml passes with an empty default (${X:-}).
	empty := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^\s+(NODDANAS_[A-Z0-9_]+): \$\{[A-Z0-9_]+:-\}\s*$`).FindAllStringSubmatch(noddanasService(t), -1) {
		if _, required := base[m[1]]; !required {
			empty[m[1]] = ""
		}
	}
	if len(empty) < 25 {
		t.Fatalf("found only %d empty-default settings; the pattern is out of date", len(empty))
	}
	unset, blank := load(nil), load(empty)
	same := func(name string, a, b any) {
		if !reflect.DeepEqual(a, b) {
			t.Errorf("%s differs when settings are empty rather than unset:\n unset: %+v\n empty: %+v", name, a, b)
		}
	}
	same("Service", unset.Service, blank.Service)
	same("Auth", unset.Auth, blank.Auth)
	same("Policy", unset.Policy, blank.Policy)
	same("OIDC", *unset.OIDC, *blank.OIDC)
	same("SAML", unset.SAML, blank.SAML)
	same("runtime", []any{unset.Listen, unset.DataDir, unset.WebDAV, unset.Worker, unset.AutoMigrate, unset.LogLevel, unset.TLSCertFile},
		[]any{blank.Listen, blank.DataDir, blank.WebDAV, blank.Worker, blank.AutoMigrate, blank.LogLevel, blank.TLSCertFile})
	same("theme", unset.Theme.Name, blank.Theme.Name)
}
