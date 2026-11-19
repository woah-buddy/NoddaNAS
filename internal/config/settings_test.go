package config

import (
	"net/url"
	"reflect"
	"strings"
	"testing"
)

var testFixed = func() *Config {
	u, _ := url.Parse("https://files.example.com")
	return &Config{PublicURL: u}
}()

// The defaults the admin area shows are the defaults Build applies.
func TestRegistryDefaultsMatchBuild(t *testing.T) {
	empty, err := Build(Values{}, testFixed)
	if err != nil {
		t.Fatal(err)
	}
	explicit := Values{}
	for _, s := range Registry {
		if s.Default != "" && s.Group != "oidc" && s.Group != "saml" {
			explicit[s.Key] = s.Default
		}
	}
	got, err := Build(explicit, testFixed)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(empty.Service, got.Service) || !reflect.DeepEqual(empty.Auth, got.Auth) || empty.Theme.Name != got.Theme.Name {
		t.Errorf("registry defaults differ from built-in defaults:\n%+v\n%+v", empty.Service, got.Service)
	}
	oidc, err := Build(Values{"OIDC_ISSUER": "https://id.example.com", "OIDC_CLIENT_ID": "c",
		"OIDC_SCOPES": "openid, email, profile", "OIDC_GROUPS_CLAIM": "groups"}, testFixed)
	if err != nil || oidc.OIDC.RedirectURL != "https://files.example.com/auth/callback" || oidc.OIDC.AllowLoopback {
		t.Fatalf("oidc: %+v %v", oidc, err)
	}
	for _, s := range Registry {
		if s.Env == "" || s.Label == "" || s.Help == "" || s.Max == 0 {
			t.Errorf("%s is incompletely described", s.Key)
		}
	}
}

func TestBuildRejectsWithFieldErrors(t *testing.T) {
	for _, tc := range []struct {
		v   Values
		key string
	}{
		{Values{"DEFAULT_QUOTA": "lots"}, "DEFAULT_QUOTA"},
		{Values{"MAX_FILE_SIZE": "1KiB"}, "MAX_FILE_SIZE"},
		{Values{"MAX_VERSIONS": "0"}, "MAX_VERSIONS"},
		{Values{"TRASH_RETENTION": "5m"}, "TRASH_RETENTION"},
		{Values{"TRASH_RETENTION": "99999999d"}, "TRASH_RETENTION"}, // would overflow
		{Values{"SESSION_IDLE": "1s"}, "SESSION_IDLE"},
		{Values{"SESSION_IDLE": "8d"}, "SESSION_IDLE"}, // longer than the 7d maximum age
		{Values{"LINK_DEFAULT_TTL": "400d"}, "LINK_DEFAULT_TTL"},
		{Values{"TEAM_CREATION": "yes please"}, "TEAM_CREATION"},
		{Values{"ALLOWED_EMAIL_DOMAINS": "example.com, not a domain"}, "ALLOWED_EMAIL_DOMAINS"},
		{Values{"OIDC_ISSUER": "http://id.example.com", "OIDC_CLIENT_ID": "c"}, "OIDC_ISSUER"},
		{Values{"OIDC_ISSUER": "https://u:p@id.example.com", "OIDC_CLIENT_ID": "c"}, "OIDC_ISSUER"},
		{Values{"OIDC_ISSUER": "https://id.example.com"}, "OIDC_CLIENT_ID"},
		{Values{"OIDC_ISSUER": "https://id.example.com", "OIDC_CLIENT_ID": "c", "OIDC_SCOPES": "email"}, "OIDC_SCOPES"},
		{Values{"SAML_IDP_METADATA_URL": "http://idp.example.com/md"}, "SAML_IDP_METADATA_URL"},
		{Values{"SAML_IDP_METADATA_URL": "https://idp.example.com/md", "SAML_IDP_METADATA": "<x/>"}, "SAML_IDP_METADATA_URL"},
		{Values{"SAML_IDP_METADATA": "<html>not metadata</html>"}, "SAML_IDP_METADATA"},
		{Values{"BRAND_NAME": "Acme\u202eFiles"}, "BRAND_NAME"},
		{Values{"BRAND_NAME": "Acme\nFiles"}, "BRAND_NAME"},
		{Values{"THEME": `{"light": {"text": "#fafafa"}}`}, "THEME"},
		{Values{"BRAND_LOGO": "bm90IGFuIGltYWdl"}, "BRAND_LOGO"},
		{Values{"OIDC_CLIENT_ID": strings.Repeat("x", 600), "OIDC_ISSUER": "https://id.example.com"}, "OIDC_CLIENT_ID"},
		{Values{"NO_SUCH_SETTING": "1"}, "NO_SUCH_SETTING"},
	} {
		_, err := Build(tc.v, testFixed)
		fes := FieldErrors(err)
		found := false
		for _, fe := range fes {
			found = found || fe.Key == tc.key
		}
		if !found {
			t.Errorf("%v: want an error on %s, got %v", tc.v, tc.key, err)
		}
	}
	// At startup the message names the environment variable.
	_, err := Build(Values{"THEME": "{"}, testFixed)
	if err == nil || !strings.Contains(err.Error(), "FRONTDIR_THEME_FILE") {
		t.Errorf("env name missing from %v", err)
	}
}

func TestBuildAllowsLoopbackIdPOnlyOnLocalhost(t *testing.T) {
	local, _ := url.Parse("http://localhost:8080")
	v := Values{"OIDC_ISSUER": "http://127.0.0.1:9000", "OIDC_CLIENT_ID": "c"}
	rt, err := Build(v, &Config{PublicURL: local})
	if err != nil || !rt.OIDC.AllowLoopback {
		t.Fatalf("localhost deployment: %+v %v", rt, err)
	}
	if _, err := Build(v, testFixed); err == nil {
		t.Fatal("plain-http loopback issuer accepted on a public deployment")
	}
}

func TestMergePrecedenceAndSignInGroups(t *testing.T) {
	env := Values{"DEFAULT_QUOTA": "1GiB"}
	web := Values{"DEFAULT_QUOTA": "2GiB", "MAX_VERSIONS": "5", "OIDC_ISSUER": "https://web-idp", "OIDC_CLIENT_ID": "w"}
	got, src := Merge(env, web)
	if got["DEFAULT_QUOTA"] != "1GiB" || src["DEFAULT_QUOTA"] != SourceServer || !Locked(env, "DEFAULT_QUOTA") {
		t.Errorf("environment must win and lock: %v %v", got, src)
	}
	if got["MAX_VERSIONS"] != "5" || src["MAX_VERSIONS"] != SourceWeb || Locked(env, "MAX_VERSIONS") {
		t.Errorf("web value: %v %v", got, src)
	}
	if src["TRASH_RETENTION"] != SourceDefault {
		t.Errorf("default: %v", src)
	}
	if got["OIDC_ISSUER"] != "https://web-idp" || src["OIDC_CLIENT_ID"] != SourceWeb {
		t.Errorf("web OIDC: %v %v", got, src)
	}
	// OIDC in the environment takes the whole group: no web value leaks in.
	env["OIDC_ISSUER"] = "https://env-idp"
	got, src = Merge(env, web)
	if got["OIDC_ISSUER"] != "https://env-idp" || got["OIDC_CLIENT_ID"] != "" || src["OIDC_CLIENT_ID"] != SourceServer ||
		!Locked(env, "OIDC_CLIENT_SECRET") || !GroupFromServer(env, "oidc") || GroupFromServer(env, "saml") {
		t.Errorf("group lock: %v %v", got, src)
	}
	// Web values of a sign-in method that is not switched on are ignored.
	got, _ = Merge(Values{}, Values{"OIDC_CLIENT_ID": "stale"})
	if got["OIDC_CLIENT_ID"] != "" {
		t.Errorf("stale web OIDC value used: %v", got)
	}
}

func TestParseSettingsKey(t *testing.T) {
	for _, ok := range []string{
		"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY",
		"3031323334353637383961626364656630313233343536373839616263646566",
	} {
		if k, err := ParseSettingsKey(ok); err != nil || len(k) != 32 {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "short", "MDEyMzQ1Njc4OWFiY2RlZg=="} {
		if _, err := ParseSettingsKey(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
