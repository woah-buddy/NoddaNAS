package config

import "testing"

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"0": 0, "1024": 1024, "10GiB": 10 << 30, "5 MiB": 5 << 20, "2TiB": 2 << 40} {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("ParseSize(%q) = %d, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "-1", "10GB", "lots", "99999999999TiB"} {
		if _, err := ParseSize(bad); err == nil {
			t.Errorf("ParseSize(%q) accepted", bad)
		}
	}
}

func TestLoadRejectsInsecurePublicURL(t *testing.T) {
	base := map[string]string{
		"NODDANAS_DATABASE_URL": "postgres://x", "NODDANAS_OIDC_ISSUER": "https://idp", "NODDANAS_OIDC_CLIENT_ID": "c",
	}
	for url, ok := range map[string]bool{
		"https://files.example.com": true, "http://localhost:8080": true, "http://files.example.com": false,
		"https://files.example.com/sub": false, "files.example.com": false,
	} {
		for k, v := range base {
			t.Setenv(k, v)
		}
		t.Setenv("NODDANAS_PUBLIC_URL", url)
		_, err := Load()
		if (err == nil) != ok {
			t.Errorf("PUBLIC_URL %q: err = %v, want ok=%v", url, err, ok)
		}
	}
}

func TestLoadRequiresASignInMethod(t *testing.T) {
	t.Setenv("NODDANAS_DATABASE_URL", "postgres://x")
	t.Setenv("NODDANAS_PUBLIC_URL", "https://files.example.com")
	if _, err := Load(); err == nil {
		t.Fatal("started with no sign-in method configured")
	}
	t.Setenv("NODDANAS_SAML_IDP_METADATA_URL", "http://idp.example.com/metadata")
	if _, err := Load(); err == nil {
		t.Fatal("accepted SAML metadata over plain http")
	}
	t.Setenv("NODDANAS_SAML_IDP_METADATA_URL", "https://idp.example.com/metadata")
	c, err := Load()
	if err != nil || c.SAML == nil || c.OIDC != nil || c.SAML.ACSURL != "https://files.example.com/auth/saml/acs" {
		t.Fatalf("SAML-only config: %+v %v", c, err)
	}
}
