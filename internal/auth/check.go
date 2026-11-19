package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

// Live checks run before sign-in settings are saved from the web, so a typo
// in an issuer or a metadata URL is caught while the administrator is still
// signed in, not discovered when nobody can sign in any more.
//
// Every message they return is safe to show: it describes what was wrong,
// never what the remote server sent (see idpclient.go).

// CheckOIDC verifies that cfg's issuer is a working OpenID provider: its
// discovery document is valid, names exactly this issuer, and points to a
// key set with at least one key.
func CheckOIDC(ctx context.Context, cfg OIDCConfig) error {
	c := NewIdPClient(cfg.AllowLoopback)
	b, err := idpGet(ctx, c, strings.TrimSuffix(cfg.Issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		return fmt.Errorf("could not read the discovery document: %w", err)
	}
	var d struct {
		Issuer        string `json:"issuer"`
		Authorization string `json:"authorization_endpoint"`
		Token         string `json:"token_endpoint"`
		JWKS          string `json:"jwks_uri"`
	}
	if json.Unmarshal(b, &d) != nil {
		return errors.New("the discovery document is not valid JSON")
	}
	if d.Issuer != cfg.Issuer {
		return errors.New("the discovery document names a different issuer (check for a missing or extra trailing slash)")
	}
	for _, e := range []string{d.Authorization, d.Token, d.JWKS} {
		if !endpointOK(e, cfg.AllowLoopback) {
			return errors.New("the discovery document lacks an https authorization, token or key endpoint")
		}
	}
	kb, err := idpGet(ctx, c, d.JWKS)
	if err != nil {
		return fmt.Errorf("could not read the signing keys: %w", err)
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if json.Unmarshal(kb, &set) != nil || len(set.Keys) == 0 {
		return errors.New("the provider publishes no signing keys")
	}
	return nil
}

func endpointOK(raw string, allowLoopback bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Scheme == "https" || allowLoopback && u.Scheme == "http"
}

// CheckSAML verifies cfg's IdP metadata (fetching it if it is given by
// URL) and returns the IdP's entity ID.
func CheckSAML(ctx context.Context, cfg SAMLConfig) (string, error) {
	md := cfg.IDPMetadata
	if len(md) == 0 {
		b, err := idpGet(ctx, NewIdPClient(cfg.AllowLoopback), cfg.IDPMetadataURL)
		if err != nil {
			return "", fmt.Errorf("could not read the metadata: %w", err)
		}
		md = b
	}
	id, err := ParseSAMLMetadata(md)
	if errors.Is(err, errNotMetadata) && len(cfg.IDPMetadata) == 0 {
		return "", errors.New("the document at that URL is not SAML metadata")
	}
	return id, err
}

var errNotMetadata = errors.New("not SAML metadata")

// ParseSAMLMetadata parses an IdP metadata document and returns the IdP's
// entity ID. The document must describe an identity provider with an
// HTTP-Redirect single sign-on endpoint and a signing certificate: without
// one, no assertion could ever be verified.
func ParseSAMLMetadata(b []byte) (string, error) {
	md, err := samlsp.ParseMetadata(b)
	if err != nil {
		return "", fmt.Errorf("%w (%v)", errNotMetadata, err)
	}
	return checkIdPMetadata(md)
}

func checkIdPMetadata(md *saml.EntityDescriptor) (string, error) {
	if md.EntityID == "" {
		return "", errors.New("the metadata has no entityID")
	}
	if len(md.IDPSSODescriptors) == 0 {
		return "", errors.New("the metadata does not describe an identity provider")
	}
	redirect, signing := false, false
	for _, d := range md.IDPSSODescriptors {
		for _, e := range d.SingleSignOnServices {
			redirect = redirect || e.Binding == saml.HTTPRedirectBinding && e.Location != ""
		}
		for _, k := range d.KeyDescriptors {
			if k.Use == "" || k.Use == "signing" {
				for _, c := range k.KeyInfo.X509Data.X509Certificates {
					signing = signing || strings.TrimSpace(c.Data) != ""
				}
			}
		}
	}
	if !redirect {
		return "", errors.New("the identity provider has no HTTP-Redirect sign-on endpoint")
	}
	if !signing {
		return "", errors.New("the identity provider publishes no signing certificate")
	}
	return md.EntityID, nil
}
