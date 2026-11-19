package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestIdPClientRefusesInternalAddresses(t *testing.T) {
	for addr, ok := range map[string]bool{
		"169.254.169.254": false, "fe80::1": false, "100.100.100.200": false, "fd00:ec2::254": false,
		"0.0.0.0": false, "::": false, "224.0.0.1": false, "255.255.255.255": false,
		"::ffff:169.254.169.254": false, "127.0.0.1": false, "::1": false,
		"10.0.0.5": true, "172.30.0.7": true, "192.168.1.10": true, "203.0.113.9": true, "2001:db8::1": true,
	} {
		if got := addrAllowed(netip.MustParseAddr(addr), false); got != ok {
			t.Errorf("%s: allowed=%v, want %v", addr, got, ok)
		}
	}
	if !addrAllowed(netip.MustParseAddr("127.0.0.1"), true) || addrAllowed(netip.MustParseAddr("169.254.169.254"), true) {
		t.Error("loopback allowance is wrong")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("hi")) }))
	defer srv.Close()
	if _, err := NewIdPClient(false).Get(srv.URL); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("loopback reached on a public deployment: %v", err)
	}
	if _, err := NewIdPClient(false).Get("http://169.254.169.254/latest/meta-data/"); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("metadata address: %v", err)
	}
	resp, err := NewIdPClient(true).Get(srv.URL)
	if err != nil {
		t.Fatalf("loopback on a localhost deployment: %v", err)
	}
	resp.Body.Close()
}

func TestIdPChecksNeverEchoTheRemote(t *testing.T) {
	const secret = "INTERNAL-ONLY-CONTENT"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/err/.well-known/openid-configuration":
			http.Error(w, secret, http.StatusInternalServerError)
		case "/big/.well-known/openid-configuration":
			_, _ = w.Write([]byte(strings.Repeat(secret, MaxIdPResponse/len(secret)+10)))
		default:
			_, _ = w.Write([]byte("<html>" + secret + "</html>"))
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	for path, want := range map[string]string{"/err": "HTTP 500", "/big": "larger than 1 MiB", "/html": "not valid JSON"} {
		err := CheckOIDC(ctx, OIDCConfig{Issuer: srv.URL + path, AllowLoopback: true})
		if err == nil || strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", path, err)
		}
	}
	_, err := CheckSAML(ctx, SAMLConfig{IDPMetadataURL: srv.URL + "/md", AllowLoopback: true})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Errorf("saml: %v", err)
	}
}
