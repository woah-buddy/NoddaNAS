package auth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// Outbound requests to identity providers.
//
// Since identity-provider URLs can be entered in the web admin area, the
// server's requests to them are a server-side request forgery (SSRF) risk:
// whoever can edit the URL can make the server send GET requests to
// addresses the browser cannot reach. The client below narrows that:
//
//   - It never connects to link-local addresses (169.254.0.0/16, fe80::/10,
//     where cloud metadata services live), well-known metadata addresses,
//     unspecified, multicast or broadcast addresses, and connects to
//     loopback only on a localhost deployment. Addresses are checked both
//     before sending and again at connect time, on the address actually
//     dialled, so DNS rebinding cannot slip past the first check.
//   - Private network addresses stay allowed: a self-hosted IdP on the same
//     Docker network is the normal case.
//   - Responses are capped at 1 MiB, the whole exchange at 20 seconds, and
//     redirects at three, never from https down to http.
//   - Callers never echo response bodies back to the person who entered the
//     URL (see CheckOIDCIssuer), so the server cannot be used to read
//     internal pages.

// MaxIdPResponse bounds any response from an identity provider.
const MaxIdPResponse = 1 << 20

var errResponseTooLarge = errors.New("response larger than 1 MiB")

// blockedAddrs are addresses no identity provider lives at.
var blockedAddrs = []netip.Prefix{
	netip.MustParsePrefix("100.100.100.200/32"), // Alibaba Cloud metadata
	netip.MustParsePrefix("fd00:ec2::254/128"),  // AWS IMDS over IPv6
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("0.0.0.0/8"),
}

// ErrBlockedAddress is returned for connections the client refuses to make.
var ErrBlockedAddress = errors.New("address not allowed for an identity provider")

func addrAllowed(a netip.Addr, allowLoopback bool) bool {
	a = a.Unmap()
	switch {
	case !a.IsValid(), a.IsUnspecified(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(),
		a.IsInterfaceLocalMulticast(), a.IsMulticast():
		return false
	case a.IsLoopback():
		return allowLoopback
	}
	for _, p := range blockedAddrs {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// NewIdPClient returns the HTTP client used for every request to an
// identity provider (OIDC discovery, keys and token exchange; SAML
// metadata). allowLoopback is for localhost deployments (development and
// tests) only.
func NewIdPClient(allowLoopback bool) *http.Client {
	// A configured HTTP proxy is dialled as itself (the operator chose it);
	// the destination is still checked before the request is sent.
	proxies := map[string]bool{}
	for _, scheme := range []string{"http", "https"} {
		if u, err := http.ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: scheme, Host: "idp.invalid"}}); err == nil && u != nil {
			proxies[canonicalHostPort(u)] = true
		}
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if proxies[addr] {
			return dialer.DialContext(ctx, network, addr)
		}
		d := *dialer
		d.Control = func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || !addrAllowed(ap.Addr(), allowLoopback) {
				return ErrBlockedAddress
			}
			return nil
		}
		return d.DialContext(ctx, network, addr)
	}
	tr := &http.Transport{
		Proxy:                  http.ProxyFromEnvironment,
		DialContext:            dial,
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  15 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		IdleConnTimeout:        90 * time.Second,
		MaxIdleConns:           10,
	}
	return &http.Client{
		Timeout:   20 * time.Second,
		Transport: &idpTransport{rt: tr, allowLoopback: allowLoopback},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
				return errors.New("redirect from https to plain http refused")
			}
			return nil
		},
	}
}

func canonicalHostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443", "socks5": "1080"}[u.Scheme]
	}
	return net.JoinHostPort(u.Hostname(), port)
}

type idpTransport struct {
	rt            http.RoundTripper
	allowLoopback bool
}

func (t *idpTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" && req.URL.Scheme != "http" {
		return nil, ErrBlockedAddress
	}
	// Check every address the name resolves to before sending, so a
	// request through a proxy is held to the same rule as a direct one.
	host := req.URL.Hostname()
	addrs, err := lookup(req.Context(), host)
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if !addrAllowed(a, t.allowLoopback) {
			return nil, ErrBlockedAddress
		}
	}
	resp, err := t.rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &limitedBody{rc: resp.Body, n: MaxIdPResponse}
	return resp, nil
}

func lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return []netip.Addr{a}, nil
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

type limitedBody struct {
	rc io.ReadCloser
	n  int64
}

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.n <= 0 {
		var one [1]byte
		if n, _ := b.rc.Read(one[:]); n > 0 {
			return 0, errResponseTooLarge
		}
		return 0, io.EOF
	}
	if int64(len(p)) > b.n {
		p = p[:b.n]
	}
	n, err := b.rc.Read(p)
	b.n -= int64(n)
	return n, err
}

func (b *limitedBody) Close() error { return b.rc.Close() }

// DescribeFetchError turns a failed request to an identity provider into a
// short message that is safe to show: it names the kind of failure, never
// anything the remote side sent.
func DescribeFetchError(err error) string {
	var dnsErr *net.DNSError
	var opErr *net.OpError
	switch {
	case errors.Is(err, ErrBlockedAddress):
		return "the address is not allowed (link-local, metadata, loopback or similar)"
	case errors.Is(err, errResponseTooLarge):
		return "the response is larger than 1 MiB"
	case errors.As(err, &dnsErr):
		return "the host name could not be resolved"
	case errors.Is(err, context.DeadlineExceeded) || isTimeout(err):
		return "the request timed out"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "the connection was refused"
	case strings.Contains(err.Error(), "certificate") || strings.Contains(err.Error(), "tls:"):
		return "the TLS connection failed (is the certificate trusted?)"
	case strings.Contains(err.Error(), "redirect"):
		return "it redirected too often, or from https to http"
	case errors.As(err, &opErr):
		return "the connection failed"
	}
	return "the request failed"
}

func isTimeout(err error) bool {
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}

// idpGet fetches url with the IdP client and returns the body of a 200
// response. Errors are safe to show (see DescribeFetchError).
func idpGet(ctx context.Context, c *http.Client, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, errors.New("the URL is not valid")
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, errors.New(DescribeFetchError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("it answered HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.New(DescribeFetchError(err))
	}
	return b, nil
}
