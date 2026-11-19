package auth

import "testing"

func TestSafeReturnTo(t *testing.T) {
	cases := map[string]string{
		"":                       "/",
		"/files/abc":             "/files/abc",
		"/s?x=1":                 "/s?x=1",
		"//evil.example":         "/",
		"/\\evil.example":        "/",
		"https://evil.example/":  "/",
		"javascript:alert(1)":    "/",
		"/ok\r\nSet-Cookie: x=y": "/",
		"relative/path":          "/",
	}
	for in, want := range cases {
		if got := SafeReturnTo(in); got != want {
			t.Errorf("SafeReturnTo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBearerOrBasic(t *testing.T) {
	if tok, ok := bearerOrBasic("Bearer abc"); !ok || tok != "abc" {
		t.Fatal("bearer")
	}
	if tok, ok := bearerOrBasic("Basic dXNlcjpzZWNyZXQ="); !ok || tok != "secret" {
		t.Fatal("basic")
	}
	for _, bad := range []string{"Bearer", "Digest abc", "Basic !!!", "Basic dXNlcg=="} {
		if _, ok := bearerOrBasic(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}
