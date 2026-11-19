package secure

import (
	"strings"
	"testing"
)

func TestTokens(t *testing.T) {
	a, b := NewToken(), NewToken()
	if a == b || !ValidToken(a) || ValidToken(a[:42]) || ValidToken(a+"=") {
		t.Fatal("token generation/validation wrong")
	}
	if id1, id2 := NewID(), NewID(); len(id1) != 32 || id1 == id2 {
		t.Fatal("IDs must be 32 hex chars and unique")
	}
	ap := NewAppPassword()
	if !ValidAppPassword(ap) || ValidAppPassword(strings.TrimPrefix(ap, AppPasswordPrefix)) {
		t.Fatal("app password validation wrong")
	}
}

func TestHashTokenIsDomainSeparated(t *testing.T) {
	tok := NewToken()
	if HashToken(PurposeSession, tok) == HashToken(PurposeAppPassword, tok) {
		t.Fatal("hashes for different purposes must differ")
	}
}

func TestPasswords(t *testing.T) {
	h := HashPassword("correct horse battery staple")
	if !strings.HasPrefix(h, "$argon2id$v=19$") {
		t.Fatalf("unexpected hash format %q", h)
	}
	if !VerifyPassword("correct horse battery staple", h) || VerifyPassword("wrong", h) {
		t.Fatal("verification wrong")
	}
	if h1, h2 := HashPassword("x"), HashPassword("x"); h1 == h2 {
		t.Fatal("hashes must be salted")
	}
	// Tampered parameters are rejected rather than honoured (DoS guard).
	huge := strings.Replace(h, "m=19456", "m=99999999", 1)
	if VerifyPassword("correct horse battery staple", huge) {
		t.Fatal("unbounded memory parameter accepted")
	}
	for _, bad := range []string{"", "$argon2i$v=19$m=1,t=1,p=1$a$b", "plaintext"} {
		if VerifyPassword("x", bad) {
			t.Errorf("accepted malformed hash %q", bad)
		}
	}
}
