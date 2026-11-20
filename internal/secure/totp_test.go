package secure

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 Appendix B (SHA-1), last six digits.
func TestTOTPVectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, c := range []struct {
		unix int64
		code string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"}} {
		if got := TOTPCode(secret, TOTPStep(time.Unix(c.unix, 0))); got != c.code {
			t.Errorf("t=%d: %s, want %s", c.unix, got, c.code)
		}
	}
}

func TestVerifyTOTP(t *testing.T) {
	secret := NewTOTPSecret()
	now := time.Unix(1_800_000_000, 0)
	cur := TOTPStep(now)
	for _, d := range []int64{-1, 0, 1} {
		if s, ok := VerifyTOTP(secret, TOTPCode(secret, cur+d), now, 0); !ok || s != cur+d {
			t.Errorf("drift %d refused", d)
		}
	}
	for _, d := range []int64{-3, -2, 2, 3} {
		if _, ok := VerifyTOTP(secret, TOTPCode(secret, cur+d), now, 0); ok {
			t.Errorf("drift %d accepted", d)
		}
	}
	// A code works once: a step at or before the last used one is refused.
	if _, ok := VerifyTOTP(secret, TOTPCode(secret, cur), now, cur); ok {
		t.Error("replayed code accepted")
	}
	if _, ok := VerifyTOTP(secret, " "+TOTPCode(secret, cur)[:3]+" "+TOTPCode(secret, cur)[3:], now, 0); !ok {
		t.Error("spaces should be ignored")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if _, ok := VerifyTOTP(secret, bad, now, 0); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	uri := TOTPURI("FrontDir", "alice@example.com", secret)
	if !strings.HasPrefix(uri, "otpauth://totp/FrontDir:alice@example.com?") || !strings.Contains(uri, "secret="+TOTPSecretText(secret)) {
		t.Errorf("uri %s", uri)
	}
}

func TestRecoveryCodes(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		c := NewRecoveryCode()
		if len(c) != 19 || strings.ContainsAny(c, "01IO") || seen[c] {
			t.Fatalf("code %q", c)
		}
		seen[c] = true
		if NormalizeRecoveryCode(strings.ToLower(strings.ReplaceAll(c, "-", " "))) != strings.ReplaceAll(c, "-", "") {
			t.Fatal("normalization")
		}
	}
}
