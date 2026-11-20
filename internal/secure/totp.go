package secure

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 6238 TOTP with HMAC-SHA1 is what authenticator apps implement; HMAC-SHA1 is not affected by SHA-1 collisions
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP (RFC 6238): six-digit codes from a shared secret and the time, as
// every authenticator app computes them (HMAC-SHA1, 30-second steps).

const (
	totpPeriod = 30
	totpDigits = 6
	totpSkew   = 1 // steps accepted either side of now, for clock drift
)

// NewTOTPSecret returns a fresh 160-bit secret.
func NewTOTPSecret() []byte {
	b := make([]byte, 20)
	mustRead(b)
	return b
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// TOTPSecretText is the secret as authenticator apps accept it typed in.
func TOTPSecretText(secret []byte) string { return b32.EncodeToString(secret) }

// TOTPURI is the otpauth:// URI that QR codes for authenticator apps carry.
func TOTPURI(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{"secret": {TOTPSecretText(secret)}, "issuer": {issuer}, "algorithm": {"SHA1"},
		"digits": {fmt.Sprint(totpDigits)}, "period": {fmt.Sprint(totpPeriod)}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// TOTPStep is the time step a moment falls in.
func TOTPStep(t time.Time) int64 { return t.Unix() / totpPeriod }

// TOTPCode computes the code for one time step.
func TOTPCode(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) // #nosec G115 -- steps are positive (time since 1970)
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000)
}

// VerifyTOTP checks a code typed by the person (spaces ignored) for the
// steps around now. A step at or before lastStep is refused, so a code
// works only once even within its window. It returns the matching step.
func VerifyTOTP(secret []byte, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return 0, false
	}
	cur := TOTPStep(now)
	found := int64(0)
	for s := cur - totpSkew; s <= cur+totpSkew; s++ {
		// Check every candidate (no early exit), so timing says nothing.
		if subtle.ConstantTimeCompare([]byte(TOTPCode(secret, s)), []byte(code)) == 1 && s > lastStep && found == 0 {
			found = s
		}
	}
	return found, found != 0
}

// Recovery codes: single-use, 80 bits each, shown once, stored hashed.

// NewRecoveryCode returns a code like "ABCD-EFGH-JKLM-NPQR" (16 characters
// from an unambiguous alphabet).
func NewRecoveryCode() string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // 32 symbols: 5 bits each
	b := make([]byte, 16)
	mustRead(b)
	var out strings.Builder
	for i, x := range b {
		if i > 0 && i%4 == 0 {
			out.WriteByte('-')
		}
		out.WriteByte(alphabet[x&31])
	}
	return out.String()
}

// NormalizeRecoveryCode strips separators and case, so codes can be typed
// loosely.
func NormalizeRecoveryCode(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '-' || r == ' ':
			return -1
		case r >= 'a' && r <= 'z':
			return r - 'a' + 'A'
		}
		return r
	}, s)
}
