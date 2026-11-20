// Package secure contains FrontDir's small set of cryptographic helpers.
// Everything here uses the Go standard library or golang.org/x/crypto; there
// is no home-grown cryptography.
package secure

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// NewID returns a random 128-bit identifier as 32 lowercase hex characters.
// IDs are unguessable, so knowing one ID never helps predict another.
func NewID() string {
	var b [16]byte
	mustRead(b[:])
	return hex.EncodeToString(b[:])
}

// TokenLen is the encoded length of a link token (32 bytes, base64url, no padding).
const TokenLen = 43

// NewToken returns a 256-bit random bearer token for public links.
func NewToken() string {
	var b [32]byte
	mustRead(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// ValidToken checks a token's shape before any lookup is attempted.
func ValidToken(t string) bool {
	if len(t) != TokenLen {
		return false
	}
	_, err := base64.RawURLEncoding.Strict().DecodeString(t)
	return err == nil
}

// Hash purposes. Domain separation means a hash computed for one purpose can
// never be replayed as a valid hash for another. They keep the project's
// former name on purpose: stored hashes depend on them, so changing them
// would invalidate every session, link and app password.
const (
	PurposeLinkToken   = "noddanas/link-token/v1"
	PurposeSession     = "noddanas/session/v1"
	PurposeAppPassword = "noddanas/app-password/v1" // #nosec G101 -- a domain-separation label, not a credential
	PurposeLogin       = "noddanas/login-request/v1"
	PurposeSetup       = "noddanas/setup-link/v1"
	PurposeMailbox     = "frontdir/mailbox-token/v1"
)

// HashToken returns the hex SHA-256 of a high-entropy bearer secret. Only
// this hash is stored. A fast hash is correct here (unlike for passwords)
// because the secret has 256 bits of entropy: there is nothing to brute-force,
// and a stolen database row cannot be turned back into a working credential.
func HashToken(purpose, token string) string {
	return domainHash(purpose, token)
}

// AppPasswordPrefix makes leaked app passwords recognizable to secret
// scanners (e.g. GitHub push protection) and to humans.
const AppPasswordPrefix = "fd_"

// LegacyAppPasswordPrefix marks app passwords created before the project
// was renamed from NoddaNAS. They keep working unchanged: the stored hash
// covers the whole token, prefix included.
const LegacyAppPasswordPrefix = "ndn_"

// NewAppPassword returns a new app password: prefix + 256-bit token.
func NewAppPassword() string { return AppPasswordPrefix + NewToken() }

// ValidAppPassword checks an app password's shape.
func ValidAppPassword(s string) bool {
	for _, p := range []string{AppPasswordPrefix, LegacyAppPasswordPrefix} {
		if len(s) == len(p)+TokenLen && s[:len(p)] == p && ValidToken(s[len(p):]) {
			return true
		}
	}
	return false
}

func domainHash(domain, msg string) string {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write([]byte(msg))
	return hex.EncodeToString(h.Sum(nil))
}

// Equal compares two strings in constant time.
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Argon2id parameters: OWASP's recommended minimum (19 MiB, 2 passes, 1 lane),
// sized so verification stays fast on a small Lambda while remaining
// memory-hard against GPU cracking.
const (
	argonTime    = 2
	argonMemory  = 19 * 1024 // KiB
	argonThreads = 1
	argonKeyLen  = 32
	argonSaltLen = 16
)

// HashPassword returns an argon2id hash in PHC string format.
func HashPassword(password string) string {
	salt := make([]byte, argonSaltLen)
	mustRead(salt)
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

// VerifyPassword checks a password against a PHC argon2id hash in constant
// time. Parameters are read from the hash but bounded, so a tampered record
// cannot make verification consume unbounded memory or CPU.
func VerifyPassword(password, phc string) bool {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var mem, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &t, &p); err != nil {
		return false
	}
	if mem == 0 || mem > 256*1024 || t == 0 || t > 10 || p == 0 || p > 8 {
		return false
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return false
	}
	want, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(want) < 16 || len(want) > 64 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, mem, p, uint32(len(want))) // #nosec G115 -- len(want) <= 64, checked above
	return subtle.ConstantTimeCompare(got, want) == 1
}

func mustRead(b []byte) {
	// crypto/rand.Read never returns an error on supported platforms (Go 1.24+)
	// and crashes the program rather than return weak randomness.
	_, _ = rand.Read(b)
}
