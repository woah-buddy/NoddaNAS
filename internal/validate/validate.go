// Package validate is the single place where untrusted strings become trusted
// values. Every name, ID, hash and email that crosses the API boundary passes
// through here before it reaches business logic or storage.
package validate

import (
	"mime"
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"github.com/woah-buddy/NoddaNAS/internal/domain"
)

// MaxNameBytes matches common filesystem limits so names round-trip through
// sync clients.
const MaxNameBytes = 255

// Name validates and normalizes a file or folder name. It returns the
// NFC-normalized name to store and display.
//
// Names never become storage paths (blob keys are random IDs), so these rules
// are about integrity and anti-spoofing rather than path traversal:
//   - no separators or NUL, so a name is always exactly one path segment;
//   - no control characters, which corrupt logs and terminals;
//   - no bidirectional overrides, which let "evil‮fdp.exe" render as "evilexe.pdf";
//   - no "." / ".." and no leading/trailing whitespace, which confuse clients.
func Name(raw string) (string, error) {
	if !utf8.ValidString(raw) {
		return "", domain.E(domain.CodeInvalid, "name must be valid UTF-8")
	}
	name := norm.NFC.String(raw)
	if name == "" {
		return "", domain.E(domain.CodeInvalid, "name must not be empty")
	}
	if len(name) > MaxNameBytes {
		return "", domain.E(domain.CodeInvalid, "name must be at most %d bytes", MaxNameBytes)
	}
	if strings.Trim(name, ".") == "" {
		return "", domain.E(domain.CodeInvalid, "name must not consist only of dots")
	}
	if strings.TrimSpace(name) != name {
		return "", domain.E(domain.CodeInvalid, "name must not start or end with whitespace")
	}
	for _, r := range name {
		switch {
		case r == '/' || r == '\\':
			return "", domain.E(domain.CodeInvalid, "name must not contain / or \\")
		case r == 0 || unicode.IsControl(r):
			return "", domain.E(domain.CodeInvalid, "name must not contain control characters")
		case isBidiControl(r):
			return "", domain.E(domain.CodeInvalid, "name must not contain bidirectional control characters")
		case r == utf8.RuneError:
			return "", domain.E(domain.CodeInvalid, "name must be valid UTF-8")
		}
	}
	return name, nil
}

// NameKey is the uniqueness key for a name within a folder. Uniqueness is
// case-insensitive so "Report.pdf" and "report.pdf" cannot coexist; they
// would collide on Windows/macOS sync clients and are a spoofing aid.
func NameKey(name string) string {
	return norm.NFC.String(cases.Fold().String(name))
}

func isBidiControl(r rune) bool {
	switch {
	case r >= 0x202A && r <= 0x202E: // LRE, RLE, PDF, LRO, RLO
		return true
	case r >= 0x2066 && r <= 0x2069: // LRI, RLI, FSI, PDI
		return true
	case r == 0x200E || r == 0x200F || r == 0x061C: // LRM, RLM, ALM
		return true
	}
	return false
}

// ID checks the format of a server-generated identifier (32 lowercase hex).
// Rejecting anything else up front means attacker-controlled strings never
// reach key construction.
func ID(s string) error {
	if !isLowerHex(s, 32) {
		return domain.E(domain.CodeInvalid, "malformed id")
	}
	return nil
}

// SHA256Hex checks for a lowercase hex SHA-256 digest.
func SHA256Hex(s string) error {
	if !isLowerHex(s, 64) {
		return domain.E(domain.CodeInvalid, "sha256 must be 64 lowercase hex characters")
	}
	return nil
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ContentType reduces a client-declared media type to a bare "type/subtype".
// Parameters are dropped and anything unparseable becomes octet-stream. The
// value is metadata only: downloads are served as attachments regardless.
func ContentType(s string) string {
	const fallback = "application/octet-stream"
	if s == "" || len(s) > 255 {
		return fallback
	}
	mt, _, err := mime.ParseMediaType(s)
	if err != nil || len(mt) > 127 || !strings.Contains(mt, "/") {
		return fallback
	}
	return mt
}

// Email normalizes an email address for lookup. Only the bare address is
// kept, lowercased.
func Email(s string) (string, error) {
	if len(s) > 254 {
		return "", domain.E(domain.CodeInvalid, "invalid email")
	}
	addr, err := mail.ParseAddress(s)
	if err != nil || addr.Address != strings.TrimSpace(s) {
		return "", domain.E(domain.CodeInvalid, "invalid email")
	}
	return strings.ToLower(addr.Address), nil
}
