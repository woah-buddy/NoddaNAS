package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

// Sealer encrypts small server-side secrets (for example TOTP secrets) with
// AES-256-GCM under a key derived from the server's settings key, bound to
// a purpose and to associated data (such as the account they belong to). A
// database dump alone does not give them away.
type Sealer struct {
	aead   cipher.AEAD
	prefix string
}

// NewSealer derives a sealer for one purpose from a 32-byte key.
func NewSealer(key []byte, purpose string) (*Sealer, error) {
	if len(key) != 32 {
		return nil, errors.New("sealer key must be 32 bytes")
	}
	k, err := hkdf.Key(sha256.New, key, nil, purpose, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead, prefix: "sealed:v1:"}, nil
}

// Seal encrypts pt, bound to aad.
func (s *Sealer) Seal(aad string, pt []byte) string {
	nonce := make([]byte, s.aead.NonceSize())
	_, _ = rand.Read(nonce) // never fails (crypto/rand panics on failure since Go 1.24)
	return s.prefix + base64.RawURLEncoding.EncodeToString(s.aead.Seal(nonce, nonce, pt, []byte(aad)))
}

// Open decrypts what Seal produced with the same aad.
func (s *Sealer) Open(aad, sealed string) ([]byte, error) {
	rest, ok := strings.CutPrefix(sealed, s.prefix)
	raw, err := base64.RawURLEncoding.DecodeString(rest)
	n := s.aead.NonceSize()
	if !ok || err != nil || len(raw) < n+s.aead.Overhead() {
		return nil, errors.New("sealed value is malformed")
	}
	pt, err := s.aead.Open(nil, raw[:n], raw[n:], []byte(aad))
	if err != nil {
		return nil, errors.New("sealed value does not decrypt with this key")
	}
	return pt, nil
}
