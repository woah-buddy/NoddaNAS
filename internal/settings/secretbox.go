package settings

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

// Secrets saved from the web admin area (today: the OIDC client secret) are
// encrypted before they reach the database, with AES-256-GCM under a key
// that lives only in the server's environment (FRONTDIR_SETTINGS_KEY_FILE).
//
// Why bother, when the database is trusted? Because database dumps travel:
// to backup storage, to a colleague debugging something, into a ticket. The
// client secret lets whoever holds it act as FrontDir towards the identity
// provider. Encrypted, a dump alone does not give it away; the key has to
// be stolen from the server too.
//
// Each value is bound to its setting name (associated data), so a
// ciphertext copied from one setting to another does not decrypt. The
// labels keep the project's former name on purpose: stored ciphertexts
// depend on them.

const encPrefix = "enc:v1:"

type secretBox struct{ aead cipher.AEAD }

func newSecretBox(key []byte) (*secretBox, error) {
	if len(key) != 32 {
		return nil, errors.New("settings key must be 32 bytes")
	}
	k, err := hkdf.Key(sha256.New, key, nil, "noddanas/settings-secrets/v1", 32)
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
	return &secretBox{aead: aead}, nil
}

func aad(key string) []byte { return []byte("noddanas/settings/v1\x00" + key) }

func (b *secretBox) seal(key, plaintext string) string {
	nonce := make([]byte, b.aead.NonceSize())
	_, _ = rand.Read(nonce) // never fails (crypto/rand panics on failure since Go 1.24)
	out := b.aead.Seal(nonce, nonce, []byte(plaintext), aad(key))
	return encPrefix + base64.RawURLEncoding.EncodeToString(out)
}

var errNotEncrypted = errors.New("stored value is not encrypted")

func (b *secretBox) open(key, stored string) (string, error) {
	rest, ok := strings.CutPrefix(stored, encPrefix)
	if !ok {
		return "", errNotEncrypted
	}
	raw, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil || len(raw) < b.aead.NonceSize()+b.aead.Overhead() {
		return "", errors.New("stored value is malformed")
	}
	n := b.aead.NonceSize()
	pt, err := b.aead.Open(nil, raw[:n], raw[n:], aad(key))
	if err != nil {
		return "", errors.New("stored value does not decrypt with this settings key")
	}
	return string(pt), nil
}
