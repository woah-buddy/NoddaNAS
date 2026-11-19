// Package blobcrypt encrypts file content at rest using envelope encryption.
//
// Every stored blob gets its own random 256-bit data key (DEK). The DEK
// encrypts the content (see stream.go) and is itself encrypted ("wrapped")
// under a key-encryption key (KEK) from the server's keyring. Only the wrapped
// DEK is stored, in the metadata database, never next to the blob.
//
// Consequences worth knowing:
//   - The blob backend (a disk, NFS share or S3 bucket) holds only ciphertext.
//     Stealing it, or a backup of it, reveals nothing without the keyring.
//   - Deleting a version's database row destroys its DEK ("crypto-shredding"),
//     so content becomes unreadable even if a backend snapshot still holds it.
//   - Rotating the KEK only re-wraps small DEKs; blobs are never re-encrypted.
package blobcrypt

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// KeySize is the size of KEKs and DEKs in bytes (AES-256).
const KeySize = 32

const wrapVersion = "v1"

// Keyring holds key-encryption keys. The first key in the file is primary
// and wraps new data keys; the others can only unwrap, which allows rotation:
// add a new key at the top, re-wrap (or wait), then remove the old one.
type Keyring struct {
	primary string
	keys    map[string]cipher.AEAD
}

// ParseKeyring reads a keyring file: one "id:base64-key" per line, with
// blank lines and "#" comments ignored. IDs are 1-32 chars of [a-z0-9-].
func ParseKeyring(data []byte) (*Keyring, error) {
	k := &Keyring{keys: map[string]cipher.AEAD{}}
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		id, b64, ok := strings.Cut(s, ":")
		if !ok || !validKeyID(id) {
			return nil, fmt.Errorf("keyring line %d: expected id:base64key with id of [a-z0-9-]{1,32}", line)
		}
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(raw) != KeySize {
			return nil, fmt.Errorf("keyring line %d: key must be %d bytes of standard base64", line, KeySize)
		}
		if _, dup := k.keys[id]; dup {
			return nil, fmt.Errorf("keyring line %d: duplicate key id %q", line, id)
		}
		aead, err := newGCM(raw)
		if err != nil {
			return nil, err
		}
		k.keys[id] = aead
		if k.primary == "" {
			k.primary = id
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if k.primary == "" {
		return nil, errors.New("keyring contains no keys")
	}
	return k, nil
}

// GenerateKeyLine returns a new keyring line for the given ID.
func GenerateKeyLine(id string) (string, error) {
	if !validKeyID(id) {
		return "", errors.New("key id must be 1-32 chars of [a-z0-9-]")
	}
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return id + ":" + base64.StdEncoding.EncodeToString(key), nil
}

func validKeyID(id string) bool {
	if len(id) == 0 || len(id) > 32 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// NewDataKey returns a fresh DEK and its wrapped form. binding is
// authenticated (not encrypted) into the wrapping: pass the blob key, so a
// wrapped DEK copied onto another database row will fail to unwrap.
func (k *Keyring) NewDataKey(binding string) (dek []byte, wrapped string, err error) {
	dek = make([]byte, KeySize)
	if _, err := rand.Read(dek); err != nil {
		return nil, "", err
	}
	aead := k.keys[k.primary]
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", err
	}
	ct := aead.Seal(nonce, nonce, dek, wrapAAD(k.primary, binding))
	return dek, wrapVersion + "." + k.primary + "." + base64.RawURLEncoding.EncodeToString(ct), nil
}

// Unwrap recovers a DEK. binding must equal the value given to NewDataKey.
func (k *Keyring) Unwrap(wrapped, binding string) ([]byte, error) {
	parts := strings.Split(wrapped, ".")
	if len(parts) != 3 || parts[0] != wrapVersion {
		return nil, errors.New("blobcrypt: malformed wrapped key")
	}
	aead, ok := k.keys[parts[1]]
	if !ok {
		return nil, fmt.Errorf("blobcrypt: unknown key id %q", parts[1])
	}
	ct, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(ct) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("blobcrypt: malformed wrapped key")
	}
	dek, err := aead.Open(nil, ct[:aead.NonceSize()], ct[aead.NonceSize():], wrapAAD(parts[1], binding))
	if err != nil {
		return nil, errors.New("blobcrypt: wrapped key failed authentication")
	}
	return dek, nil
}

// NeedsRewrap reports whether a wrapped key uses a non-primary KEK.
func (k *Keyring) NeedsRewrap(wrapped string) bool {
	parts := strings.Split(wrapped, ".")
	return len(parts) != 3 || parts[1] != k.primary
}

func wrapAAD(keyID, binding string) []byte {
	return []byte("noddanas/dek/" + wrapVersion + "\x00" + keyID + "\x00" + binding)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
