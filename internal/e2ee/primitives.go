// Package e2ee implements FrontDir's end-to-end encryption as specified in
// docs/E2EE.md. It is client-side code: the browser implements the same
// spec in JavaScript, and this package serves the CLI client and the test
// suite. The server only ever uses ParsePrefix, to check a container's shape.
//
// Everything here is built from Go standard-library primitives: X25519
// (crypto/ecdh), Ed25519, HKDF and PBKDF2 (SHA-256), HMAC and AES-256-GCM.
package e2ee

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

// Label prefix for every KDF info string, AAD and signature context. It
// keeps the project's former name on purpose: it is part of format v1, and
// changing it would make every existing file unreadable (docs/E2EE.md).
const L = "noddanas/e2ee/v1/"

// ErrAuth means a ciphertext, wrapped key or signature failed verification.
var ErrAuth = errors.New("e2ee: authentication failed")

// B64 encodes base64url without padding.
func B64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// UnB64 decodes base64url without padding.
func UnB64(s string) ([]byte, error) { return base64.RawURLEncoding.Strict().DecodeString(s) }

// join builds a label: L+name, then each part preceded by a NUL separator.
func join(name string, parts ...string) []byte {
	var b bytes.Buffer
	b.WriteString(L + name)
	for _, p := range parts {
		b.WriteByte(0)
		b.WriteString(p)
	}
	return b.Bytes()
}

func kdf(ikm, salt []byte, info string) []byte {
	k, err := hkdf.Key(sha256.New, ikm, salt, L+info, 32)
	if err != nil {
		panic(err) // only fails for invalid lengths, which are constants here
	}
	return k
}

func random(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func gcmFor(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return g
}

// gcmSeal encrypts with a random nonce: nonce || ciphertext || tag.
func gcmSeal(key, pt, aad []byte) []byte {
	g := gcmFor(key)
	nonce := random(g.NonceSize())
	return g.Seal(nonce, nonce, pt, aad)
}

func gcmOpen(key, ct, aad []byte) ([]byte, error) {
	g := gcmFor(key)
	if len(ct) < g.NonceSize()+g.Overhead() {
		return nil, ErrAuth
	}
	pt, err := g.Open(nil, ct[:g.NonceSize()], ct[g.NonceSize():], aad)
	if err != nil {
		return nil, ErrAuth
	}
	return pt, nil
}

// Seal encrypts pt to an X25519 public key (docs/E2EE.md §2).
func Seal(recipient *ecdh.PublicKey, pt, ctx []byte) ([]byte, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ss, err := eph.ECDH(recipient)
	if err != nil {
		return nil, err
	}
	salt := append(append([]byte{}, eph.PublicKey().Bytes()...), recipient.Bytes()...)
	k := kdf(ss, salt, "seal")
	return append(eph.PublicKey().Bytes(), gcmSeal(k, pt, ctx)...), nil
}

// Open decrypts a sealed message with the recipient's private key.
func Open(priv *ecdh.PrivateKey, sealed, ctx []byte) ([]byte, error) {
	if len(sealed) < 32 {
		return nil, ErrAuth
	}
	ephPub, err := ecdh.X25519().NewPublicKey(sealed[:32])
	if err != nil {
		return nil, ErrAuth
	}
	ss, err := priv.ECDH(ephPub)
	if err != nil {
		return nil, ErrAuth
	}
	salt := append(append([]byte{}, sealed[:32]...), priv.PublicKey().Bytes()...)
	return gcmOpen(kdf(ss, salt, "seal"), sealed[32:], ctx)
}

func sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// sign/verify over a label followed by message parts (the same bytes the
// browser builds).
func sign(priv ed25519.PrivateKey, msg []byte) []byte { return ed25519.Sign(priv, msg) }

func verify(pub ed25519.PublicKey, msg, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, msg, sig) {
		return ErrAuth
	}
	return nil
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// pad32 pads to a multiple of 32 bytes (minimum 32) with zero bytes, so
// ciphertext length reveals only an approximate name length.
func pad32(b []byte) []byte {
	n := (len(b) + 31) / 32 * 32
	if n == 0 {
		n = 32
	}
	out := make([]byte, n)
	copy(out, b)
	return out
}

func unpad(b []byte) []byte { return bytes.TrimRight(b, "\x00") }

// Fingerprint identifies a user's key pair for out-of-band verification.
func Fingerprint(encPub, sigPub []byte) string {
	msg := append(join("fingerprint"), 0)
	msg = append(append(msg, encPub...), sigPub...)
	return hex.EncodeToString(sum(msg))[:40]
}
