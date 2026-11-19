package e2ee

import (
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/text/unicode/norm"
)

// NodeKey is a file's or folder's key with its derived subkeys
// (docs/E2EE.md §4).
type NodeKey struct {
	raw  []byte
	wrap []byte
	name []byte
	hash []byte
}

// NewNodeKey returns a fresh random node key.
func NewNodeKey() *NodeKey {
	k, _ := nodeKeyFrom(random(32))
	return k
}

func nodeKeyFrom(raw []byte) (*NodeKey, error) {
	if len(raw) != 32 {
		return nil, ErrAuth
	}
	return &NodeKey{raw: raw, wrap: kdf(raw, nil, "node/wrap"), name: kdf(raw, nil, "node/name"), hash: kdf(raw, nil, "node/hash")}, nil
}

// Raw exposes the key bytes (for sealing into shares, links and trash).
func (k *NodeKey) Raw() []byte { return k.raw }

// NodeKeyFromRaw rebuilds a node key from its bytes.
func NodeKeyFromRaw(raw []byte) (*NodeKey, error) { return nodeKeyFrom(raw) }

// WrapChild wraps a child's key under this (parent) key.
func (k *NodeKey) WrapChild(childID string, child *NodeKey) string {
	return B64(gcmSeal(k.wrap, child.raw, join("node-key", childID)))
}

// UnwrapChild recovers a child's key.
func (k *NodeKey) UnwrapChild(childID, wrapped string) (*NodeKey, error) {
	raw, err := openB64(k.wrap, wrapped, join("node-key", childID))
	if err != nil {
		return nil, err
	}
	return nodeKeyFrom(raw)
}

// EncryptName encrypts a child's name under this (parent) key.
func (k *NodeKey) EncryptName(childID, name string) string {
	return B64(gcmSeal(k.name, pad32([]byte(nfc(name))), join("node-name", childID)))
}

// DecryptName decrypts a child's name.
func (k *NodeKey) DecryptName(childID, enc string) (string, error) {
	pt, err := openB64(k.name, enc, join("node-name", childID))
	if err != nil {
		return "", err
	}
	return string(unpad(pt)), nil
}

// NameHash is the keyed, case-insensitive uniqueness key for a child name.
func (k *NodeKey) NameHash(name string) string {
	return hex.EncodeToString(hmacSHA256(k.hash, []byte(lowerName(name))))
}

func nfc(s string) string { return norm.NFC.String(s) }

// lowerName matches JavaScript's name.normalize("NFC").toLowerCase().
func lowerName(s string) string { return cases.Lower(language.Und).String(nfc(s)) }

// ValidateName applies the same rules as the server once did for plaintext
// names; clients enforce them now that the server cannot see names.
func ValidateName(name string) error {
	n := nfc(name)
	switch {
	case n == "" || len(n) > 255:
		return errors.New("name must be 1-255 bytes")
	case strings.Trim(n, ".") == "":
		return errors.New("name must not consist only of dots")
	case strings.TrimSpace(n) != n:
		return errors.New("name must not start or end with whitespace")
	case strings.ContainsAny(n, "/\\\x00"):
		return errors.New(`name must not contain "/", "\" or NUL`)
	}
	for _, r := range n {
		if r < 0x20 || r == 0x7f || r >= 0x80 && r < 0xa0 || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069 {
			return errors.New("name must not contain control or bidirectional-override characters")
		}
	}
	return nil
}
