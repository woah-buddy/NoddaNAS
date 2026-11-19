package e2ee

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// PBKDF2Iterations is the passphrase work factor (OWASP 2023 guidance for
// PBKDF2-HMAC-SHA256). PBKDF2 is used because browsers implement it natively.
const PBKDF2Iterations = 600_000

// MinPassphraseLen is the minimum passphrase length in characters.
const MinPassphraseLen = 12

// Bundle is a user's key bundle: public keys in the clear, private keys
// encrypted under MK, and MK wrapped by each unlocker. It is what the
// server stores and what a key backup file contains.
type Bundle struct {
	V       int        `json:"v"`
	UserID  string     `json:"userId"`
	Pub     PublicKeys `json:"pub"`
	SelfSig string     `json:"selfSig"`
	Private string     `json:"private"`
	Unlock  []Unlocker `json:"unlock"`
}

// PublicKeys are a user's published keys (base64url raw keys).
type PublicKeys struct {
	Enc string `json:"enc"`
	Sig string `json:"sig"`
}

// Unlocker wraps MK under a passphrase or a recovery code.
type Unlocker struct {
	Type string `json:"type"` // "passphrase" or "recovery"
	KDF  string `json:"kdf,omitempty"`
	Iter int    `json:"iter,omitempty"`
	Salt string `json:"salt"`
	MK   string `json:"mk"`
}

// Account is an unlocked account: never stored or sent anywhere.
type Account struct {
	UserID string
	MK     []byte
	Enc    *ecdh.PrivateKey
	Sig    ed25519.PrivateKey
}

// Fingerprint returns the account's key fingerprint.
func (a *Account) Fingerprint() string {
	return Fingerprint(a.Enc.PublicKey().Bytes(), a.Sig.Public().(ed25519.PublicKey))
}

// PersonalSpaceSecret derives the secret of the user's personal space.
func (a *Account) PersonalSpaceSecret() []byte { return kdf(a.MK, nil, "space-secret/personal") }

func pubkeysMsg(userID string, enc, sig []byte) []byte {
	m := append(join("pubkeys", userID), 0)
	return append(append(m, enc...), sig...)
}

// NewAccount creates keys for userID, protected by passphrase. It returns
// the unlocked account, the bundle to upload, and the recovery code to show
// the user exactly once.
func NewAccount(userID, passphrase string) (*Account, *Bundle, string, error) {
	if utf8.RuneCountInString(passphrase) < MinPassphraseLen {
		return nil, nil, "", errors.New("e2ee: passphrase must be at least 12 characters")
	}
	enc, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}
	sigPub, sigPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}
	a := &Account{UserID: userID, MK: random(32), Enc: enc, Sig: sigPriv}
	priv, _ := json.Marshal(map[string]string{"enc": B64(enc.Bytes()), "sig": B64(sigPriv.Seed())})
	b := &Bundle{
		V: 1, UserID: userID,
		Pub:     PublicKeys{Enc: B64(enc.PublicKey().Bytes()), Sig: B64(sigPub)},
		SelfSig: B64(sign(sigPriv, pubkeysMsg(userID, enc.PublicKey().Bytes(), sigPub))),
		Private: B64(gcmSeal(kdf(a.MK, nil, "mk/private-keys"), priv, join("private-keys", userID))),
	}
	pass, err := passphraseUnlocker(userID, passphrase, a.MK, PBKDF2Iterations)
	if err != nil {
		return nil, nil, "", err
	}
	code := random(20)
	b.Unlock = []Unlocker{pass, recoveryUnlocker(userID, code, a.MK)}
	return a, b, FormatRecoveryCode(code), nil
}

func passphraseKey(passphrase string, salt []byte, iter int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, norm.NFC.String(passphrase), salt, iter, 32)
}

func passphraseUnlocker(userID, passphrase string, mk []byte, iter int) (Unlocker, error) {
	salt := random(16)
	k, err := passphraseKey(passphrase, salt, iter)
	if err != nil {
		return Unlocker{}, err
	}
	return Unlocker{Type: "passphrase", KDF: "pbkdf2-sha256", Iter: iter, Salt: B64(salt),
		MK: B64(gcmSeal(k, mk, join("unlock/passphrase", userID)))}, nil
}

func recoveryUnlocker(userID string, code, mk []byte) Unlocker {
	salt := random(16)
	return Unlocker{Type: "recovery", Salt: B64(salt),
		MK: B64(gcmSeal(kdf(code, salt, "unlock/recovery"), mk, join("unlock/recovery", userID)))}
}

// ErrWrongSecret means the passphrase or recovery code did not unlock the bundle.
var ErrWrongSecret = errors.New("e2ee: wrong passphrase or recovery code")

// Unlock opens a bundle with a passphrase.
func Unlock(b *Bundle, passphrase string) (*Account, error) {
	for _, u := range b.Unlock {
		if u.Type != "passphrase" || u.KDF != "pbkdf2-sha256" {
			continue
		}
		// Bound the work factor read from (server-supplied) data.
		if u.Iter < 100_000 || u.Iter > 10_000_000 {
			return nil, errors.New("e2ee: unsupported passphrase parameters")
		}
		salt, err := UnB64(u.Salt)
		if err != nil {
			return nil, ErrWrongSecret
		}
		k, err := passphraseKey(passphrase, salt, u.Iter)
		if err != nil {
			return nil, err
		}
		if mk, err := openB64(k, u.MK, join("unlock/passphrase", b.UserID)); err == nil {
			return b.open(mk)
		}
	}
	return nil, ErrWrongSecret
}

// UnlockWithRecoveryCode opens a bundle with the recovery code.
func UnlockWithRecoveryCode(b *Bundle, code string) (*Account, error) {
	raw, err := ParseRecoveryCode(code)
	if err != nil {
		return nil, err
	}
	for _, u := range b.Unlock {
		if u.Type != "recovery" {
			continue
		}
		salt, err := UnB64(u.Salt)
		if err != nil {
			continue
		}
		if mk, err := openB64(kdf(raw, salt, "unlock/recovery"), u.MK, join("unlock/recovery", b.UserID)); err == nil {
			return b.open(mk)
		}
	}
	return nil, ErrWrongSecret
}

func openB64(key []byte, s string, aad []byte) ([]byte, error) {
	ct, err := UnB64(s)
	if err != nil {
		return nil, ErrAuth
	}
	return gcmOpen(key, ct, aad)
}

func (b *Bundle) open(mk []byte) (*Account, error) {
	pt, err := openB64(kdf(mk, nil, "mk/private-keys"), b.Private, join("private-keys", b.UserID))
	if err != nil {
		return nil, err
	}
	var keys struct{ Enc, Sig string }
	if err := json.Unmarshal(pt, &keys); err != nil {
		return nil, ErrAuth
	}
	encRaw, err1 := UnB64(keys.Enc)
	seed, err2 := UnB64(keys.Sig)
	if err1 != nil || err2 != nil || len(seed) != ed25519.SeedSize {
		return nil, ErrAuth
	}
	enc, err := ecdh.X25519().NewPrivateKey(encRaw)
	if err != nil {
		return nil, ErrAuth
	}
	a := &Account{UserID: b.UserID, MK: mk, Enc: enc, Sig: ed25519.NewKeyFromSeed(seed)}
	// The private keys must match the published ones, or the bundle was tampered with.
	if B64(enc.PublicKey().Bytes()) != b.Pub.Enc || B64(a.Sig.Public().(ed25519.PublicKey)) != b.Pub.Sig {
		return nil, ErrAuth
	}
	return a, nil
}

// ChangePassphrase replaces the bundle's passphrase unlocker.
func (a *Account) ChangePassphrase(b *Bundle, passphrase string) error {
	if utf8.RuneCountInString(passphrase) < MinPassphraseLen {
		return errors.New("e2ee: passphrase must be at least 12 characters")
	}
	u, err := passphraseUnlocker(a.UserID, passphrase, a.MK, PBKDF2Iterations)
	if err != nil {
		return err
	}
	out := []Unlocker{u}
	for _, x := range b.Unlock {
		if x.Type != "passphrase" {
			out = append(out, x)
		}
	}
	b.Unlock = out
	return nil
}

// Directory entry for another user, as published by the server.
type PublicUser struct {
	ID     string
	Enc    *ecdh.PublicKey
	Sig    ed25519.PublicKey
	Finger string
}

// VerifyPublicKeys checks a published key set's self-signature and returns
// usable keys. It proves the keys belong together and to userID; whether
// the server served the right keys at all is what fingerprints are for.
func VerifyPublicKeys(userID string, pub PublicKeys, selfSig string) (*PublicUser, error) {
	encRaw, err1 := UnB64(pub.Enc)
	sigRaw, err2 := UnB64(pub.Sig)
	sig, err3 := UnB64(selfSig)
	if err1 != nil || err2 != nil || err3 != nil || len(sigRaw) != ed25519.PublicKeySize {
		return nil, ErrAuth
	}
	if err := verify(sigRaw, pubkeysMsg(userID, encRaw, sigRaw), sig); err != nil {
		return nil, err
	}
	enc, err := ecdh.X25519().NewPublicKey(encRaw)
	if err != nil {
		return nil, ErrAuth
	}
	return &PublicUser{ID: userID, Enc: enc, Sig: sigRaw, Finger: Fingerprint(encRaw, sigRaw)}, nil
}

// Public returns the account's own directory entry.
func (a *Account) Public() *PublicUser {
	sig := a.Sig.Public().(ed25519.PublicKey)
	return &PublicUser{ID: a.UserID, Enc: a.Enc.PublicKey(), Sig: sig, Finger: a.Fingerprint()}
}

// ---- recovery codes ------------------------------------------------------------

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// FormatRecoveryCode renders 20 bytes as 32 Crockford base32 characters in
// groups of four.
func FormatRecoveryCode(b []byte) string {
	var bits uint64
	var n int
	var out strings.Builder
	chars := 0
	for _, c := range b {
		bits = bits<<8 | uint64(c)
		n += 8
		for n >= 5 {
			n -= 5
			if chars > 0 && chars%4 == 0 {
				out.WriteByte('-')
			}
			out.WriteByte(crockford[(bits>>n)&31])
			chars++
		}
	}
	return out.String()
}

// ParseRecoveryCode accepts a recovery code typed by a human.
func ParseRecoveryCode(s string) ([]byte, error) {
	var bits uint64
	var n int
	var out []byte
	count := 0
	for _, r := range strings.ToUpper(s) {
		switch r {
		case '-', ' ':
			continue
		case 'O':
			r = '0'
		case 'I', 'L':
			r = '1'
		}
		v := strings.IndexRune(crockford, r)
		if v < 0 {
			return nil, errors.New("e2ee: invalid character in recovery code")
		}
		count++
		bits = bits<<5 | uint64(v)
		n += 5
		if n >= 8 {
			n -= 8
			out = append(out, byte(bits>>n)) // #nosec G115 -- keeps the low 8 bits on purpose (base32 decoding)
		}
	}
	if count != 32 || len(out) != 20 {
		return nil, errors.New("e2ee: a recovery code has 32 characters")
	}
	return out, nil
}
