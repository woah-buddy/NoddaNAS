package e2ee

import "crypto/ecdh"

// Space holds an unlocked space secret and the keys derived from it
// (docs/E2EE.md §3).
type Space struct {
	ID     string
	Secret []byte
	Priv   *ecdh.PrivateKey
}

// OpenSpace derives a space's keys from its secret.
func OpenSpace(id string, secret []byte) *Space {
	priv, err := ecdh.X25519().NewPrivateKey(kdf(secret, nil, "space-x25519"))
	if err != nil {
		panic(err) // any 32 bytes are a valid X25519 private key
	}
	return &Space{ID: id, Secret: secret, Priv: priv}
}

// NewTeamSecret returns a fresh random team-space secret.
func NewTeamSecret() []byte { return random(32) }

// PublicKey returns the space's public key (raw bytes).
func (s *Space) PublicKey() []byte { return s.Priv.PublicKey().Bytes() }

func spaceKeyMsg(spaceID string, pub []byte) []byte {
	return append(append(join("space-key", spaceID), 0), pub...)
}

// SignSpaceKey is the creator's signature over the space's public key.
func SignSpaceKey(creator *Account, spaceID string, pub []byte) string {
	return B64(sign(creator.Sig, spaceKeyMsg(spaceID, pub)))
}

// VerifySpaceKey checks a space public key against its creator's signature
// and returns it ready for sealing.
func VerifySpaceKey(creator *PublicUser, spaceID, pubB64, sigB64 string) (*ecdh.PublicKey, error) {
	pub, err1 := UnB64(pubB64)
	sig, err2 := UnB64(sigB64)
	if err1 != nil || err2 != nil {
		return nil, ErrAuth
	}
	if err := verify(creator.Sig, spaceKeyMsg(spaceID, pub), sig); err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPublicKey(pub)
}

// WrapRoot wraps the space's root node key.
func (s *Space) WrapRoot(rootID string, nk *NodeKey) string {
	return B64(gcmSeal(kdf(s.Secret, nil, "space-root"), nk.raw, join("space-root", s.ID, rootID)))
}

// UnwrapRoot recovers the space's root node key.
func (s *Space) UnwrapRoot(rootID, wrapped string) (*NodeKey, error) {
	raw, err := openB64(kdf(s.Secret, nil, "space-root"), wrapped, join("space-root", s.ID, rootID))
	if err != nil {
		return nil, err
	}
	return nodeKeyFrom(raw)
}

// EncryptName encrypts a team space's display name.
func (s *Space) EncryptName(name string) string {
	return B64(gcmSeal(kdf(s.Secret, nil, "space-name"), pad32([]byte(nfc(name))), join("space-name", s.ID)))
}

// DecryptName decrypts a team space's display name.
func (s *Space) DecryptName(enc string) (string, error) {
	pt, err := openB64(kdf(s.Secret, nil, "space-name"), enc, join("space-name", s.ID))
	return string(unpad(pt)), err
}

func grantSigMsg(spaceID, memberID string, grant []byte) []byte {
	return append(append(join("space-grant-sig", spaceID, memberID), 0), sum(grant)...)
}

// Grant gives a team space's secret to a member: sealed to the member's
// key and signed by the granter.
func (s *Space) Grant(granter *Account, member *PublicUser) (grant, sig string, err error) {
	g, err := Seal(member.Enc, s.Secret, join("space-grant", s.ID, member.ID))
	if err != nil {
		return "", "", err
	}
	return B64(g), B64(sign(granter.Sig, grantSigMsg(s.ID, member.ID, g))), nil
}

// OpenGrant recovers a team space from a grant, after checking the
// granter's signature.
func OpenGrant(me *Account, granter *PublicUser, spaceID, grantB64, sigB64 string) (*Space, error) {
	g, err1 := UnB64(grantB64)
	sig, err2 := UnB64(sigB64)
	if err1 != nil || err2 != nil {
		return nil, ErrAuth
	}
	if err := verify(granter.Sig, grantSigMsg(spaceID, me.UserID, g), sig); err != nil {
		return nil, err
	}
	secret, err := Open(me.Enc, g, join("space-grant", spaceID, me.UserID))
	if err != nil {
		return nil, err
	}
	if len(secret) != 32 {
		return nil, ErrAuth
	}
	return OpenSpace(spaceID, secret), nil
}

// PersonalSpace opens the account owner's personal space.
func (a *Account) PersonalSpace(spaceID string) *Space {
	return OpenSpace(spaceID, a.PersonalSpaceSecret())
}
