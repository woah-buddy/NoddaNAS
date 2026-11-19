package service

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"unicode"

	"github.com/woah-buddy/NoddaNAS/internal/domain"
	"github.com/woah-buddy/NoddaNAS/internal/e2ee"
	"github.com/woah-buddy/NoddaNAS/internal/secure"
	"github.com/woah-buddy/NoddaNAS/internal/validate"
)

// Identity is what the identity provider (OIDC or SAML) asserted at sign-in.
type Identity struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Groups        []string
}

// LoginUser finds or provisions the account for an authenticated identity
// and refreshes its profile, groups and admin flag.
//
// Accounts are keyed by (issuer, subject), never by email. An email is
// recorded only if the IdP says it is verified and no other account holds
// it, so nobody can register someone else's address to receive their shares.
func (s *Service) LoginUser(ctx context.Context, id Identity) (*domain.User, error) {
	if id.Issuer == "" || id.Subject == "" {
		return nil, domain.ErrUnauthorized
	}
	email := ""
	if id.EmailVerified {
		if e, err := validate.Email(id.Email); err == nil {
			email = e
		}
	}
	name := cleanDisplayName(id.Name)
	groups := cleanGroups(id.Groups)
	admin := s.isAdminGroups(groups)

	u, err := s.store.GetUserByIdentity(ctx, id.Issuer, id.Subject)
	switch {
	case err == nil:
		if u.Email != email || u.DisplayName != name || u.Admin != admin {
			if err := s.store.UpdateUserProfile(ctx, u.ID, email, name, admin); err != nil {
				return nil, err
			}
		}
	case errors.Is(err, domain.ErrNotFound):
		if u, err = s.provision(ctx, id, email, name, admin); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	if err := s.store.SyncGroups(ctx, u.ID, groups); err != nil {
		return nil, err
	}
	return s.store.GetUser(ctx, u.ID)
}

func (s *Service) provision(ctx context.Context, id Identity, email, name string, admin bool) (*domain.User, error) {
	now := s.now()
	u := &domain.User{
		ID: secure.NewID(), Issuer: id.Issuer, Subject: id.Subject, Email: email, DisplayName: name,
		Admin: admin, PersonalSpaceID: secure.NewID(), CreatedAt: now,
	}
	sp := &domain.Space{
		ID: u.PersonalSpaceID, Kind: domain.SpacePersonal, OwnerUserID: u.ID, RootID: secure.NewID(),
		QuotaBytes: s.cfg.DefaultQuota, CreatedAt: now, CreatedBy: u.ID,
	}
	root := &domain.Node{
		ID: sp.RootID, SpaceID: sp.ID, Kind: domain.KindFolder,
		CreatedAt: now, CreatedBy: u.ID, ModifiedAt: now, ModifiedBy: u.ID, Revision: 1,
	}
	if err := s.store.CreateUser(ctx, u, sp, root); err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return s.store.GetUserByIdentity(ctx, id.Issuer, id.Subject) // concurrent first sign-in
		}
		return nil, err
	}
	s.audit(ctx, "user.provisioned", Principal{UserID: u.ID}, "email_recorded", u.Email != "", "admin", admin)
	return u, nil
}

func cleanDisplayName(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r >= 0x202A && r <= 0x202E || r >= 0x2066 && r <= 0x2069 {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > 128 {
		s = string(r[:128])
	}
	return s
}

func cleanGroups(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, g := range in {
		if validate.Group(g) == nil && !seen[g] && len(out) < 1000 {
			seen[g] = true
			out = append(out, g)
		}
	}
	sort.Strings(out)
	return out
}

// Me returns the caller's account and personal space.
func (s *Service) Me(ctx context.Context, p Principal) (*domain.User, *domain.Space, error) {
	if p.UserID == "" {
		return nil, nil, domain.ErrUnauthorized
	}
	u, err := s.store.GetUser(ctx, p.UserID)
	if err != nil {
		return nil, nil, err
	}
	sp, err := s.store.GetSpace(ctx, u.PersonalSpaceID)
	return u, sp, err
}

// ---- E2EE keys -------------------------------------------------------------------

// SetupKeys stores the caller's first key bundle and their personal space's
// keys. The server checks shape and self-consistency (signatures verify),
// which catches broken clients; it cannot and does not check secrets.
func (s *Service) SetupKeys(ctx context.Context, p Principal, bundle string, personal SpaceKeys) error {
	if p.ReadOnly {
		return domain.E(domain.CodeForbidden, "this credential is read-only")
	}
	u, sp, err := s.Me(ctx, p)
	if err != nil {
		return err
	}
	b, keys, err := parseBundle(u.ID, bundle)
	if err != nil {
		return err
	}
	pub, err := e2ee.VerifyPublicKeys(u.ID, b.Pub, b.SelfSig)
	if err != nil {
		return domain.E(domain.CodeInvalid, "key bundle self-signature does not verify")
	}
	personal.KeySigner = u.ID
	if err := checkSpaceKeys(sp.ID, personal, pub); err != nil {
		return err
	}
	if err := s.store.SetKeys(ctx, u.ID, *keys, bundle, personal); err != nil {
		return err
	}
	s.audit(ctx, "keys.setup", p, "fingerprint", pub.Finger)
	return nil
}

// UpdateKeyBundle replaces the caller's key bundle, e.g. after a passphrase
// change. The public keys must not change: replacing them would let a
// hijacked session substitute keys that other users then encrypt to.
func (s *Service) UpdateKeyBundle(ctx context.Context, p Principal, bundle string) error {
	if p.ReadOnly {
		return domain.E(domain.CodeForbidden, "this credential is read-only")
	}
	u, err := s.store.GetUser(ctx, p.UserID)
	if err != nil {
		return err
	}
	if u.Keys == nil {
		return domain.E(domain.CodePrecondition, "encryption keys are not set up yet")
	}
	_, keys, err := parseBundle(u.ID, bundle)
	if err != nil {
		return err
	}
	if *keys != *u.Keys {
		return domain.E(domain.CodeInvalid, "public keys cannot be changed")
	}
	if err := s.store.UpdateKeyBundle(ctx, u.ID, bundle); err != nil {
		return err
	}
	s.audit(ctx, "keys.bundle_updated", p)
	return nil
}

func parseBundle(userID, raw string) (*e2ee.Bundle, *domain.PublicKeys, error) {
	if len(raw) > 16<<10 {
		return nil, nil, domain.E(domain.CodeInvalid, "key bundle too large")
	}
	var b e2ee.Bundle
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return nil, nil, domain.E(domain.CodeInvalid, "malformed key bundle")
	}
	if b.V != 1 || b.UserID != userID || len(b.Unlock) < 2 || len(b.Unlock) > 8 || b.Private == "" {
		return nil, nil, domain.E(domain.CodeInvalid, "key bundle must be v1, for this user, with passphrase and recovery unlockers")
	}
	types := map[string]bool{}
	for _, u := range b.Unlock {
		types[u.Type] = true
	}
	if !types["passphrase"] || !types["recovery"] {
		return nil, nil, domain.E(domain.CodeInvalid, "key bundle needs both a passphrase and a recovery unlocker")
	}
	for f, v := range map[string]string{"pub.enc": b.Pub.Enc, "pub.sig": b.Pub.Sig} {
		if err := validate.Opaque(f, v, validate.PublicKeyLen, validate.PublicKeyLen); err != nil {
			return nil, nil, err
		}
	}
	if err := validate.Opaque("selfSig", b.SelfSig, validate.SignatureLen, validate.SignatureLen); err != nil {
		return nil, nil, err
	}
	return &b, &domain.PublicKeys{Enc: b.Pub.Enc, Sig: b.Pub.Sig, SelfSig: b.SelfSig}, nil
}

func checkSpaceKeys(spaceID string, k SpaceKeys, creator *e2ee.PublicUser) error {
	if err := validate.Opaque("rootKey", k.RootKey, validate.WrappedKeyLen, validate.WrappedKeyLen); err != nil {
		return err
	}
	if _, err := e2ee.VerifySpaceKey(creator, spaceID, k.PublicKey, k.KeySig); err != nil {
		return domain.E(domain.CodeInvalid, "space key signature does not verify")
	}
	return nil
}

// KeyBundle returns the caller's (encrypted) key bundle.
func (s *Service) KeyBundle(ctx context.Context, p Principal) (string, error) {
	u, err := s.store.GetUser(ctx, p.UserID)
	if err != nil {
		return "", err
	}
	if u.Keys == nil {
		return "", domain.E(domain.CodeNotFound, "encryption keys are not set up yet")
	}
	return u.KeyBundle, nil
}

// PublicUser is a directory entry: what other users may know about a user.
type PublicUser struct {
	ID          string
	DisplayName string
	Email       string
	Keys        *domain.PublicKeys
}

// UserKeys returns a user's public keys (for verifying their signatures and
// encrypting to them). Available to any signed-in user.
func (s *Service) UserKeys(ctx context.Context, p Principal, userID string) (*PublicUser, error) {
	if p.UserID == "" {
		return nil, domain.ErrUnauthorized
	}
	if err := validate.ID(userID); err != nil {
		return nil, domain.ErrNotFound
	}
	u, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &PublicUser{ID: u.ID, DisplayName: u.DisplayName, Email: u.Email, Keys: u.Keys}, nil
}

// LookupUser finds a user by verified email, for sharing.
func (s *Service) LookupUser(ctx context.Context, p Principal, email string) (*PublicUser, error) {
	if p.UserID == "" {
		return nil, domain.ErrUnauthorized
	}
	e, err := validate.Email(email)
	if err != nil {
		return nil, err
	}
	id, err := s.store.GetUserIDByEmail(ctx, e)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, domain.E(domain.CodeNotFound, "no user with that email address has signed in yet")
	} else if err != nil {
		return nil, err
	}
	return s.UserKeys(ctx, p, id)
}

// SetQuota is an administrative operation (CLI or admin API).
func (s *Service) SetQuota(ctx context.Context, spaceID string, quota int64) error {
	if quota < 0 {
		return domain.E(domain.CodeInvalid, "quota must not be negative")
	}
	return s.store.SetSpaceQuota(ctx, spaceID, quota)
}

// SetUserQuotaByEmail sets a user's personal space quota (CLI).
func (s *Service) SetUserQuotaByEmail(ctx context.Context, email string, quota int64) error {
	e, err := validate.Email(email)
	if err != nil {
		return err
	}
	id, err := s.store.GetUserIDByEmail(ctx, e)
	if err != nil {
		return err
	}
	u, err := s.store.GetUser(ctx, id)
	if err != nil {
		return err
	}
	return s.SetQuota(ctx, u.PersonalSpaceID, quota)
}
