package service

import (
	"context"
	"errors"
	"strings"
	"unicode"

	"github.com/woah-buddy/NoddaNAS/internal/domain"
	"github.com/woah-buddy/NoddaNAS/internal/secure"
	"github.com/woah-buddy/NoddaNAS/internal/validate"
)

// Identity is what the identity provider asserted at login.
type Identity struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
}

// LoginUser finds or provisions the account for an authenticated identity.
//
// Accounts are keyed by (issuer, subject), never by email: emails can be
// reassigned or unverified, subjects cannot. An email is recorded only if the
// IdP says it is verified, and only if no other account already holds it, so
// nobody can sign up with someone else's address and receive their shares.
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

	u, err := s.store.GetUserByIdentity(ctx, id.Issuer, id.Subject)
	switch {
	case err == nil:
		if u.Email != email || u.DisplayName != name {
			if err := s.store.UpdateUserProfile(ctx, u.ID, email, name); err != nil {
				return nil, err
			}
			return s.store.GetUser(ctx, u.ID)
		}
		return u, nil
	case !errors.Is(err, domain.ErrNotFound):
		return nil, err
	}

	now := s.now()
	u = &domain.User{
		ID: secure.NewID(), Issuer: id.Issuer, Subject: id.Subject, Email: email, DisplayName: name,
		RootID: secure.NewID(), QuotaBytes: s.cfg.DefaultQuota, CreatedAt: now,
	}
	root := &domain.Node{
		ID: u.RootID, OwnerID: u.ID, Kind: domain.KindFolder,
		CreatedAt: now, ModifiedAt: now, ModifiedBy: u.ID, Revision: 1,
	}
	if err := s.store.CreateUser(ctx, u, root); err != nil {
		if errors.Is(err, domain.ErrConflict) {
			// Another request provisioned this identity concurrently.
			return s.store.GetUserByIdentity(ctx, id.Issuer, id.Subject)
		}
		return nil, err
	}
	s.audit(ctx, "user.provisioned", Principal{UserID: u.ID}, "email_recorded", u.Email != "")
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

// Me returns the caller's account.
func (s *Service) Me(ctx context.Context, p Principal) (*domain.User, error) {
	if p.UserID == "" {
		return nil, domain.ErrUnauthorized
	}
	return s.store.GetUser(ctx, p.UserID)
}

// SetQuotaByEmail is an administrative operation (exposed via the CLI only).
func (s *Service) SetQuotaByEmail(ctx context.Context, email string, quota int64) error {
	if quota < 0 {
		return domain.E(domain.CodeInvalid, "quota must not be negative")
	}
	e, err := validate.Email(email)
	if err != nil {
		return err
	}
	id, err := s.store.GetUserIDByEmail(ctx, e)
	if err != nil {
		return err
	}
	return s.store.SetQuota(ctx, id, quota)
}
