package service

import (
	"context"
	"errors"
	"strings"

	"github.com/woah-buddy/FrontDir/internal/domain"
	"github.com/woah-buddy/FrontDir/internal/secure"
	"github.com/woah-buddy/FrontDir/internal/validate"
)

// Local accounts (internal/auth/local.go): the account records. Credentials
// live with the auth package; this creates and finds the accounts, which
// are ordinary FrontDir accounts with issuer "local".

// LocalAccountsOn reports whether local accounts may sign in.
func (s *Service) LocalAccountsOn() bool { return s.conf().LocalAccounts }

// LocalAdminsAllowed reports whether local accounts can be administrators.
func (s *Service) LocalAdminsAllowed() bool { return s.conf().LocalAdmins }

// CreateLocalUser creates a local account. The email is recorded as the
// person's address (the administrator who creates the account vouches for
// it), so others can share with them, and is what they sign in with.
func (s *Service) CreateLocalUser(ctx context.Context, actor, email, name string, admin bool) (*domain.User, error) {
	if !s.conf().LocalAccounts {
		return nil, domain.E(domain.CodePrecondition, "local accounts are not enabled (Admin → Settings → Local accounts)")
	}
	e, err := validate.Email(email)
	if err != nil {
		return nil, domain.E(domain.CodeInvalid, "a valid email address is required")
	}
	if admin && !s.conf().LocalAdmins {
		return nil, domain.E(domain.CodeInvalid, "local accounts cannot be administrators while an identity provider is configured, unless allowed in the settings")
	}
	name = cleanDisplayName(name)
	if name == "" {
		name, _, _ = strings.Cut(e, "@")
	}
	if _, err := s.store.GetUserIDByEmail(ctx, e); err == nil {
		return nil, domain.E(domain.CodeConflict, "an account with this email address already exists")
	} else if !errors.Is(err, domain.ErrNotFound) {
		return nil, err
	}
	u, err := s.provision(ctx, Identity{Issuer: domain.IssuerLocal, Subject: secure.NewID()}, e, name, false)
	if err != nil {
		return nil, err
	}
	if u.Email != e { // another account took the address at the same moment
		return nil, domain.E(domain.CodeConflict, "an account with this email address already exists")
	}
	if admin {
		if err := s.store.SetAdminGranted(ctx, u.ID, true, s.conf().AdminGroups); err != nil {
			return nil, err
		}
	}
	s.log.InfoContext(ctx, "audit", "event", "local.user_created", "user", u.ID, "by", actor, "admin", admin)
	return s.store.GetUser(ctx, u.ID)
}

// AdminCreateLocalUser is CreateLocalUser for an administrator, who must
// have confirmed who they are recently.
func (s *Service) AdminCreateLocalUser(ctx context.Context, p Principal, email, name string, admin bool) (*domain.User, error) {
	if err := s.RequireFreshAdmin(ctx, p); err != nil {
		return nil, err
	}
	return s.CreateLocalUser(ctx, p.UserID, email, name, admin)
}

// AdminLocalUser returns a local account an administrator may reset. Nobody
// resets their own (they would lock themselves out mid-session).
func (s *Service) AdminLocalUser(ctx context.Context, p Principal, userID string) (*domain.User, error) {
	if err := s.RequireFreshAdmin(ctx, p); err != nil {
		return nil, err
	}
	if userID == p.UserID {
		return nil, domain.E(domain.CodeInvalid, "you cannot reset your own sign-in here; another administrator, or the operator (frontdir reset-mfa), can")
	}
	if validate.ID(userID) != nil {
		return nil, domain.ErrNotFound
	}
	u, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if u.Issuer != domain.IssuerLocal {
		return nil, domain.E(domain.CodeInvalid, "this account signs in through an identity provider")
	}
	return u, nil
}
