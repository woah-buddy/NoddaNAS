package service

import (
	"context"
	"strings"
	"time"

	"github.com/woah-buddy/FrontDir/internal/domain"
	"github.com/woah-buddy/FrontDir/internal/validate"
)

// Administration: people, administrator rights and quotas.
//
// Reading the admin area needs administrator rights. Changing anything in
// it also needs a recent sign-in: the administrator must have
// re-authenticated at their identity provider, on request, within
// RecentSignIn. It is the same idea as sudo asking for your password again:
// a session left open on an unattended computer, or one stolen somehow,
// can look but cannot change who may sign in, who administers, or where
// sign-in goes.

// RecentSignIn is how recent the re-authentication must be.
const RecentSignIn = 15 * time.Minute

// ErrReauthRequired asks the caller to confirm who they are again.
var ErrReauthRequired = domain.E(domain.CodeReauth, "confirm it's you: sign in again to make this change")

// RequireAdmin checks that p is an administrator (and not a read-only
// credential).
func (s *Service) RequireAdmin(ctx context.Context, p Principal) error { return s.requireAdmin(ctx, p) }

// RequireFreshAdmin checks that p is an administrator who re-authenticated
// within RecentSignIn.
func (s *Service) RequireFreshAdmin(ctx context.Context, p Principal) error {
	if err := s.requireAdmin(ctx, p); err != nil {
		return err
	}
	now := s.now()
	if p.ReauthAt.IsZero() || now.Sub(p.ReauthAt) > RecentSignIn || p.ReauthAt.After(now.Add(time.Minute)) {
		return ErrReauthRequired
	}
	return nil
}

// UserSummary is an account as the admin area lists it.
type UserSummary struct {
	ID              string
	DisplayName     string
	Email           string
	Issuer          string
	Admin           bool // effective
	AdminGranted    bool // appointed in FrontDir (otherwise through a group)
	KeysSetUp       bool
	PersonalSpaceID string
	QuotaBytes      int64
	UsedBytes       int64
	CreatedAt       time.Time
}

// AdminListUsers lists accounts, optionally filtered by part of an email
// address or name.
func (s *Service) AdminListUsers(ctx context.Context, p Principal, query string) ([]UserSummary, error) {
	if err := s.requireAdmin(ctx, p); err != nil {
		return nil, err
	}
	query = strings.TrimSpace(query)
	if len(query) > 200 {
		return nil, domain.E(domain.CodeInvalid, "search is too long")
	}
	return s.store.ListUsers(ctx, query, 200)
}

// AdminSetAdmin appoints or removes an administrator. Nobody changes their
// own rights, so the last administrator cannot lock everyone out by
// accident, and a hijacked session cannot quietly entrench itself.
// Administrators through a group stay administrators until removed from
// the group (or the group from the administrator groups).
func (s *Service) AdminSetAdmin(ctx context.Context, p Principal, userID string, admin bool) error {
	if err := s.RequireFreshAdmin(ctx, p); err != nil {
		return err
	}
	if err := validate.ID(userID); err != nil {
		return domain.ErrNotFound
	}
	if userID == p.UserID {
		return domain.E(domain.CodeForbidden, "you cannot change your own administrator rights; ask another administrator")
	}
	if err := s.store.SetAdminGranted(ctx, userID, admin, s.conf().AdminGroups); err != nil {
		return err
	}
	event := "user.admin_removed"
	if admin {
		event = "user.admin_granted"
	}
	s.audit(ctx, event, p, "target", userID)
	return nil
}

// AdminSetUserQuota sets a person's personal storage.
func (s *Service) AdminSetUserQuota(ctx context.Context, p Principal, userID string, quota int64) error {
	if err := s.RequireFreshAdmin(ctx, p); err != nil {
		return err
	}
	if err := validate.ID(userID); err != nil {
		return domain.ErrNotFound
	}
	u, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.SetQuota(ctx, u.PersonalSpaceID, quota); err != nil {
		return err
	}
	s.audit(ctx, "user.quota", p, "target", userID, "bytes", quota)
	return nil
}

// ApplyAdminGroups re-derives every account's administrator flag from the
// current administrator groups (after they changed).
func (s *Service) ApplyAdminGroups(ctx context.Context) (int64, error) {
	return s.store.RecomputeAdmins(ctx, s.conf().AdminGroups)
}

// UserAndGroups returns an account with the groups it had at its last
// sign-in (for the settings lockout checks).
func (s *Service) UserAndGroups(ctx context.Context, userID string) (*domain.User, []string, error) {
	u, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	g, err := s.store.UserGroups(ctx, userID)
	return u, g, err
}

// IssuerCounts counts accounts per identity issuer.
func (s *Service) IssuerCounts(ctx context.Context) (map[string]int64, error) {
	return s.store.IssuerCounts(ctx)
}

// UserByID returns an account (for the HTTP layer's own bookkeeping, e.g.
// choosing how to send someone back to their identity provider).
func (s *Service) UserByID(ctx context.Context, id string) (*domain.User, error) {
	if err := validate.ID(id); err != nil {
		return nil, domain.ErrNotFound
	}
	return s.store.GetUser(ctx, id)
}
