package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/woah-buddy/FrontDir/internal/domain"
	"github.com/woah-buddy/FrontDir/internal/secure"
	"github.com/woah-buddy/FrontDir/internal/validate"
)

// This file is FrontDir's single authorization decision point. Every
// operation on a node, from every transport, goes through authorize (or
// authorizeLink for anonymous public links); every operation on a space
// goes through spaceAccess.
//
// The policy:
//   - A personal space's owner holds every permission on it.
//   - A team space's members hold the permission of their effective role
//     (the strongest of their direct role and their IdP-group roles):
//     read → read, write → write, manage → full control.
//   - A user share grants read or write on a node and everything below it.
//   - Anything inside the trash, or in a deleted space, is invisible.
//   - Changing an entry (rename, move, delete) needs write on its parent
//     folder, like POSIX directories.
//   - Callers who cannot see a node get "not found", never "forbidden".
//
// Authorization is the server's half of access control. The other half is
// cryptographic: even with server access, a caller can only decrypt what
// some key they hold unlocks (docs/E2EE.md).

type access struct {
	node      *domain.Node
	chain     []*domain.Node // node, parent, ..., root
	perms     []domain.Permission
	space     *domain.Space
	spacePerm domain.Permission // permission from space ownership/membership
	grants    map[string]*domain.Share
}

func (a *access) perm() domain.Permission { return a.perms[0] }

func (a *access) parentPerm() domain.Permission {
	if len(a.perms) < 2 {
		return domain.PermNone
	}
	return a.perms[1]
}

func (a *access) contains(id string) bool {
	for _, n := range a.chain {
		if n.ID == id {
			return true
		}
	}
	return false
}

var errTooDeep = domain.E(domain.CodeInvalid, "folders are nested too deeply")

// loadChain fetches a node's ancestry and checks the tree invariants: the
// chain reaches a root, stays within one space, and contains nothing trashed.
func (s *Service) loadChain(ctx context.Context, nodeID string) ([]*domain.Node, *domain.Space, error) {
	if err := validate.ID(nodeID); err != nil {
		return nil, nil, domain.ErrNotFound
	}
	chain, err := s.store.GetAncestry(ctx, nodeID, s.conf().MaxDepth+1)
	if err != nil {
		return nil, nil, err
	}
	top := chain[len(chain)-1]
	if !top.IsRoot() {
		if len(chain) > s.conf().MaxDepth {
			return nil, nil, errTooDeep
		}
		return nil, nil, domain.ErrNotFound
	}
	spaceID := chain[0].SpaceID
	for _, n := range chain {
		if n.SpaceID != spaceID {
			return nil, nil, fmt.Errorf("integrity: node %s crosses spaces", n.ID)
		}
		if n.TrashedAt != nil {
			return nil, nil, domain.ErrNotFound
		}
	}
	sp, err := s.store.GetSpace(ctx, spaceID)
	if err != nil {
		return nil, nil, err
	}
	if sp.DeletedAt != nil || sp.RootID != top.ID {
		return nil, nil, domain.ErrNotFound
	}
	return chain, sp, nil
}

// spaceRole returns p's effective role in a space (RoleManage for the owner
// of a personal space), with the membership record for team spaces.
func (s *Service) spaceRole(ctx context.Context, p Principal, sp *domain.Space) (domain.Role, *domain.Membership, error) {
	if sp.Kind == domain.SpacePersonal {
		if sp.OwnerUserID == p.UserID {
			return domain.RoleManage, nil, nil
		}
		return domain.RoleNone, nil, nil
	}
	m, err := s.store.GetMembership(ctx, sp.ID, p.UserID)
	if errors.Is(err, domain.ErrNotFound) {
		return domain.RoleNone, nil, nil
	} else if err != nil {
		return domain.RoleNone, nil, err
	}
	return m.Role(), m, nil
}

func capReadOnly(p Principal, perm domain.Permission) domain.Permission {
	if p.ReadOnly && perm != domain.PermNone {
		return domain.PermRead
	}
	return perm
}

// authorize decides whether p may act on nodeID with at least `want`.
func (s *Service) authorize(ctx context.Context, p Principal, nodeID string, want domain.Permission) (*access, error) {
	if p.UserID == "" {
		return nil, domain.ErrUnauthorized
	}
	chain, sp, err := s.loadChain(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	role, _, err := s.spaceRole(ctx, p, sp)
	if err != nil {
		return nil, err
	}
	a := &access{node: chain[0], chain: chain, perms: make([]domain.Permission, len(chain)), space: sp,
		spacePerm: role.Permission(), grants: map[string]*domain.Share{}}

	best := a.spacePerm
	if best != domain.PermOwner {
		ids := make([]string, len(chain))
		for i, n := range chain {
			ids[i] = n.ID
		}
		grants, err := s.store.GetGrants(ctx, p.UserID, ids)
		if err != nil {
			return nil, err
		}
		now := s.now()
		for _, g := range grants {
			if g.Kind == domain.ShareUser && g.RecipientID == p.UserID && g.SpaceID == sp.ID && !g.Expired(now) {
				a.grants[g.NodeID] = g
			}
		}
	}
	// A grant covers its node and all descendants: walk from the root down.
	for i := len(chain) - 1; i >= 0; i-- {
		if g, ok := a.grants[chain[i].ID]; ok && g.Permission.Rank() > best.Rank() {
			best = g.Permission
		}
		a.perms[i] = capReadOnly(p, best)
	}
	a.spacePerm = capReadOnly(p, a.spacePerm)

	switch {
	case a.perm() == domain.PermNone:
		return nil, domain.ErrNotFound
	case !a.perm().Allows(want):
		return nil, domain.E(domain.CodeForbidden, "you do not have %s permission on this item", want)
	}
	return a, nil
}

// requireParentWrite enforces "changing an entry needs write on its parent".
func requireParentWrite(a *access) error {
	if a.node.IsRoot() {
		return domain.E(domain.CodeForbidden, "a space's root folder cannot be renamed, moved or deleted")
	}
	if !a.parentPerm().Allows(domain.PermWrite) {
		return domain.E(domain.CodeForbidden, "you need write permission on the containing folder")
	}
	return nil
}

// spaceAccess authorizes an operation on a whole space.
func (s *Service) spaceAccess(ctx context.Context, p Principal, spaceID string, want domain.Role) (*domain.Space, domain.Role, *domain.Membership, error) {
	if p.UserID == "" {
		return nil, "", nil, domain.ErrUnauthorized
	}
	if err := validate.ID(spaceID); err != nil {
		return nil, "", nil, domain.ErrNotFound
	}
	sp, err := s.store.GetSpace(ctx, spaceID)
	if err != nil {
		return nil, "", nil, err
	}
	if sp.DeletedAt != nil {
		return nil, "", nil, domain.ErrNotFound
	}
	role, m, err := s.spaceRole(ctx, p, sp)
	if err != nil {
		return nil, "", nil, err
	}
	if role == domain.RoleNone {
		return nil, "", nil, domain.ErrNotFound
	}
	if p.ReadOnly && role != domain.RoleRead {
		role = domain.RoleRead
	}
	if role.Permission().Rank() < want.Permission().Rank() {
		return nil, "", nil, domain.E(domain.CodeForbidden, "this needs the %s role in the space", want)
	}
	return sp, role, m, nil
}

// LinkCredential is what an anonymous visitor presents for a public link.
// The link secret that decrypts never reaches the server.
type LinkCredential struct {
	Token    string
	Password string
}

// authorizeLink validates a public link and checks that nodeID (or the
// link's own node, if empty) lies within the shared subtree. It returns the
// chain from the target up to the link's node.
func (s *Service) authorizeLink(ctx context.Context, cred LinkCredential, nodeID string) (*domain.Share, []*domain.Node, error) {
	if !secure.ValidToken(cred.Token) {
		return nil, nil, domain.ErrNotFound
	}
	sh, err := s.store.GetShareByTokenHash(ctx, secure.HashToken(secure.PurposeLinkToken, cred.Token))
	if err != nil {
		return nil, nil, err
	}
	if sh.Kind != domain.ShareLink || sh.Permission != domain.PermRead {
		return nil, nil, domain.ErrNotFound
	}
	now := s.now()
	if sh.Expired(now) {
		return nil, nil, domain.E(domain.CodeGone, "this link has expired")
	}
	if sh.Locked(now) {
		return nil, nil, domain.E(domain.CodeRateLimited, "too many wrong passwords; try again later")
	}
	if sh.PasswordHash != "" {
		if cred.Password == "" {
			return nil, nil, &domain.Error{Code: domain.CodeUnauthorized, Message: "this link requires a password",
				Detail: map[string]string{"reason": "password_required"}}
		}
		if !secure.VerifyPassword(cred.Password, sh.PasswordHash) {
			if err := s.store.RecordLinkFailure(ctx, sh.ID, s.conf().LinkMaxFailures, now.Add(s.conf().LinkLockout)); err != nil {
				return nil, nil, err
			}
			s.log.WarnContext(ctx, "audit", "event", "link.password_failed", "share", sh.ID)
			return nil, nil, &domain.Error{Code: domain.CodeUnauthorized, Message: "wrong password",
				Detail: map[string]string{"reason": "password_wrong"}}
		}
		if sh.FailedAttempts > 0 {
			if err := s.store.ResetLinkFailures(ctx, sh.ID); err != nil {
				return nil, nil, err
			}
		}
	}
	if nodeID == "" {
		nodeID = sh.NodeID
	}
	chain, sp, err := s.loadChain(ctx, nodeID)
	if err != nil {
		if errors.Is(err, errTooDeep) {
			return nil, nil, err
		}
		return nil, nil, domain.ErrNotFound
	}
	for i, n := range chain {
		if n.ID == sh.NodeID {
			if sp.ID != sh.SpaceID {
				return nil, nil, domain.ErrNotFound
			}
			return sh, chain[:i+1], nil
		}
	}
	return nil, nil, domain.ErrNotFound
}
