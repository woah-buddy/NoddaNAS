package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/woah-buddy/NoddaNAS/internal/domain"
	"github.com/woah-buddy/NoddaNAS/internal/secure"
	"github.com/woah-buddy/NoddaNAS/internal/validate"
)

// This file is NoddaNAS's single authorization decision point. Every
// operation on a node, from every transport, goes through authorize (or
// authorizeLink for anonymous public links). Keeping the policy in one place
// makes it reviewable and testable, and makes "forgot to check" bugs much
// harder to write: no other code path can produce a node to act on.
//
// The policy, in brief:
//   - Owners hold every permission on their own tree.
//   - A user share grants read or write on a node and everything below it.
//   - Anything inside the trash is invisible to normal operations.
//   - Changing an entry (rename, move, delete) needs write on its parent
//     folder, like POSIX directories. So someone you share "Photos" with
//     can manage what is inside it, but cannot rename or delete "Photos".
//   - Callers who cannot see a node get "not found", never "forbidden", so
//     probing IDs reveals nothing. "Forbidden" is only returned when the
//     caller can already see the node but lacks a stronger permission.

// access is the outcome of an authorization decision.
type access struct {
	node  *domain.Node
	chain []*domain.Node // node, parent, ..., root
	perms []domain.Permission
}

// perm is the caller's permission on the node itself.
func (a *access) perm() domain.Permission { return a.perms[0] }

// parentPerm is the caller's permission on the node's parent folder
// (PermNone for a root).
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

// loadChain fetches a node's ancestry and checks the tree invariants every
// caller relies on: the chain reaches a root, stays within one owner, and
// contains nothing trashed.
func (s *Service) loadChain(ctx context.Context, nodeID string) ([]*domain.Node, error) {
	if err := validate.ID(nodeID); err != nil {
		return nil, domain.ErrNotFound
	}
	chain, err := s.store.GetAncestry(ctx, nodeID, s.cfg.MaxDepth+1)
	if err != nil {
		return nil, err
	}
	top := chain[len(chain)-1]
	if !top.IsRoot() {
		if len(chain) > s.cfg.MaxDepth {
			return nil, errTooDeep // fail closed rather than walk forever
		}
		return nil, domain.ErrNotFound // broken chain: parent missing
	}
	owner := chain[0].OwnerID
	for _, n := range chain {
		if n.OwnerID != owner {
			// Should be impossible; refuse loudly rather than guess.
			return nil, fmt.Errorf("integrity: node %s crosses owners", n.ID)
		}
		if n.TrashedAt != nil {
			return nil, domain.ErrNotFound
		}
	}
	return chain, nil
}

// authorize decides whether p may act on nodeID with at least `want`.
func (s *Service) authorize(ctx context.Context, p Principal, nodeID string, want domain.Permission) (*access, error) {
	if p.UserID == "" {
		return nil, domain.ErrUnauthorized
	}
	chain, err := s.loadChain(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	a := &access{node: chain[0], chain: chain, perms: make([]domain.Permission, len(chain))}

	if chain[0].OwnerID == p.UserID {
		for i := range a.perms {
			a.perms[i] = domain.PermOwner
		}
	} else {
		ids := make([]string, len(chain))
		for i, n := range chain {
			ids[i] = n.ID
		}
		grants, err := s.store.GetGrants(ctx, p.UserID, ids)
		if err != nil {
			return nil, err
		}
		byNode := map[string]domain.Permission{}
		for _, g := range grants {
			if g.Kind == domain.ShareUser && g.RecipientID == p.UserID && !g.Expired(s.now()) {
				if g.Permission.Rank() > byNode[g.NodeID].Rank() {
					byNode[g.NodeID] = g.Permission
				}
			}
		}
		// A grant covers its node and all descendants: walk from the root
		// down, carrying the strongest permission seen so far.
		var best domain.Permission
		for i := len(chain) - 1; i >= 0; i-- {
			if g := byNode[chain[i].ID]; g.Rank() > best.Rank() {
				best = g
			}
			a.perms[i] = best
		}
	}

	if p.ReadOnly {
		for i, perm := range a.perms {
			if perm != domain.PermNone {
				a.perms[i] = domain.PermRead
			}
		}
	}

	switch {
	case a.perm() == domain.PermNone:
		return nil, domain.ErrNotFound
	case !a.perm().Allows(want):
		return nil, domain.E(domain.CodeForbidden, "you do not have %s permission on this item", want)
	}
	return a, nil
}

// requireParentWrite enforces the "changing an entry needs write on its
// parent" rule.
func requireParentWrite(a *access) error {
	if a.node.IsRoot() {
		return domain.E(domain.CodeForbidden, "the root folder cannot be renamed, moved or deleted")
	}
	if !a.parentPerm().Allows(domain.PermWrite) {
		return domain.E(domain.CodeForbidden, "you need write permission on the containing folder")
	}
	return nil
}

// LinkCredential is what an anonymous visitor presents for a public link.
type LinkCredential struct {
	Token    string
	Password string
}

// authorizeLink validates a public link and checks that nodeID (or the
// link's own node, if empty) lies within the shared subtree.
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
			until := now.Add(s.cfg.LinkLockout)
			if err := s.store.RecordLinkFailure(ctx, sh.ID, s.cfg.LinkMaxFailures, until); err != nil {
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
	chain, err := s.loadChain(ctx, nodeID)
	if err != nil {
		if errors.Is(err, errTooDeep) {
			return nil, nil, err
		}
		return nil, nil, domain.ErrNotFound
	}
	inside := false
	for _, n := range chain {
		if n.ID == sh.NodeID {
			inside = true
			break
		}
	}
	if !inside || chain[0].OwnerID != sh.OwnerID {
		return nil, nil, domain.ErrNotFound
	}
	return sh, chain, nil
}
