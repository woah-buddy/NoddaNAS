package service

import (
	"context"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/woah-buddy/NoddaNAS/internal/domain"
	"github.com/woah-buddy/NoddaNAS/internal/secure"
	"github.com/woah-buddy/NoddaNAS/internal/validate"
)

// ShareWithUser grants another user read or write access to a node the
// caller owns. Only owners can share; recipients cannot re-share.
func (s *Service) ShareWithUser(ctx context.Context, p Principal, nodeID, email string, perm domain.Permission) (*domain.Share, error) {
	if perm != domain.PermRead && perm != domain.PermWrite {
		return nil, domain.E(domain.CodeInvalid, "permission must be read or write")
	}
	a, err := s.authorize(ctx, p, nodeID, domain.PermOwner)
	if err != nil {
		return nil, err
	}
	if a.node.IsRoot() {
		return nil, domain.E(domain.CodeInvalid, "your root folder cannot be shared; share a folder inside it")
	}
	addr, err := validate.Email(email)
	if err != nil {
		return nil, err
	}
	recipient, err := s.store.GetUserIDByEmail(ctx, addr)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, domain.E(domain.CodeNotFound, "no user with that email address has signed in yet")
	} else if err != nil {
		return nil, err
	}
	if recipient == p.UserID {
		return nil, domain.E(domain.CodeInvalid, "you cannot share with yourself")
	}
	sh := &domain.Share{
		ID: secure.NewID(), Kind: domain.ShareUser, NodeID: nodeID, OwnerID: a.node.OwnerID, CreatedBy: p.UserID,
		Permission: perm, CreatedAt: s.now(), RecipientID: recipient,
	}
	if err := s.store.CreateShare(ctx, sh); err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return nil, domain.E(domain.CodeConflict, "this item is already shared with that user")
		}
		return nil, err
	}
	s.audit(ctx, "share.user.create", p, "share", sh.ID, "node", nodeID, "recipient", recipient, "permission", string(perm))
	return sh, nil
}

// LinkOptions configures a public link.
type LinkOptions struct {
	Password     string
	ExpiresAt    *time.Time // nil = the default lifetime
	MaxDownloads int64      // 0 = unlimited
}

// CreateLink creates a read-only public link and returns the share together
// with its token. The token is shown exactly once: only its hash is stored.
func (s *Service) CreateLink(ctx context.Context, p Principal, nodeID string, opts LinkOptions) (*domain.Share, string, error) {
	a, err := s.authorize(ctx, p, nodeID, domain.PermOwner)
	if err != nil {
		return nil, "", err
	}
	if a.node.IsRoot() {
		return nil, "", domain.E(domain.CodeInvalid, "your root folder cannot be shared; share a folder inside it")
	}
	now := s.now()
	// Secure by default: every link expires, even if the caller did not ask.
	expires := now.Add(s.cfg.LinkDefaultTTL)
	if opts.ExpiresAt != nil {
		expires = opts.ExpiresAt.UTC()
	}
	if expires.Before(now.Add(time.Minute)) || expires.After(now.Add(s.cfg.LinkMaxTTL)) {
		return nil, "", domain.E(domain.CodeInvalid, "expiry must be between one minute and %d days from now", int(s.cfg.LinkMaxTTL.Hours()/24))
	}
	if opts.MaxDownloads < 0 || opts.MaxDownloads > 1_000_000 {
		return nil, "", domain.E(domain.CodeInvalid, "maxDownloads must be between 0 and 1000000")
	}
	pwHash := ""
	if opts.Password != "" {
		if n := utf8.RuneCountInString(opts.Password); n < 10 || len(opts.Password) > 256 {
			return nil, "", domain.E(domain.CodeInvalid, "link passwords must be at least 10 characters")
		}
		pwHash = secure.HashPassword(opts.Password)
	}
	token := secure.NewToken()
	sh := &domain.Share{
		ID: secure.NewID(), Kind: domain.ShareLink, NodeID: nodeID, OwnerID: a.node.OwnerID, CreatedBy: p.UserID,
		Permission: domain.PermRead, CreatedAt: now, TokenHash: secure.HashToken(secure.PurposeLinkToken, token),
		PasswordHash: pwHash, ExpiresAt: &expires, MaxDownloads: opts.MaxDownloads,
	}
	if err := s.store.CreateShare(ctx, sh); err != nil {
		return nil, "", err
	}
	s.audit(ctx, "share.link.create", p, "share", sh.ID, "node", nodeID, "password", pwHash != "",
		"expires", expires, "max_downloads", opts.MaxDownloads)
	return sh, token, nil
}

// ListShares lists the shares on a node the caller owns.
func (s *Service) ListShares(ctx context.Context, p Principal, nodeID string) ([]*domain.Share, error) {
	if _, err := s.authorize(ctx, p, nodeID, domain.PermOwner); err != nil {
		return nil, err
	}
	return s.store.ListSharesByNode(ctx, nodeID)
}

// DeleteShare revokes a share. The owner can revoke any of their shares; a
// recipient can remove a share made with them ("leave" it).
func (s *Service) DeleteShare(ctx context.Context, p Principal, shareID string) error {
	if p.UserID == "" {
		return domain.ErrUnauthorized
	}
	if err := validate.ID(shareID); err != nil {
		return domain.ErrNotFound
	}
	sh, err := s.store.GetShare(ctx, shareID)
	if err != nil {
		return err
	}
	if sh.OwnerID != p.UserID && sh.RecipientID != p.UserID {
		return domain.ErrNotFound
	}
	if p.ReadOnly {
		return domain.E(domain.CodeForbidden, "this credential is read-only")
	}
	if err := s.store.DeleteShare(ctx, shareID); err != nil {
		return err
	}
	s.audit(ctx, "share.delete", p, "share", shareID, "node", sh.NodeID)
	return nil
}

// SharedItem is a share made with the caller, with the node it grants.
type SharedItem struct {
	Share *domain.Share
	Node  *NodeInfo
}

// SharedWithMe lists what other users have shared with the caller. Shares
// whose node is currently trashed or gone are omitted.
func (s *Service) SharedWithMe(ctx context.Context, p Principal) ([]SharedItem, error) {
	if p.UserID == "" {
		return nil, domain.ErrUnauthorized
	}
	shares, err := s.store.ListSharesByRecipient(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	var out []SharedItem
	for _, sh := range shares {
		info, err := s.GetNode(ctx, p, sh.NodeID)
		if err != nil {
			continue
		}
		out = append(out, SharedItem{Share: sh, Node: info})
	}
	return out, nil
}

// ---- anonymous access via public links --------------------------------------

// LinkNode returns the link's node (or a node inside it).
func (s *Service) LinkNode(ctx context.Context, cred LinkCredential, nodeID string) (*domain.Share, *domain.Node, error) {
	sh, chain, err := s.authorizeLink(ctx, cred, nodeID)
	if err != nil {
		return nil, nil, err
	}
	return sh, chain[0], nil
}

// LinkChildren lists a folder inside a public link.
func (s *Service) LinkChildren(ctx context.Context, cred LinkCredential, nodeID, cursor string, limit int) (*domain.Node, []*domain.Node, string, error) {
	_, chain, err := s.authorizeLink(ctx, cred, nodeID)
	if err != nil {
		return nil, nil, "", err
	}
	n := chain[0]
	if n.Kind != domain.KindFolder {
		return nil, nil, "", domain.E(domain.CodeInvalid, "not a folder")
	}
	children, next, err := s.store.ListChildren(ctx, n.ID, cursor, s.pageSize(limit))
	return n, children, next, err
}

// LinkOpen opens a file inside a public link for download. Every request
// counts against a download limit, including HTTP range requests: exempting
// ranges would let a client fetch "bytes=1-" forever without being counted.
func (s *Service) LinkOpen(ctx context.Context, cred LinkCredential, nodeID string) (*Content, error) {
	sh, chain, err := s.authorizeLink(ctx, cred, nodeID)
	if err != nil {
		return nil, err
	}
	n := chain[0]
	if n.Kind != domain.KindFile {
		return nil, domain.E(domain.CodeInvalid, "not a file")
	}
	if err := s.store.RecordLinkDownload(ctx, sh.ID); err != nil {
		return nil, err
	}
	c, err := s.openVersion(ctx, n, "")
	if err == nil {
		s.log.InfoContext(ctx, "audit", "event", "link.download", "share", sh.ID, "node", n.ID)
	}
	return c, err
}
