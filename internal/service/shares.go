package service

import (
	"context"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/woah-buddy/FrontDir/internal/domain"
	"github.com/woah-buddy/FrontDir/internal/secure"
	"github.com/woah-buddy/FrontDir/internal/validate"
)

// NewUserShare is a share created by a client: it sealed the node key and
// name to the recipient and signed the grant (docs/E2EE.md §6).
type NewUserShare struct {
	ShareID     string
	RecipientID string
	Permission  domain.Permission
	SealedKey   string
	Sig         string
}

// ShareWithUser grants another user access to a node. Only callers with
// full control (personal-space owner, team manager) can share.
func (s *Service) ShareWithUser(ctx context.Context, p Principal, nodeID string, req NewUserShare) (*domain.Share, error) {
	if req.Permission != domain.PermRead && req.Permission != domain.PermWrite {
		return nil, domain.E(domain.CodeInvalid, "permission must be read or write")
	}
	if err := firstErr(validate.ID(req.ShareID), validate.ID(req.RecipientID),
		validate.Opaque("sealedKey", req.SealedKey, 32+12+16, validate.SealedMax),
		validate.Opaque("sig", req.Sig, validate.SignatureLen, validate.SignatureLen)); err != nil {
		return nil, err
	}
	a, err := s.authorize(ctx, p, nodeID, domain.PermOwner)
	if err != nil {
		return nil, err
	}
	if a.node.IsRoot() {
		return nil, domain.E(domain.CodeInvalid, "share a folder inside the space, or add members to a team folder")
	}
	if req.RecipientID == p.UserID {
		return nil, domain.E(domain.CodeInvalid, "you cannot share with yourself")
	}
	recipient, err := s.store.GetUser(ctx, req.RecipientID)
	if err != nil {
		return nil, err
	}
	if recipient.Keys == nil {
		return nil, domain.E(domain.CodePrecondition, "that user has not set up encryption yet")
	}
	sh := &domain.Share{
		ID: req.ShareID, Kind: domain.ShareUser, NodeID: nodeID, SpaceID: a.space.ID, CreatedBy: p.UserID,
		Permission: req.Permission, CreatedAt: s.now(), RecipientID: req.RecipientID,
		SealedKey: req.SealedKey, ShareSig: req.Sig,
	}
	if err := s.store.CreateShare(ctx, sh); err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return nil, domain.E(domain.CodeConflict, "this item is already shared with that user")
		}
		return nil, err
	}
	s.audit(ctx, "share.user.create", p, "share", sh.ID, "node", nodeID, "recipient", req.RecipientID, "permission", string(req.Permission))
	return sh, nil
}

// LinkOptions configures a public link.
type LinkOptions struct {
	ShareID      string
	LinkKey      string // node key + name encrypted under the link secret
	Password     string
	ExpiresAt    *time.Time
	MaxDownloads int64
}

// CreateLink creates a read-only public link and returns it with its access
// token. The token is shown once (only its hash is stored); the link secret
// that decrypts never reaches the server at all.
func (s *Service) CreateLink(ctx context.Context, p Principal, nodeID string, opts LinkOptions) (*domain.Share, string, error) {
	if err := firstErr(validate.ID(opts.ShareID),
		validate.Opaque("linkKey", opts.LinkKey, 12+16+1, validate.SealedMax)); err != nil {
		return nil, "", err
	}
	a, err := s.authorize(ctx, p, nodeID, domain.PermOwner)
	if err != nil {
		return nil, "", err
	}
	if a.node.IsRoot() {
		return nil, "", domain.E(domain.CodeInvalid, "a space's root folder cannot be shared by link")
	}
	now := s.now()
	expires := now.Add(s.conf().LinkDefaultTTL) // every link expires, even if not asked
	if opts.ExpiresAt != nil {
		expires = opts.ExpiresAt.UTC()
	}
	if expires.Before(now.Add(time.Minute)) || expires.After(now.Add(s.conf().LinkMaxTTL)) {
		return nil, "", domain.E(domain.CodeInvalid, "expiry must be between one minute and %d days from now", int(s.conf().LinkMaxTTL.Hours()/24))
	}
	if opts.MaxDownloads < 0 || opts.MaxDownloads > 1_000_000 {
		return nil, "", domain.E(domain.CodeInvalid, "maxDownloads must be between 0 and 1000000")
	}
	pwHash := ""
	if opts.Password != "" {
		if utf8.RuneCountInString(opts.Password) < 10 || len(opts.Password) > 256 {
			return nil, "", domain.E(domain.CodeInvalid, "link passwords must be at least 10 characters")
		}
		pwHash = secure.HashPassword(opts.Password)
	}
	token := secure.NewToken()
	sh := &domain.Share{
		ID: opts.ShareID, Kind: domain.ShareLink, NodeID: nodeID, SpaceID: a.space.ID, CreatedBy: p.UserID,
		Permission: domain.PermRead, CreatedAt: now, TokenHash: secure.HashToken(secure.PurposeLinkToken, token),
		LinkKey: opts.LinkKey, PasswordHash: pwHash, ExpiresAt: &expires, MaxDownloads: opts.MaxDownloads,
	}
	if err := s.store.CreateShare(ctx, sh); err != nil {
		return nil, "", err
	}
	s.audit(ctx, "share.link.create", p, "share", sh.ID, "node", nodeID, "password", pwHash != "",
		"expires", expires, "max_downloads", opts.MaxDownloads)
	return sh, token, nil
}

// ListShares lists the shares on a node the caller fully controls.
func (s *Service) ListShares(ctx context.Context, p Principal, nodeID string) ([]*domain.Share, error) {
	if _, err := s.authorize(ctx, p, nodeID, domain.PermOwner); err != nil {
		return nil, err
	}
	return s.store.ListSharesByNode(ctx, nodeID)
}

// DeleteShare revokes a share. Allowed for whoever fully controls the node,
// the share's creator, and (to leave it) its recipient.
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
	if sh.CreatedBy != p.UserID && sh.RecipientID != p.UserID {
		if _, err := s.authorize(ctx, p, sh.NodeID, domain.PermOwner); err != nil {
			return domain.ErrNotFound
		}
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

// SharedWithMe lists what others have shared with the caller.
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
		if info, err := s.GetNode(ctx, p, sh.NodeID); err == nil {
			out = append(out, SharedItem{Share: sh, Node: info})
		}
	}
	return out, nil
}

// MaxSharedByMe bounds the "shared by me" list.
const MaxSharedByMe = 1000

// SharedByMeItem is a share the caller created. Node is nil when the caller
// can no longer see the item (for example after leaving a team folder, or
// while it is in the trash); the share is still listed so it can be revoked.
type SharedByMeItem struct {
	Share *domain.Share
	Node  *NodeInfo
}

// SharedByMe lists the shares (user shares and public links) the caller
// created, newest first. truncated reports that more exist than were listed.
func (s *Service) SharedByMe(ctx context.Context, p Principal) (items []SharedByMeItem, truncated bool, err error) {
	if p.UserID == "" {
		return nil, false, domain.ErrUnauthorized
	}
	shares, err := s.store.ListSharesByCreator(ctx, p.UserID, MaxSharedByMe+1)
	if err != nil {
		return nil, false, err
	}
	if len(shares) > MaxSharedByMe {
		shares, truncated = shares[:MaxSharedByMe], true
	}
	items = make([]SharedByMeItem, len(shares))
	for i, sh := range shares {
		items[i].Share = sh
		// Node details go through the normal access check, so this list
		// never reveals more about an item than the caller could read anyway.
		if info, err := s.GetNode(ctx, p, sh.NodeID); err == nil {
			items[i].Node = info
		}
	}
	return items, truncated, nil
}

// RevokeMyLinks is the caller's kill switch: it revokes every public link
// they created, everywhere, in one atomic statement. Links stop working
// immediately; the link secrets in already-shared URLs become useless
// because the server no longer holds the token or the wrapped key.
func (s *Service) RevokeMyLinks(ctx context.Context, p Principal) (int64, error) {
	if p.UserID == "" {
		return 0, domain.ErrUnauthorized
	}
	if p.ReadOnly {
		return 0, domain.E(domain.CodeForbidden, "this credential is read-only")
	}
	n, err := s.store.DeleteLinksByCreator(ctx, p.UserID)
	if err != nil {
		return 0, err
	}
	mb, err := s.store.CloseMailboxesByCreator(ctx, p.UserID, s.now()) // mailboxes are links too
	if err != nil {
		return n, err
	}
	s.audit(ctx, "share.link.revoke_all", p, "count", n, "mailboxes", mb)
	return n + mb, nil
}

// AdminRevokeAllLinks is the instance-wide kill switch: it revokes every
// public link created by anyone. Administrators only.
func (s *Service) AdminRevokeAllLinks(ctx context.Context, p Principal) (int64, error) {
	if err := s.RequireFreshAdmin(ctx, p); err != nil {
		return 0, err
	}
	n, err := s.store.DeleteAllLinks(ctx)
	if err != nil {
		return 0, err
	}
	mb, err := s.store.CloseAllMailboxes(ctx, s.now())
	if err != nil {
		return n, err
	}
	s.log.WarnContext(ctx, "audit", "event", "admin.links.revoke_all", "user", p.UserID, "count", n, "mailboxes", mb)
	return n + mb, nil
}

// OperatorFindUser resolves a user for operator commands, by ID or by
// verified email. (Emails are recorded only when the identity provider
// vouches for them, so the ID always works when the email may not.)
func (s *Service) OperatorFindUser(ctx context.Context, emailOrID string) (*domain.User, error) {
	if validate.ID(emailOrID) == nil {
		return s.store.GetUser(ctx, emailOrID)
	}
	e, err := validate.Email(emailOrID)
	if err != nil {
		return nil, domain.E(domain.CodeInvalid, "give the user's email address or 32-character ID")
	}
	id, err := s.store.GetUserIDByEmail(ctx, e)
	if err != nil {
		return nil, err
	}
	return s.store.GetUser(ctx, id)
}

// OperatorRevokeLinks is the break-glass path for the server operator (the
// `frontdir revoke-links` command, run with database access). It works even
// when the web UI or every administrator account is unavailable or
// compromised. An empty or malformed user ID is rejected (it never means
// "everyone"); use OperatorRevokeAllLinks for that.
func (s *Service) OperatorRevokeLinks(ctx context.Context, userID string) (int64, error) {
	if err := validate.ID(userID); err != nil {
		return 0, domain.E(domain.CodeInvalid, "a user ID is required")
	}
	id := userID
	n, err := s.store.DeleteLinksByCreator(ctx, id)
	if err != nil {
		return 0, err
	}
	mb, err := s.store.CloseMailboxesByCreator(ctx, id, s.now())
	if err != nil {
		return n, err
	}
	s.log.WarnContext(ctx, "audit", "event", "operator.links.revoke_user", "actor", "cli", "target", id, "count", n, "mailboxes", mb)
	return n + mb, nil
}

// OperatorRevokeAllLinks revokes every public link (break-glass, operator CLI).
func (s *Service) OperatorRevokeAllLinks(ctx context.Context) (int64, error) {
	n, err := s.store.DeleteAllLinks(ctx)
	if err != nil {
		return 0, err
	}
	mb, err := s.store.CloseAllMailboxes(ctx, s.now())
	if err != nil {
		return n, err
	}
	s.log.WarnContext(ctx, "audit", "event", "operator.links.revoke_all", "actor", "cli", "count", n, "mailboxes", mb)
	return n + mb, nil
}

// ---- anonymous access via public links ---------------------------------------------

// LinkView is what a link visitor receives: the link (with its encrypted
// key), the path from the link's node down to the target, and the target.
type LinkView struct {
	Share *domain.Share
	Path  []*domain.Node // link node first, target last
}

// LinkNode resolves a node within a public link.
func (s *Service) LinkNode(ctx context.Context, cred LinkCredential, nodeID string) (*LinkView, error) {
	sh, chain, err := s.authorizeLink(ctx, cred, nodeID)
	if err != nil {
		return nil, err
	}
	path := make([]*domain.Node, len(chain))
	for i, n := range chain {
		path[len(chain)-1-i] = n
	}
	return &LinkView{Share: sh, Path: path}, nil
}

// LinkChildren lists a folder inside a public link.
func (s *Service) LinkChildren(ctx context.Context, cred LinkCredential, nodeID, cursor string, limit int) ([]*domain.Node, string, error) {
	_, chain, err := s.authorizeLink(ctx, cred, nodeID)
	if err != nil {
		return nil, "", err
	}
	if chain[0].Kind != domain.KindFolder {
		return nil, "", domain.E(domain.CodeInvalid, "not a folder")
	}
	if cursor != "" && validate.ID(cursor) != nil {
		return nil, "", domain.E(domain.CodeInvalid, "invalid cursor")
	}
	return s.store.ListChildren(ctx, chain[0].ID, cursor, s.pageSize(limit))
}

// LinkOpen opens a file inside a public link. Every request counts against
// a download limit, including range requests (otherwise "bytes=1-" would
// bypass it).
func (s *Service) LinkOpen(ctx context.Context, cred LinkCredential, nodeID string) (*Content, error) {
	sh, chain, err := s.authorizeLink(ctx, cred, nodeID)
	if err != nil {
		return nil, err
	}
	if chain[0].Kind != domain.KindFile {
		return nil, domain.E(domain.CodeInvalid, "not a file")
	}
	if err := s.store.RecordLinkDownload(ctx, sh.ID); err != nil {
		return nil, err
	}
	c, err := s.openVersion(ctx, chain[0], "")
	if err == nil {
		s.log.InfoContext(ctx, "audit", "event", "link.download", "share", sh.ID, "node", chain[0].ID)
	}
	return c, err
}

// LinkSigner returns a user's public keys to a link visitor so they can
// verify container signatures. It requires a valid link and reveals
// nothing beyond the keys (no name or email).
func (s *Service) LinkSigner(ctx context.Context, cred LinkCredential, userID string) (*PublicUser, error) {
	if _, _, err := s.authorizeLink(ctx, cred, ""); err != nil {
		return nil, err
	}
	if err := validate.ID(userID); err != nil {
		return nil, domain.ErrNotFound
	}
	u, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &PublicUser{ID: u.ID, Keys: u.Keys}, nil
}
