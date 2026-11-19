package service

import (
	"context"
	"errors"

	"github.com/woah-buddy/NoddaNAS/internal/domain"
	"github.com/woah-buddy/NoddaNAS/internal/validate"
)

// NodeInfo is a node plus the caller's effective permission on it.
type NodeInfo struct {
	Node           *domain.Node
	Permission     domain.Permission
	CanModifyEntry bool // may rename, move or delete it (write on parent)
}

func infoOf(a *access) *NodeInfo {
	return &NodeInfo{Node: a.node, Permission: a.perm(), CanModifyEntry: requireParentWrite(a) == nil}
}

// GetNode returns a node the caller can read.
func (s *Service) GetNode(ctx context.Context, p Principal, id string) (*NodeInfo, error) {
	a, err := s.authorize(ctx, p, id, domain.PermRead)
	if err != nil {
		return nil, err
	}
	return infoOf(a), nil
}

// Path tells a client how to derive a node's key: an entry point it holds
// a key for (its space, or a share made with it) plus every node from that
// entry point down to the target, each with its wrapped key.
type Path struct {
	Space *SpaceInfo    // the space; Role is RoleNone if access is via a share
	Share *domain.Share // the entry share, if access is via a user share
	Nodes []*domain.Node
	Info  *NodeInfo
}

// NodePath returns the key-derivation path to a node.
func (s *Service) NodePath(ctx context.Context, p Principal, id string) (*Path, error) {
	a, err := s.authorize(ctx, p, id, domain.PermRead)
	if err != nil {
		return nil, err
	}
	role, m, err := s.spaceRole(ctx, p, a.space)
	if err != nil {
		return nil, err
	}
	out := &Path{Space: &SpaceInfo{Space: a.space, Role: role, Membership: m}, Info: infoOf(a)}
	entry := len(a.chain) - 1 // the root
	if role == domain.RoleNone {
		// Access is through a share: start at the highest shared ancestor.
		entry = -1
		for i := len(a.chain) - 1; i >= 0; i-- {
			if g, ok := a.grants[a.chain[i].ID]; ok {
				entry, out.Share = i, g
				break
			}
		}
		if entry < 0 {
			return nil, domain.ErrNotFound
		}
	}
	for i := entry; i >= 0; i-- {
		out.Nodes = append(out.Nodes, a.chain[i])
	}
	return out, nil
}

// ListChildren lists a folder the caller can read.
func (s *Service) ListChildren(ctx context.Context, p Principal, id, cursor string, limit int) (*NodeInfo, []*domain.Node, string, error) {
	a, err := s.authorize(ctx, p, id, domain.PermRead)
	if err != nil {
		return nil, nil, "", err
	}
	if a.node.Kind != domain.KindFolder {
		return nil, nil, "", domain.E(domain.CodeInvalid, "not a folder")
	}
	if cursor != "" && validate.ID(cursor) != nil {
		return nil, nil, "", domain.E(domain.CodeInvalid, "invalid cursor")
	}
	children, next, err := s.store.ListChildren(ctx, id, cursor, s.pageSize(limit))
	if err != nil {
		return nil, nil, "", err
	}
	return infoOf(a), children, next, nil
}

// EntryFields are the client-encrypted fields that place a node in a folder.
type EntryFields struct {
	NameEnc    string // name encrypted under the parent's name key
	NameHash   string // keyed name hash under the parent's hash key
	WrappedKey string // node key wrapped under the parent's wrap key
}

func (e EntryFields) validate(needKey bool) error {
	if err := validate.Opaque("nameEnc", e.NameEnc, validate.EncNameMin, validate.EncNameMax); err != nil {
		return err
	}
	if err := validate.SHA256Hex(e.NameHash); err != nil {
		return domain.E(domain.CodeInvalid, "nameHash must be 64 lowercase hex characters")
	}
	if needKey {
		return validate.Opaque("wrappedKey", e.WrappedKey, validate.WrappedKeyLen, validate.WrappedKeyLen)
	}
	return nil
}

// CreateFolder creates folder `id` (chosen by the client) inside parentID.
func (s *Service) CreateFolder(ctx context.Context, p Principal, parentID, id string, e EntryFields) (*domain.Node, error) {
	if err := validate.ID(id); err != nil {
		return nil, err
	}
	if err := e.validate(true); err != nil {
		return nil, err
	}
	a, err := s.authorize(ctx, p, parentID, domain.PermWrite)
	if err != nil {
		return nil, err
	}
	if a.node.Kind != domain.KindFolder {
		return nil, domain.E(domain.CodeInvalid, "parent is not a folder")
	}
	if len(a.chain) >= s.cfg.MaxDepth {
		return nil, errTooDeep
	}
	now := s.now()
	n := &domain.Node{
		ID: id, SpaceID: a.space.ID, ParentID: a.node.ID, Kind: domain.KindFolder,
		NameEnc: e.NameEnc, NameHash: e.NameHash, WrappedKey: e.WrappedKey,
		CreatedAt: now, CreatedBy: p.UserID, ModifiedAt: now, ModifiedBy: p.UserID, Revision: 1,
	}
	if err := s.store.CreateFolder(ctx, n); err != nil {
		return nil, s.nameConflict(ctx, err, a.node.ID, e.NameHash)
	}
	s.audit(ctx, "folder.create", p, "node", n.ID, "parent", a.node.ID)
	return n, nil
}

// nameConflict turns a unique violation into a helpful 409 that tells the
// client which existing node holds the name (it can see the folder anyway).
func (s *Service) nameConflict(ctx context.Context, err error, parentID, hash string) error {
	if !errors.Is(err, domain.ErrConflict) {
		return err
	}
	e := &domain.Error{Code: domain.CodeConflict, Message: "an item with that name already exists in this folder"}
	if existing, gerr := s.store.GetChildByHash(ctx, parentID, hash); gerr == nil {
		e.Detail = map[string]string{"existingId": existing.ID, "existingKind": string(existing.Kind)}
	}
	return e
}

// UpdateRequest renames and/or moves a node. A rename supplies a new
// encrypted name and hash; a move also supplies the node key re-wrapped
// under the new parent. Revision, if non-zero, must match.
type UpdateRequest struct {
	ParentID *string
	Entry    EntryFields
	Revision int64
}

// Update renames and/or moves a node.
func (s *Service) Update(ctx context.Context, p Principal, id string, req UpdateRequest) (*domain.Node, error) {
	a, err := s.authorize(ctx, p, id, domain.PermRead)
	if err != nil {
		return nil, err
	}
	if err := requireParentWrite(a); err != nil {
		return nil, err
	}
	moving := req.ParentID != nil && *req.ParentID != a.node.ParentID
	if err := req.Entry.validate(moving); err != nil {
		return nil, err
	}
	n := *a.node
	n.NameEnc, n.NameHash = req.Entry.NameEnc, req.Entry.NameHash
	if moving {
		dest, err := s.authorize(ctx, p, *req.ParentID, domain.PermWrite)
		if err != nil {
			return nil, err
		}
		switch {
		case dest.node.Kind != domain.KindFolder:
			return nil, domain.E(domain.CodeInvalid, "destination is not a folder")
		case dest.space.ID != a.space.ID:
			// Content and quota belong to a space. Moving between spaces
			// means re-encrypting for the new owner, which clients do as
			// download-and-upload.
			return nil, domain.E(domain.CodeInvalid, "items cannot be moved between spaces; copy them instead")
		case dest.contains(n.ID):
			return nil, domain.E(domain.CodeInvalid, "a folder cannot be moved into itself")
		case len(dest.chain) >= s.cfg.MaxDepth:
			return nil, errTooDeep
		}
		n.ParentID, n.WrappedKey = dest.node.ID, req.Entry.WrappedKey
	}
	rev := req.Revision
	if rev == 0 {
		rev = a.node.Revision
	}
	n.ModifiedAt, n.ModifiedBy = s.now(), p.UserID
	if err := s.store.UpdateNodeLocation(ctx, &n, rev); err != nil {
		return nil, s.nameConflict(ctx, err, n.ParentID, n.NameHash)
	}
	s.audit(ctx, "node.update", p, "node", n.ID, "parent", n.ParentID, "moved", moving)
	return &n, nil
}

// TrashRequest carries the sealed key that lets the space owner restore the
// item later (docs/E2EE.md §7).
type TrashRequest struct {
	RestoreKey string
	RestoreSig string
	Revision   int64
}

// Trash moves a node (and everything under it) to its space's trash.
func (s *Service) Trash(ctx context.Context, p Principal, id string, req TrashRequest) error {
	if err := firstErr(validate.Opaque("restoreKey", req.RestoreKey, 32+12+16, validate.SealedMax),
		validate.Opaque("restoreSig", req.RestoreSig, validate.SignatureLen, validate.SignatureLen)); err != nil {
		return err
	}
	a, err := s.authorize(ctx, p, id, domain.PermRead)
	if err != nil {
		return err
	}
	if err := requireParentWrite(a); err != nil {
		return err
	}
	rev := req.Revision
	if rev == 0 {
		rev = a.node.Revision
	}
	n := *a.node
	now := s.now()
	n.TrashedAt, n.TrashedBy, n.RestoreKey, n.RestoreSig = &now, p.UserID, req.RestoreKey, req.RestoreSig
	if err := s.store.TrashNode(ctx, &n, rev); err != nil {
		return err
	}
	s.audit(ctx, "node.trash", p, "node", id, "space", a.space.ID)
	return nil
}

// TrashEntry is a trashed node and when it will be purged automatically.
type TrashEntry struct {
	Node      *domain.Node
	ExpiresAt int64 // Unix seconds
}

// ListTrash lists a space's trash: its owner, or team members with write.
func (s *Service) ListTrash(ctx context.Context, p Principal, spaceID string) ([]TrashEntry, error) {
	if _, _, _, err := s.spaceAccess(ctx, p, spaceID, domain.RoleWrite); err != nil {
		return nil, err
	}
	nodes, err := s.store.ListTrash(ctx, spaceID)
	if err != nil {
		return nil, err
	}
	out := make([]TrashEntry, len(nodes))
	for i, n := range nodes {
		out[i] = TrashEntry{Node: n, ExpiresAt: n.TrashedAt.Add(s.cfg.TrashRetention).Unix()}
	}
	return out, nil
}

func (s *Service) trashed(ctx context.Context, p Principal, id string, want domain.Role) (*domain.Node, error) {
	if err := validate.ID(id); err != nil {
		return nil, domain.ErrNotFound
	}
	n, err := s.store.GetNode(ctx, id)
	if err != nil {
		return nil, err
	}
	if n.TrashedAt == nil {
		return nil, domain.ErrNotFound
	}
	if _, _, _, err := s.spaceAccess(ctx, p, n.SpaceID, want); err != nil {
		if errors.Is(err, domain.ErrForbidden) {
			return nil, err
		}
		return nil, domain.ErrNotFound
	}
	return n, nil
}

// RestoreRequest places a trashed node back: the client re-wrapped its key
// and re-encrypted its name for the destination folder.
type RestoreRequest struct {
	ParentID string
	Entry    EntryFields
}

// Restore takes a node out of the trash into ParentID (same space).
func (s *Service) Restore(ctx context.Context, p Principal, id string, req RestoreRequest) (*domain.Node, error) {
	n, err := s.trashed(ctx, p, id, domain.RoleWrite)
	if err != nil {
		return nil, err
	}
	if err := req.Entry.validate(true); err != nil {
		return nil, err
	}
	dest, err := s.authorize(ctx, p, req.ParentID, domain.PermWrite)
	if err != nil {
		return nil, err
	}
	if dest.node.Kind != domain.KindFolder || dest.space.ID != n.SpaceID || dest.contains(n.ID) {
		return nil, domain.E(domain.CodeInvalid, "restore into a folder of the same space")
	}
	n.ParentID, n.NameEnc, n.NameHash, n.WrappedKey = dest.node.ID, req.Entry.NameEnc, req.Entry.NameHash, req.Entry.WrappedKey
	if err := s.store.RestoreNode(ctx, n); err != nil {
		return nil, s.nameConflict(ctx, err, n.ParentID, n.NameHash)
	}
	s.audit(ctx, "node.restore", p, "node", n.ID)
	return n, nil
}

// DeletePermanently schedules a trashed node for purging (space managers).
func (s *Service) DeletePermanently(ctx context.Context, p Principal, id string) error {
	if _, err := s.trashed(ctx, p, id, domain.RoleManage); err != nil {
		return err
	}
	if err := s.store.MarkPurging(ctx, id); err != nil {
		return err
	}
	s.audit(ctx, "node.purge_requested", p, "node", id)
	return nil
}

// EmptyTrash schedules everything in a space's trash for purging.
func (s *Service) EmptyTrash(ctx context.Context, p Principal, spaceID string) (int, error) {
	if _, _, _, err := s.spaceAccess(ctx, p, spaceID, domain.RoleManage); err != nil {
		return 0, err
	}
	nodes, err := s.store.ListTrash(ctx, spaceID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, node := range nodes {
		if err := s.store.MarkPurging(ctx, node.ID); err == nil {
			n++
		} else if !errors.Is(err, domain.ErrNotFound) {
			return n, err
		}
	}
	s.audit(ctx, "trash.empty", p, "space", spaceID, "count", n)
	return n, nil
}
