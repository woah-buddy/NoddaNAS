package service

import (
	"context"
	"errors"

	"github.com/woah-buddy/NoddaNAS/internal/domain"
	"github.com/woah-buddy/NoddaNAS/internal/secure"
	"github.com/woah-buddy/NoddaNAS/internal/validate"
)

// NodeInfo is a node plus the caller's effective permission on it, so
// clients can show only the actions that will succeed.
type NodeInfo struct {
	Node       *domain.Node
	Permission domain.Permission
	// CanModifyEntry reports whether the caller may rename, move or delete
	// this item (which needs write permission on its parent).
	CanModifyEntry bool
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

// ListChildren lists a folder the caller can read.
func (s *Service) ListChildren(ctx context.Context, p Principal, id, cursor string, limit int) (*NodeInfo, []*domain.Node, string, error) {
	a, err := s.authorize(ctx, p, id, domain.PermRead)
	if err != nil {
		return nil, nil, "", err
	}
	if a.node.Kind != domain.KindFolder {
		return nil, nil, "", domain.E(domain.CodeInvalid, "not a folder")
	}
	children, next, err := s.store.ListChildren(ctx, id, cursor, s.pageSize(limit))
	if err != nil {
		return nil, nil, "", err
	}
	return infoOf(a), children, next, nil
}

// CreateFolder creates a folder inside parentID.
func (s *Service) CreateFolder(ctx context.Context, p Principal, parentID, rawName string) (*domain.Node, error) {
	name, err := validate.Name(rawName)
	if err != nil {
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
		ID: secure.NewID(), OwnerID: a.node.OwnerID, ParentID: a.node.ID, Name: name, Kind: domain.KindFolder,
		CreatedAt: now, ModifiedAt: now, ModifiedBy: p.UserID, Revision: 1,
	}
	if err := s.store.CreateFolder(ctx, n, validate.NameKey(name)); err != nil {
		return nil, nameConflict(err)
	}
	s.audit(ctx, "folder.create", p, "node", n.ID, "parent", a.node.ID)
	return n, nil
}

func nameConflict(err error) error {
	if errors.Is(err, domain.ErrConflict) {
		return domain.E(domain.CodeConflict, "an item with that name already exists in this folder")
	}
	return err
}

// UpdateRequest renames and/or moves a node. Nil fields are unchanged.
// Revision, if non-zero, must match the node's current revision.
type UpdateRequest struct {
	Name     *string
	ParentID *string
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
	n := *a.node
	changed := false

	if req.Name != nil {
		name, err := validate.Name(*req.Name)
		if err != nil {
			return nil, err
		}
		changed = changed || name != n.Name
		n.Name = name
	}
	if req.ParentID != nil && *req.ParentID != n.ParentID {
		dest, err := s.authorize(ctx, p, *req.ParentID, domain.PermWrite)
		if err != nil {
			return nil, err
		}
		switch {
		case dest.node.Kind != domain.KindFolder:
			return nil, domain.E(domain.CodeInvalid, "destination is not a folder")
		case dest.node.OwnerID != n.OwnerID:
			// Content and quota belong to the owner; moving across owners
			// would silently transfer both. Copy instead (not yet supported).
			return nil, domain.E(domain.CodeInvalid, "items cannot be moved between different users' storage")
		case dest.contains(n.ID):
			return nil, domain.E(domain.CodeInvalid, "a folder cannot be moved into itself")
		case len(dest.chain) >= s.cfg.MaxDepth:
			return nil, errTooDeep
		}
		n.ParentID = dest.node.ID
		changed = true
	}
	if !changed {
		return a.node, nil
	}
	rev := req.Revision
	if rev == 0 {
		rev = a.node.Revision
	}
	n.ModifiedAt, n.ModifiedBy = s.now(), p.UserID
	if err := s.store.UpdateNodeLocation(ctx, &n, validate.NameKey(n.Name), rev); err != nil {
		return nil, nameConflict(err)
	}
	s.audit(ctx, "node.update", p, "node", n.ID, "parent", n.ParentID)
	return &n, nil
}

// Trash moves a node (and everything under it) to its owner's trash.
func (s *Service) Trash(ctx context.Context, p Principal, id string, revision int64) error {
	a, err := s.authorize(ctx, p, id, domain.PermRead)
	if err != nil {
		return err
	}
	if err := requireParentWrite(a); err != nil {
		return err
	}
	if revision == 0 {
		revision = a.node.Revision
	}
	if err := s.store.TrashNode(ctx, a.node, s.now(), revision); err != nil {
		return err
	}
	s.audit(ctx, "node.trash", p, "node", id, "owner", a.node.OwnerID)
	return nil
}

// ListTrash lists the caller's own trash.
func (s *Service) ListTrash(ctx context.Context, p Principal) ([]domain.TrashEntry, error) {
	if p.UserID == "" {
		return nil, domain.ErrUnauthorized
	}
	nodes, err := s.store.ListTrash(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	out := make([]domain.TrashEntry, len(nodes))
	for i, n := range nodes {
		out[i] = domain.TrashEntry{Node: n, ExpiresAt: n.TrashedAt.Add(s.cfg.TrashRetention)}
	}
	return out, nil
}

// ownTrashed returns a trashed node owned by p, for trash operations.
func (s *Service) ownTrashed(ctx context.Context, p Principal, id string) (*domain.Node, error) {
	if p.UserID == "" {
		return nil, domain.ErrUnauthorized
	}
	if err := validate.ID(id); err != nil {
		return nil, domain.ErrNotFound
	}
	n, err := s.store.GetNode(ctx, id)
	if err != nil {
		return nil, err
	}
	if n.OwnerID != p.UserID || n.TrashedAt == nil {
		return nil, domain.ErrNotFound
	}
	if p.ReadOnly {
		return nil, domain.E(domain.CodeForbidden, "this credential is read-only")
	}
	return n, nil
}

// Restore takes a node out of the trash, back into its original folder (or
// the root, if that folder is gone). newName optionally resolves a clash.
func (s *Service) Restore(ctx context.Context, p Principal, id string, newName *string) (*domain.Node, error) {
	n, err := s.ownTrashed(ctx, p, id)
	if err != nil {
		return nil, err
	}
	if newName != nil {
		name, err := validate.Name(*newName)
		if err != nil {
			return nil, err
		}
		n.Name = name
	}
	if _, err := s.authorize(ctx, p, n.ParentID, domain.PermWrite); err != nil {
		u, uerr := s.store.GetUser(ctx, p.UserID)
		if uerr != nil {
			return nil, uerr
		}
		n.ParentID = u.RootID
	}
	if err := s.store.RestoreNode(ctx, n, validate.NameKey(n.Name)); err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return nil, domain.E(domain.CodeConflict, "an item with that name already exists there; restore it under a new name")
		}
		return nil, err
	}
	s.audit(ctx, "node.restore", p, "node", n.ID)
	return n, nil
}

// DeletePermanently schedules a trashed node for purging.
func (s *Service) DeletePermanently(ctx context.Context, p Principal, id string) error {
	if _, err := s.ownTrashed(ctx, p, id); err != nil {
		return err
	}
	if err := s.store.MarkPurging(ctx, id); err != nil {
		return err
	}
	s.audit(ctx, "node.purge_requested", p, "node", id)
	return nil
}

// EmptyTrash schedules everything in the caller's trash for purging.
func (s *Service) EmptyTrash(ctx context.Context, p Principal) (int, error) {
	if p.ReadOnly {
		return 0, domain.E(domain.CodeForbidden, "this credential is read-only")
	}
	entries, err := s.ListTrash(ctx, p)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if err := s.store.MarkPurging(ctx, e.Node.ID); err == nil {
			n++
		} else if !errors.Is(err, domain.ErrNotFound) {
			return n, err
		}
	}
	s.audit(ctx, "trash.empty", p, "count", n)
	return n, nil
}

// Lookup resolves a path of names, starting at the caller's root folder,
// to a node the caller can read. It serves path-based clients like WebDAV.
func (s *Service) Lookup(ctx context.Context, p Principal, segments []string) (*NodeInfo, error) {
	u, err := s.Me(ctx, p)
	if err != nil {
		return nil, err
	}
	if len(segments) >= s.cfg.MaxDepth {
		return nil, errTooDeep
	}
	id := u.RootID
	for _, seg := range segments {
		name, err := validate.Name(seg)
		if err != nil {
			return nil, domain.ErrNotFound
		}
		child, err := s.store.GetChildByName(ctx, id, validate.NameKey(name))
		if err != nil {
			return nil, err
		}
		id = child.ID
	}
	return s.GetNode(ctx, p, id)
}
