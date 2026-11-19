package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"path"
	"strings"

	"github.com/woah-buddy/NoddaNAS/internal/blobcrypt"
	"github.com/woah-buddy/NoddaNAS/internal/domain"
	"github.com/woah-buddy/NoddaNAS/internal/secure"
	"github.com/woah-buddy/NoddaNAS/internal/validate"
)

// UploadRequest describes file content arriving from a client. Either
// NodeID (new version of an existing file) or ParentID+Name (new file) is set.
type UploadRequest struct {
	ParentID  string
	Name      string
	Overwrite bool // if a file with Name exists, add a version instead of failing

	NodeID   string
	Revision int64 // optional: expected current revision of NodeID

	Size        int64  // declared size in bytes, or -1 if unknown
	SHA256      string // optional declared digest (hex); verified if given
	ContentType string
}

// uploadTarget is where an upload will land, resolved and authorized.
type uploadTarget struct {
	existing *domain.Node // nil for a new file
	parent   *domain.Node // for new files
	name     string
	ownerID  string
}

func (s *Service) resolveUploadTarget(ctx context.Context, p Principal, req *UploadRequest) (*uploadTarget, error) {
	if req.NodeID != "" {
		a, err := s.authorize(ctx, p, req.NodeID, domain.PermWrite)
		if err != nil {
			return nil, err
		}
		if a.node.Kind != domain.KindFile {
			return nil, domain.E(domain.CodeInvalid, "not a file")
		}
		return &uploadTarget{existing: a.node, name: a.node.Name, ownerID: a.node.OwnerID}, nil
	}
	name, err := validate.Name(req.Name)
	if err != nil {
		return nil, err
	}
	a, err := s.authorize(ctx, p, req.ParentID, domain.PermWrite)
	if err != nil {
		return nil, err
	}
	if a.node.Kind != domain.KindFolder {
		return nil, domain.E(domain.CodeInvalid, "parent is not a folder")
	}
	if len(a.chain) >= s.cfg.MaxDepth {
		return nil, errTooDeep
	}
	t := &uploadTarget{parent: a.node, name: name, ownerID: a.node.OwnerID}
	existing, err := s.store.GetChildByName(ctx, a.node.ID, validate.NameKey(name))
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return t, nil
	case err != nil:
		return nil, err
	case existing.Kind != domain.KindFile:
		return nil, domain.E(domain.CodeConflict, "a folder with that name already exists")
	case !req.Overwrite:
		return nil, &domain.Error{Code: domain.CodeConflict, Message: "a file with that name already exists",
			Detail: map[string]string{"existingId": existing.ID}}
	}
	t.existing = existing
	return t, nil
}

// errOverLimit signals that a body exceeded its allowed size.
var errOverLimit = errors.New("body exceeds allowed size")

// limitReader fails (rather than silently truncating like io.LimitReader)
// once more than n bytes have been read.
type limitReader struct {
	r    io.Reader
	n    int64
	read int64
}

func (l *limitReader) Read(p []byte) (int, error) {
	if int64(len(p)) > l.n-l.read+1 {
		p = p[:l.n-l.read+1]
	}
	k, err := l.r.Read(p)
	l.read += int64(k)
	if l.read > l.n {
		return k, errOverLimit
	}
	return k, err
}

// Upload stores new file content. The bytes are streamed (never buffered
// whole), size-limited, hashed and encrypted on the way to the blob store.
func (s *Service) Upload(ctx context.Context, p Principal, req UploadRequest, body io.Reader) (*domain.Node, error) {
	if req.SHA256 != "" {
		if err := validate.SHA256Hex(req.SHA256); err != nil {
			return nil, err
		}
	}
	if req.Size > s.cfg.MaxFileSize {
		return nil, domain.E(domain.CodeTooLarge, "file exceeds the maximum size")
	}
	target, err := s.resolveUploadTarget(ctx, p, &req)
	if err != nil {
		return nil, err
	}

	// Quota pre-check. This is advisory (it saves streaming gigabytes only
	// to be refused); the binding check is atomic, in CommitContent.
	owner, err := s.store.GetUser(ctx, target.ownerID)
	if err != nil {
		return nil, err
	}
	remaining := max(owner.QuotaBytes-owner.UsedBytes, 0)
	if req.Size > remaining {
		return nil, domain.E(domain.CodeQuota, "storage quota exceeded")
	}
	limit, quotaBound := s.cfg.MaxFileSize, false
	if remaining < limit {
		limit, quotaBound = remaining, true
	}
	if req.Size >= 0 {
		limit, quotaBound = req.Size, false
	}

	blobKey := secure.NewID()
	dek, wrapped, err := s.keys.NewDataKey(blobKey)
	if err != nil {
		return nil, err
	}
	lr := &limitReader{r: body, n: limit}
	h := sha256.New()
	enc, err := blobcrypt.NewEncryptReader(io.TeeReader(lr, h), dek)
	if err != nil {
		return nil, err
	}
	if _, err := s.blobs.Create(ctx, blobKey, enc); err != nil {
		_ = s.blobs.Delete(context.WithoutCancel(ctx), blobKey)
		if errors.Is(err, errOverLimit) {
			switch {
			case req.Size >= 0:
				return nil, domain.E(domain.CodeInvalid, "body is longer than the declared size")
			case quotaBound:
				return nil, domain.E(domain.CodeQuota, "storage quota exceeded")
			default:
				return nil, domain.E(domain.CodeTooLarge, "file exceeds the maximum size")
			}
		}
		return nil, err
	}
	fail := func(err error) (*domain.Node, error) {
		_ = s.blobs.Delete(context.WithoutCancel(ctx), blobKey)
		return nil, err
	}
	digest := hex.EncodeToString(h.Sum(nil))
	if req.Size >= 0 && lr.read != req.Size {
		return fail(domain.E(domain.CodeInvalid, "body is shorter than the declared size"))
	}
	if req.SHA256 != "" && !secure.Equal(digest, req.SHA256) {
		return fail(domain.E(domain.CodeInvalid, "content does not match the declared SHA-256"))
	}

	// Re-authorize: an upload can take minutes, and the caller's access may
	// have been revoked (or the folder trashed) while bytes were in flight.
	target, err = s.resolveUploadTarget(ctx, p, &req)
	if err != nil {
		return fail(err)
	}
	ctype := detectContentType(req.ContentType, target.name)
	v := &domain.Version{
		ID: secure.NewID(), OwnerID: target.ownerID, BlobKey: blobKey, WrappedKey: wrapped,
		Size: lr.read, SHA256: digest, CreatedAt: s.now(), CreatedBy: p.UserID,
	}
	n, err := s.commit(ctx, p, target, v, ctype, req.Revision)
	if err != nil {
		return fail(err)
	}
	s.audit(ctx, "file.upload", p, "node", n.ID, "version", v.ID, "size", v.Size, "owner", target.ownerID)
	s.pruneVersions(ctx, n)
	return n, nil
}

func (s *Service) commit(ctx context.Context, p Principal, t *uploadTarget, v *domain.Version, ctype string, rev int64) (*domain.Node, error) {
	var n domain.Node
	isNew := t.existing == nil
	if isNew {
		n = domain.Node{
			ID: secure.NewID(), OwnerID: t.ownerID, ParentID: t.parent.ID, Name: t.name, Kind: domain.KindFile,
			CreatedAt: v.CreatedAt, Revision: 1,
		}
	} else {
		n = *t.existing
		if rev == 0 {
			rev = n.Revision
		}
	}
	v.NodeID = n.ID
	n.Size, n.SHA256, n.VersionID, n.ContentType = v.Size, v.SHA256, v.ID, ctype
	n.ModifiedAt, n.ModifiedBy = v.CreatedAt, p.UserID
	if err := s.store.CommitContent(ctx, &n, validate.NameKey(n.Name), v, isNew, rev); err != nil {
		return nil, nameConflict(err)
	}
	return &n, nil
}

func detectContentType(declared, name string) string {
	ct := validate.ContentType(declared)
	if ct == "application/octet-stream" {
		if byExt := mime.TypeByExtension(strings.ToLower(path.Ext(name))); byExt != "" {
			ct = validate.ContentType(byExt)
		}
	}
	return ct
}

// pruneVersions keeps at most MaxVersions versions per file. The database
// row (which holds the only copy of the data key) is deleted first, so even
// if deleting the blob then fails, the leftover ciphertext is unreadable.
func (s *Service) pruneVersions(ctx context.Context, n *domain.Node) {
	vs, err := s.store.ListVersions(ctx, n.ID)
	if err != nil || len(vs) <= s.cfg.MaxVersions {
		return
	}
	var old []*domain.Version
	for _, v := range vs[s.cfg.MaxVersions:] {
		if v.ID != n.VersionID {
			old = append(old, v)
		}
	}
	if err := s.store.DeleteVersions(ctx, old); err != nil {
		s.log.ErrorContext(ctx, "prune versions", "node", n.ID, "err", err)
		return
	}
	for _, v := range old {
		if err := s.blobs.Delete(ctx, v.BlobKey); err != nil {
			s.log.WarnContext(ctx, "orphaned blob (already crypto-shredded)", "blob", v.BlobKey, "err", err)
		}
	}
}

// Content is an open, decrypting reader over one version of a file.
type Content struct {
	Node    *domain.Node
	Version *domain.Version
	io.ReadSeeker
	closer io.Closer
}

// Close releases the underlying blob.
func (c *Content) Close() error { return c.closer.Close() }

func (s *Service) openVersion(ctx context.Context, n *domain.Node, versionID string) (*Content, error) {
	if versionID == "" {
		versionID = n.VersionID
	}
	if err := validate.ID(versionID); err != nil {
		return nil, domain.ErrNotFound
	}
	v, err := s.store.GetVersion(ctx, n.ID, versionID)
	if err != nil {
		return nil, err
	}
	dek, err := s.keys.Unwrap(v.WrappedKey, v.BlobKey)
	if err != nil {
		return nil, err
	}
	rc, err := s.blobs.Open(ctx, v.BlobKey)
	if err != nil {
		return nil, err
	}
	r, err := blobcrypt.NewReader(rc, dek, v.Size)
	if err != nil {
		rc.Close()
		return nil, err
	}
	return &Content{Node: n, Version: v, ReadSeeker: r, closer: rc}, nil
}

// OpenContent opens a file version (current if versionID is "") for reading.
func (s *Service) OpenContent(ctx context.Context, p Principal, nodeID, versionID string) (*Content, error) {
	a, err := s.authorize(ctx, p, nodeID, domain.PermRead)
	if err != nil {
		return nil, err
	}
	if a.node.Kind != domain.KindFile {
		return nil, domain.E(domain.CodeInvalid, "not a file")
	}
	c, err := s.openVersion(ctx, a.node, versionID)
	if err == nil {
		s.audit(ctx, "file.download", p, "node", nodeID, "version", c.Version.ID)
	}
	return c, err
}

// ListVersions lists a file's stored versions, newest first.
func (s *Service) ListVersions(ctx context.Context, p Principal, nodeID string) ([]*domain.Version, error) {
	a, err := s.authorize(ctx, p, nodeID, domain.PermRead)
	if err != nil {
		return nil, err
	}
	if a.node.Kind != domain.KindFile {
		return nil, domain.E(domain.CodeInvalid, "not a file")
	}
	return s.store.ListVersions(ctx, nodeID)
}

// RestoreVersion makes an old version current again by storing it as a new
// version (re-encrypted under a fresh data key). History is never rewritten.
func (s *Service) RestoreVersion(ctx context.Context, p Principal, nodeID, versionID string) (*domain.Node, error) {
	a, err := s.authorize(ctx, p, nodeID, domain.PermWrite)
	if err != nil {
		return nil, err
	}
	if a.node.Kind != domain.KindFile {
		return nil, domain.E(domain.CodeInvalid, "not a file")
	}
	old, err := s.openVersion(ctx, a.node, versionID)
	if err != nil {
		return nil, err
	}
	defer old.Close()
	n, err := s.Upload(ctx, p, UploadRequest{
		NodeID: nodeID, Revision: a.node.Revision, Size: old.Version.Size, SHA256: old.Version.SHA256,
		ContentType: a.node.ContentType,
	}, old)
	if err == nil {
		s.audit(ctx, "file.version_restore", p, "node", nodeID, "from_version", versionID)
	}
	return n, err
}
