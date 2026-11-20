package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"github.com/woah-buddy/FrontDir/internal/domain"
	"github.com/woah-buddy/FrontDir/internal/e2ee"
	"github.com/woah-buddy/FrontDir/internal/secure"
	"github.com/woah-buddy/FrontDir/internal/validate"
)

// UploadRequest describes an end-to-end encrypted container arriving from a
// client. Either NewID+ParentID+Entry (a new file) or NodeID (a new version
// of an existing file) is set.
type UploadRequest struct {
	ParentID string
	NewID    string
	Entry    EntryFields

	NodeID   string
	Revision int64

	Size int64 // declared Content-Length, or -1 if unknown

	// The signed version record (docs/E2EE.md §5c) and its signature.
	Record, RecordSig []byte

	restore bool // a server-side restore: the record must say so
}

type uploadTarget struct {
	existing *domain.Node // nil for a new file
	parent   *domain.Node
	space    *domain.Space
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
		return &uploadTarget{existing: a.node, space: a.space}, nil
	}
	if err := validate.ID(req.NewID); err != nil {
		return nil, err
	}
	if err := req.Entry.validate(true); err != nil {
		return nil, err
	}
	a, err := s.authorize(ctx, p, req.ParentID, domain.PermWrite)
	if err != nil {
		return nil, err
	}
	if a.node.Kind != domain.KindFolder {
		return nil, domain.E(domain.CodeInvalid, "parent is not a folder")
	}
	if len(a.chain) >= s.conf().MaxDepth {
		return nil, errTooDeep
	}
	if _, err := s.store.GetChildByHash(ctx, a.node.ID, req.Entry.NameHash); err == nil {
		return nil, s.nameConflict(ctx, domain.ErrConflict, a.node.ID, req.Entry.NameHash)
	} else if !errors.Is(err, domain.ErrNotFound) {
		return nil, err
	}
	return &uploadTarget{parent: a.node, space: a.space}, nil
}

// limitReader fails (rather than silently truncating) past n bytes.
type limitReader struct {
	r    io.Reader
	n    int64
	read int64
}

var errOverLimit = errors.New("body exceeds the container's declared size")

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

// Upload stores a client-encrypted container. The server cannot decrypt
// it; it checks the container's structure (version, algorithm, owning space)
// and exact length, hashes it, and charges its size to the space's quota.
func (s *Service) Upload(ctx context.Context, p Principal, req UploadRequest, body io.Reader) (*domain.Node, error) {
	target, err := s.resolveUploadTarget(ctx, p, &req)
	if err != nil {
		return nil, err
	}
	var head bytes.Buffer
	prefix, err := e2ee.ParsePrefix(io.TeeReader(io.LimitReader(body, 12+e2ee.MaxHeaderLen), &head))
	if err != nil {
		return nil, domain.E(domain.CodeInvalid, "body is not a valid FrontDir encrypted container")
	}
	if prefix.Owner.Space != target.space.ID {
		return nil, domain.E(domain.CodeInvalid, "the container is sealed to a different space")
	}
	if validate.ID(prefix.Signer.User) != nil {
		return nil, domain.E(domain.CodeInvalid, "the container does not name a valid signer")
	}
	nodeID := req.NewID
	if target.existing != nil {
		nodeID = target.existing.ID
	}
	current, err := s.currentVersion(ctx, target.existing)
	if err != nil {
		return nil, err
	}
	record, err := s.checkRecord(ctx, p, &req, nodeID, current, prefix)
	if err != nil {
		return nil, err
	}
	total := prefix.TotalSize()
	switch {
	case req.Size >= 0 && req.Size != total:
		return nil, domain.E(domain.CodeInvalid, "Content-Length does not match the container's declared size")
	case total > s.conf().MaxFileSize:
		return nil, domain.E(domain.CodeTooLarge, "file exceeds the maximum size")
	case total > target.space.QuotaBytes-target.space.UsedBytes:
		return nil, domain.E(domain.CodeQuota, "storage quota exceeded") // advisory; the binding check is atomic
	}

	blobKey := secure.NewID()
	lr := &limitReader{r: io.MultiReader(&head, body), n: total}
	h := sha256.New()
	dg := prefix.NewDigester() // attribution digest (docs/E2EE.md §5b), in the same pass
	if _, err := s.blobs.Create(ctx, blobKey, io.TeeReader(lr, io.MultiWriter(h, dg))); err != nil {
		_ = s.blobs.Delete(context.WithoutCancel(ctx), blobKey)
		if errors.Is(err, errOverLimit) {
			return nil, domain.E(domain.CodeInvalid, "body is longer than the container's declared size")
		}
		return nil, err
	}
	fail := func(err error) (*domain.Node, error) {
		_ = s.blobs.Delete(context.WithoutCancel(ctx), blobKey)
		return nil, err
	}
	if lr.read != total {
		return fail(domain.E(domain.CodeInvalid, "body is shorter than the container's declared size"))
	}
	digest, err := dg.Digest()
	if err != nil { // cannot happen once the length matched; refuse rather than store a version without it
		return fail(err)
	}
	// Re-authorize: the upload may have taken minutes, and access may have
	// been revoked (or the folder trashed) while bytes were in flight.
	if target, err = s.resolveUploadTarget(ctx, p, &req); err != nil {
		return fail(err)
	}
	now := s.now()
	v := &domain.Version{ID: secure.NewID(), SpaceID: target.space.ID, BlobKey: blobKey, Size: total,
		SHA256: hex.EncodeToString(h.Sum(nil)), CreatedAt: now, CreatedBy: p.UserID,
		SignerID: prefix.Signer.User, Header: digest.Header, BodyHash: digest.BodyHash, Trailer: digest.Trailer,
		Record: record.Raw, RecordSig: record.Sig, Seq: record.Seq, RecordHash: record.Hash()}
	n, err := s.commit(ctx, p, target, &req, v, prefix.Size)
	if err != nil {
		return fail(err)
	}
	s.audit(ctx, "file.upload", p, "node", n.ID, "version", v.ID, "size", v.Size, "space", v.SpaceID)
	s.pruneVersions(ctx, n)
	return n, nil
}

func (s *Service) commit(ctx context.Context, p Principal, t *uploadTarget, req *UploadRequest, v *domain.Version, plainSize int64) (*domain.Node, error) {
	var n domain.Node
	isNew := t.existing == nil
	rev := req.Revision
	if isNew {
		n = domain.Node{ID: req.NewID, SpaceID: t.space.ID, ParentID: t.parent.ID, Kind: domain.KindFile,
			NameEnc: req.Entry.NameEnc, NameHash: req.Entry.NameHash, WrappedKey: req.Entry.WrappedKey,
			CreatedAt: v.CreatedAt, CreatedBy: p.UserID, Revision: 1}
	} else {
		n = *t.existing
		if rev == 0 {
			rev = n.Revision
		}
	}
	v.NodeID = n.ID
	n.Size, n.PlainSize, n.SHA256, n.VersionID, n.ModifiedAt, n.ModifiedBy = v.Size, plainSize, v.SHA256, v.ID, v.CreatedAt, p.UserID
	if err := s.store.CommitContent(ctx, &n, v, isNew, rev); err != nil {
		if isNew {
			return nil, s.nameConflict(ctx, err, n.ParentID, n.NameHash)
		}
		return nil, err
	}
	return &n, nil
}

// pruneVersions keeps at most MaxVersions versions per file.
func (s *Service) pruneVersions(ctx context.Context, n *domain.Node) {
	vs, err := s.store.ListVersions(ctx, n.ID)
	if err != nil || len(vs) <= s.conf().MaxVersions {
		return
	}
	var old []*domain.Version
	for _, v := range vs[s.conf().MaxVersions:] {
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
			s.log.WarnContext(ctx, "orphaned blob", "blob", v.BlobKey, "err", err)
		}
	}
}

// Content is one stored container, open for reading. It is ciphertext: the
// client decrypts it.
type Content struct {
	Node    *domain.Node
	Version *domain.Version
	io.ReadSeekCloser
}

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
	rc, err := s.blobs.Open(ctx, v.BlobKey)
	if err != nil {
		return nil, err
	}
	return &Content{Node: n, Version: v, ReadSeekCloser: rc}, nil
}

// OpenContent opens a file version (current if versionID is "").
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
	vs, err := s.store.ListVersions(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	// Versions stored before digests were recorded and not backfilled yet:
	// the prefix alone is cheap to read, and clients need it to restore
	// such a version (their record names its container).
	for _, v := range vs {
		if len(v.Header) == 0 && v.BodyHash == nil {
			if h, err := s.readPrefix(ctx, v); err == nil {
				v.Header = h
			}
		}
	}
	return vs, nil
}

// RestoreVersion makes an old version current again by storing a copy of
// its container as a new version. The container is unchanged (still
// encrypted, still decryptable with the file's key); history is preserved.
func (s *Service) RestoreVersion(ctx context.Context, p Principal, nodeID, versionID string, record, recordSig []byte) (*domain.Node, error) {
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
	n, err := s.Upload(ctx, p, UploadRequest{NodeID: nodeID, Revision: a.node.Revision, Size: old.Version.Size,
		Record: record, RecordSig: recordSig, restore: true}, old)
	if err == nil {
		s.audit(ctx, "file.version_restore", p, "node", nodeID, "from_version", versionID)
	}
	return n, err
}
