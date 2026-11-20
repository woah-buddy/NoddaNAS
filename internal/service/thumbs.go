package service

import (
	"context"
	"encoding/binary"
	"io"

	"github.com/woah-buddy/FrontDir/internal/domain"
	"github.com/woah-buddy/FrontDir/internal/validate"
)

// Thumbnails (docs/E2EE.md §5a): small client-encrypted previews attached
// to one version of a file, beside its container, so adding one never
// rewrites the file. The server stores them per version and per maker and
// can read none of them. Clients decide what to show (the version author's
// thumbnail, or their own), after verifying the maker's signature.

// Thumbnail size bounds, as encrypted: a 24 KiB image in its JSON wrapper,
// plus the nonce and tag.
const (
	thumbEncMax = 36 << 10
	thumbEncMin = 12 + 16 + 1
)

// AttachThumbnail stores the caller's thumbnail for a version of a file.
// Making previews is part of maintaining files, so it takes write access;
// a read-only credential cannot.
func (s *Service) AttachThumbnail(ctx context.Context, p Principal, nodeID, versionID, enc, sig string) error {
	a, err := s.authorize(ctx, p, nodeID, domain.PermWrite)
	if err != nil {
		return err
	}
	if a.node.Kind != domain.KindFile {
		return domain.E(domain.CodeInvalid, "not a file")
	}
	if validate.ID(versionID) != nil {
		return domain.ErrNotFound
	}
	if _, err := s.store.GetVersion(ctx, nodeID, versionID); err != nil {
		return err // the version must belong to this file
	}
	if err := firstErr(validate.Opaque("enc", enc, thumbEncMin, thumbEncMax), validate.Opaque("sig", sig, 64, 64)); err != nil {
		return err
	}
	return s.store.PutThumbnail(ctx, &domain.Thumbnail{VersionID: versionID, MakerID: p.UserID, Enc: enc, Sig: sig, CreatedAt: s.now()})
}

// ThumbnailSet is what a client needs to show a file's thumbnail: the
// current version's container prefix (it carries the salt, the key
// commitment and the author) and the thumbnails made by that version's
// uploader and by the caller.
type ThumbnailSet struct {
	VersionID  string
	Prefix     []byte
	Thumbnails []*domain.Thumbnail
}

// Thumbnails returns the thumbnails a client may show for a file's current
// version, or not-found if there are none.
func (s *Service) Thumbnails(ctx context.Context, p Principal, nodeID string) (*ThumbnailSet, error) {
	a, err := s.authorize(ctx, p, nodeID, domain.PermRead)
	if err != nil {
		return nil, err
	}
	if a.node.Kind != domain.KindFile || a.node.VersionID == "" {
		return nil, domain.ErrNotFound
	}
	v, err := s.store.GetVersion(ctx, nodeID, a.node.VersionID)
	if err != nil {
		return nil, err
	}
	thumbs, err := s.store.GetThumbnails(ctx, v.ID, []string{v.CreatedBy, p.UserID})
	if err != nil {
		return nil, err
	}
	if len(thumbs) == 0 {
		return nil, domain.ErrNotFound
	}
	rc, err := s.blobs.Open(ctx, v.BlobKey)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	var head [12]byte
	if _, err := io.ReadFull(rc, head[:]); err != nil {
		return nil, err
	}
	hl := binary.BigEndian.Uint32(head[8:])
	if hl == 0 || hl > 64<<10 {
		return nil, domain.E(domain.CodeInvalid, "stored container is malformed")
	}
	prefix := make([]byte, 12+int(hl))
	copy(prefix, head[:])
	if _, err := io.ReadFull(rc, prefix[12:]); err != nil {
		return nil, err
	}
	return &ThumbnailSet{VersionID: v.ID, Prefix: prefix, Thumbnails: thumbs}, nil
}

// markThumbnails sets the HasThumbnail hint on listed files.
func (s *Service) markThumbnails(ctx context.Context, p Principal, nodes []*domain.Node) error {
	var ids []string
	for _, n := range nodes {
		if n.Kind == domain.KindFile && n.VersionID != "" {
			ids = append(ids, n.VersionID)
		}
	}
	hints, err := s.store.ThumbnailHints(ctx, ids, p.UserID)
	if err != nil {
		return err
	}
	for _, n := range nodes {
		n.HasThumbnail = hints[n.VersionID]
	}
	return nil
}
