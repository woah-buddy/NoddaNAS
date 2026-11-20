package service

import (
	"context"
	"errors"

	"github.com/woah-buddy/FrontDir/internal/domain"
	"github.com/woah-buddy/FrontDir/internal/e2ee"
)

// Signed version history (docs/E2EE.md §5c). Every new version carries a
// record signed by whoever stores it, naming the version before it. The
// server cannot forge records; it checks them so that an honest server
// keeps every file's chain consistent (each version follows the current
// one, one version per position) and refuses records that would only
// confuse clients. Clients verify everything again themselves.

var errNeedRecord = domain.E(domain.CodeInvalid,
	"new versions must carry a signed version record (update your FrontDir client)")

// checkRecord validates the record for a version about to be stored.
// nodeID is the file's ID; head is its current version (nil for a new
// file); restore is set for server-side restores, which must say so.
func (s *Service) checkRecord(ctx context.Context, p Principal, req *UploadRequest, nodeID string, head *domain.Version, prefix *e2ee.Prefix) (*e2ee.SignedRecord, error) {
	if len(req.Record) == 0 {
		return nil, errNeedRecord
	}
	r, err := e2ee.ParseRecord(req.Record, req.RecordSig)
	if err != nil {
		return nil, domain.E(domain.CodeInvalid, "malformed version record")
	}
	switch {
	case r.Node != nodeID:
		return nil, domain.E(domain.CodeInvalid, "the version record is about another file")
	case r.By != p.UserID:
		return nil, domain.E(domain.CodeInvalid, "the version record must be signed by you")
	case r.Container != e2ee.B64(prefix.Hash()):
		return nil, domain.E(domain.CodeInvalid, "the version record is about a different container")
	case r.Kind == e2ee.KindSave && prefix.Signer.User != p.UserID:
		return nil, domain.E(domain.CodeInvalid, "a version you did not encrypt can only be recorded as a restore")
	case req.restore && r.Kind != e2ee.KindRestore:
		return nil, domain.E(domain.CodeInvalid, "a restore must be recorded as one")
	case (req.dropID != "") != (r.Kind == e2ee.KindDrop):
		return nil, domain.E(domain.CodeInvalid, "only filing a mailbox drop is recorded as a drop")
	case r.Kind == e2ee.KindDrop && prefix.Signer.User != p.UserID:
		return nil, domain.E(domain.CodeInvalid, "whoever files a drop signs its container")
	}
	u, err := s.store.GetUser(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	if u.Keys == nil {
		return nil, domain.E(domain.CodePrecondition, "set up encryption first")
	}
	pub, err := e2ee.VerifyPublicKeys(u.ID, e2ee.PublicKeys{Enc: u.Keys.Enc, Sig: u.Keys.Sig}, u.Keys.SelfSig)
	if err != nil {
		return nil, err
	}
	if err := r.Verify(pub); err != nil {
		return nil, domain.E(domain.CodeInvalid, "the version record's signature does not verify")
	}
	// Its place in the chain: right after the current version.
	if head != nil && head.Seq > 0 {
		if r.Seq != head.Seq+1 || r.Prev != e2ee.B64(head.RecordHash) {
			return nil, domain.E(domain.CodePrecondition, "the file changed since your client read its history; reload and retry")
		}
	} else if r.Seq != 1 {
		return nil, domain.E(domain.CodePrecondition, "the file changed since your client read its history; reload and retry")
	}
	return r, nil
}

// currentVersion returns a file's current version, or nil for a file
// without one.
func (s *Service) currentVersion(ctx context.Context, n *domain.Node) (*domain.Version, error) {
	if n == nil || n.VersionID == "" {
		return nil, nil
	}
	v, err := s.store.GetVersion(ctx, n.ID, n.VersionID)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, nil
	}
	return v, err
}
