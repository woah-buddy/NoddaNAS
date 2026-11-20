package service

import (
	"context"
	"errors"
	"io"

	"github.com/woah-buddy/FrontDir/internal/domain"
	"github.com/woah-buddy/FrontDir/internal/e2ee"
)

// Attribution digests (docs/E2EE.md §5b). Uploads record each version's
// prefix, body hash and trailer as the bytes stream in; versions stored
// before that existed get theirs here, from the stored ciphertext, a few
// at a time on each maintenance run. It needs no keys.
//
// Replicas may occasionally digest the same version at once; the result is
// identical and only the first write is kept, so that wastes a little work
// and nothing else.

const digestsPerRun = 20

// backfillDigests digests up to limit versions that have no digest yet.
func (s *Service) backfillDigests(ctx context.Context, limit int) error {
	vs, err := s.store.VersionsWithoutDigest(ctx, limit)
	if err != nil {
		return err
	}
	for _, v := range vs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err := s.digestVersion(ctx, v)
		switch {
		case err == nil:
		case errors.Is(err, domain.ErrNotFound) || errors.Is(err, e2ee.ErrMalformed):
			// Missing or damaged: record that, so it is not retried forever.
			// Clients then show the author as unverifiable, and storage
			// verification (frontdir verify-storage) reports the damage.
			s.log.WarnContext(ctx, "version digest unavailable", "version", v.ID, "node", v.NodeID, "err", err)
			v.SignerID, v.Header, v.BodyHash, v.Trailer = "", nil, nil, nil
		default:
			return err // storage trouble: try again on the next run
		}
		if err := s.store.SetVersionDigest(ctx, v); err != nil {
			return err
		}
	}
	return nil
}

// digestVersion computes v's digest from its stored container.
func (s *Service) digestVersion(ctx context.Context, v *domain.Version) error {
	rc, err := s.blobs.Open(ctx, v.BlobKey)
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()
	p, err := e2ee.ParsePrefix(rc)
	if err != nil {
		return err
	}
	d := p.NewDigester()
	_, _ = d.Write(p.Raw())
	if _, err := io.Copy(d, rc); err != nil {
		return err
	}
	dg, err := d.Digest()
	if err != nil {
		return err
	}
	v.SignerID, v.Header, v.BodyHash, v.Trailer = p.Signer.User, dg.Header, dg.BodyHash, dg.Trailer
	return nil
}
