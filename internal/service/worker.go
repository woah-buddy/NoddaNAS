package service

import (
	"context"
	"errors"
	"time"

	"github.com/woah-buddy/FrontDir/internal/domain"
)

// Background maintenance runs inside every replica. Work is claimed through
// the database (FOR UPDATE SKIP LOCKED), so replicas cooperate without a
// separate queue service and no item is processed twice concurrently.

const purgeLease = 10 * time.Minute

// RunMaintenance expires old trash, purges scheduled nodes, deletes the
// leftovers of finished mailboxes and fills in missing version digests. It returns how many nodes were purged.
func (s *Service) RunMaintenance(ctx context.Context, maxPurges int) (int, error) {
	if n, err := s.store.ExpireTrash(ctx, s.now().Add(-s.conf().TrashRetention)); err != nil {
		return 0, err
	} else if n > 0 {
		s.log.InfoContext(ctx, "trash expired", "count", n)
	}
	purged := 0
	for purged < maxPurges && ctx.Err() == nil {
		n, err := s.store.ClaimPurge(ctx, purgeLease)
		if errors.Is(err, domain.ErrNotFound) {
			break
		} else if err != nil {
			return purged, err
		}
		if err := s.purge(ctx, n); err != nil {
			// The lease expires and another attempt picks it up later.
			s.log.ErrorContext(ctx, "purge failed", "node", n.ID, "err", err)
			continue
		}
		purged++
	}
	for ctx.Err() == nil {
		sp, err := s.store.ClaimDeletedSpace(ctx, purgeLease)
		if errors.Is(err, domain.ErrNotFound) {
			break
		} else if err != nil {
			return purged, err
		}
		if err := s.purgeSpace(ctx, sp); err != nil {
			s.log.ErrorContext(ctx, "space purge failed", "space", sp.ID, "err", err)
			break
		}
	}
	if err := s.expireMailboxes(ctx); err != nil && ctx.Err() == nil {
		s.log.ErrorContext(ctx, "mailbox expiry", "err", err)
	}
	if err := s.backfillDigests(ctx, digestsPerRun); err != nil && ctx.Err() == nil {
		s.log.ErrorContext(ctx, "version digests", "err", err)
	}
	return purged, nil
}

// purgeSpace permanently deletes a deleted team space: blobs first, then
// rows, so an interrupted purge is simply resumed.
func (s *Service) purgeSpace(ctx context.Context, sp *domain.Space) error {
	if err := s.purgeDrops(ctx, func() ([]*domain.Drop, error) { return s.store.SpaceDrops(ctx, sp.ID, 200) }); err != nil {
		return err
	}
	for ctx.Err() == nil {
		versions, err := s.store.SpaceVersions(ctx, sp.ID, 200)
		if err != nil {
			return err
		}
		if len(versions) == 0 {
			break
		}
		for _, v := range versions {
			if err := s.blobs.Delete(ctx, v.BlobKey); err != nil {
				return err
			}
		}
		if err := s.store.DeleteVersions(ctx, versions); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.store.DeleteSpace(ctx, sp.ID); err != nil {
		return err
	}
	s.log.InfoContext(ctx, "audit", "event", "space.purged", "space", sp.ID)
	return nil
}

// purge permanently deletes a node and everything under it. Each step is
// idempotent, so a crash or retry at any point converges on the same result.
// Blobs are deleted before their rows: if we stopped in between, the rows
// (and so the work) would still be found and retried.
func (s *Service) purge(ctx context.Context, n *domain.Node) error {
	// Mailboxes on the folders go with them, their pending drops first.
	if err := s.purgeDrops(ctx, func() ([]*domain.Drop, error) { return s.store.SubtreeDrops(ctx, n.ID, 200) }); err != nil {
		return err
	}
	for ctx.Err() == nil {
		versions, err := s.store.SubtreeVersions(ctx, n.ID, 200)
		if err != nil {
			return err
		}
		if len(versions) == 0 {
			break
		}
		for _, v := range versions {
			if err := s.blobs.Delete(ctx, v.BlobKey); err != nil {
				return err
			}
		}
		if err := s.store.DeleteVersions(ctx, versions); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.store.DeleteSubtree(ctx, n.ID); err != nil {
		return err
	}
	s.log.InfoContext(ctx, "audit", "event", "node.purged", "node", n.ID, "space", n.SpaceID)
	return nil
}

// RunWorker runs maintenance every interval until ctx is cancelled.
func (s *Service) RunWorker(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if _, err := s.RunMaintenance(ctx, 100); err != nil && ctx.Err() == nil {
			s.log.ErrorContext(ctx, "maintenance", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
