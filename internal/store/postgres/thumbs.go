package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/woah-buddy/FrontDir/internal/domain"
)

// PutThumbnail stores (or replaces) a maker's thumbnail for a version.
func (s *Store) PutThumbnail(ctx context.Context, t *domain.Thumbnail) error {
	_, err := s.db.Exec(ctx, `INSERT INTO thumbnails (version_id, maker_id, enc, sig, created_at) VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (version_id, maker_id) DO UPDATE SET enc = $3, sig = $4, created_at = $5`,
		t.VersionID, t.MakerID, t.Enc, t.Sig, t.CreatedAt)
	return mapErr(err)
}

// GetThumbnails returns a version's thumbnails by the given makers.
func (s *Store) GetThumbnails(ctx context.Context, versionID string, makers []string) ([]*domain.Thumbnail, error) {
	rows, err := s.db.Query(ctx, `SELECT version_id, maker_id, enc, sig, created_at FROM thumbnails
		WHERE version_id = $1 AND maker_id = ANY($2::text[]) ORDER BY maker_id`, versionID, makers)
	if err != nil {
		return nil, mapErr(err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (*domain.Thumbnail, error) {
		t := &domain.Thumbnail{}
		return t, r.Scan(&t.VersionID, &t.MakerID, &t.Enc, &t.Sig, &t.CreatedAt)
	})
	return out, mapErr(err)
}

// ThumbnailHints reports which versions have a thumbnail by their author
// (the signer their header names; the uploader for versions not yet
// backfilled) or by the viewer.
func (s *Store) ThumbnailHints(ctx context.Context, versionIDs []string, viewerID string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(versionIDs) == 0 {
		return out, nil
	}
	rows, err := s.db.Query(ctx, `SELECT DISTINCT t.version_id FROM thumbnails t JOIN versions v ON v.id = t.version_id
		WHERE t.version_id = ANY($1::text[]) AND (t.maker_id = COALESCE(v.signer_id, v.created_by) OR t.maker_id = $2)`, versionIDs, viewerID)
	if err != nil {
		return nil, mapErr(err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, mapErr(err)
	}
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}
