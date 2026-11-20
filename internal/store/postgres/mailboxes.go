package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/woah-buddy/FrontDir/internal/domain"
)

// File mailboxes (docs/E2EE.md §6a).

const mailboxCols = `m.id, m.node_id, m.space_id, m.created_by, m.created_at, m.token_hash, m.box_key, m.info,
	m.password_hash, m.expires_at, m.max_bytes, m.max_files, m.auto_file, m.closed_at, m.used_bytes, m.used_files,
	m.failed_attempts, m.locked_until,
	(SELECT count(*) FROM mailbox_drops d WHERE d.mailbox_id = m.id),
	(SELECT coalesce(sum(d.size), 0) FROM mailbox_drops d WHERE d.mailbox_id = m.id)`

func scanMailbox(row pgx.Row) (*domain.Mailbox, error) {
	m := &domain.Mailbox{}
	err := row.Scan(&m.ID, &m.NodeID, &m.SpaceID, &m.CreatedBy, &m.CreatedAt, &m.TokenHash, &m.BoxKey, &m.Info,
		&m.PasswordHash, &m.ExpiresAt, &m.MaxBytes, &m.MaxFiles, &m.AutoFile, &m.ClosedAt, &m.UsedBytes, &m.UsedFiles,
		&m.FailedAttempts, &m.LockedUntil, &m.PendingFiles, &m.PendingBytes)
	return m, mapErr(err)
}

func (s *Store) queryMailboxes(ctx context.Context, where string, args ...any) ([]*domain.Mailbox, error) {
	rows, err := s.db.Query(ctx, "SELECT "+mailboxCols+" FROM mailboxes m WHERE "+where, args...)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []*domain.Mailbox
	for rows.Next() {
		m, err := scanMailbox(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, mapErr(rows.Err())
}

func (s *Store) CreateMailbox(ctx context.Context, m *domain.Mailbox) error {
	_, err := s.db.Exec(ctx, `INSERT INTO mailboxes (id, node_id, space_id, created_by, created_at, token_hash, box_key, info,
			password_hash, expires_at, max_bytes, max_files, auto_file) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		m.ID, m.NodeID, m.SpaceID, m.CreatedBy, m.CreatedAt, m.TokenHash, m.BoxKey, m.Info, m.PasswordHash, m.ExpiresAt,
		m.MaxBytes, m.MaxFiles, m.AutoFile)
	return mapErr(err)
}

func (s *Store) GetMailbox(ctx context.Context, id string) (*domain.Mailbox, error) {
	return scanMailbox(s.db.QueryRow(ctx, "SELECT "+mailboxCols+" FROM mailboxes m WHERE m.id=$1", id))
}

func (s *Store) GetMailboxByTokenHash(ctx context.Context, hash string) (*domain.Mailbox, error) {
	return scanMailbox(s.db.QueryRow(ctx, "SELECT "+mailboxCols+" FROM mailboxes m WHERE m.token_hash=$1", hash))
}

func (s *Store) ListMailboxesByNode(ctx context.Context, nodeID string) ([]*domain.Mailbox, error) {
	return s.queryMailboxes(ctx, "m.node_id=$1 ORDER BY m.created_at DESC", nodeID)
}

func (s *Store) ListMailboxesByCreator(ctx context.Context, userID string, limit int) ([]*domain.Mailbox, error) {
	return s.queryMailboxes(ctx, "m.created_by=$1 ORDER BY m.created_at DESC LIMIT $2", userID, limit)
}

// CloseMailbox stops a mailbox accepting drops; pending drops stay.
func (s *Store) CloseMailbox(ctx context.Context, id string, now time.Time) error {
	_, err := s.db.Exec(ctx, "UPDATE mailboxes SET closed_at=$2 WHERE id=$1 AND closed_at IS NULL", id, now)
	return mapErr(err)
}

// CloseMailboxesByCreator closes every open mailbox the user created (the
// per-user kill switch), in one statement.
func (s *Store) CloseMailboxesByCreator(ctx context.Context, userID string, now time.Time) (int64, error) {
	tag, err := s.db.Exec(ctx, "UPDATE mailboxes SET closed_at=$2 WHERE created_by=$1 AND closed_at IS NULL", userID, now)
	if err != nil {
		return 0, mapErr(err)
	}
	return tag.RowsAffected(), nil
}

// CloseAllMailboxes closes every open mailbox (the instance-wide kill
// switch). Separate from the per-user method so that no input can widen it.
func (s *Store) CloseAllMailboxes(ctx context.Context, now time.Time) (int64, error) {
	tag, err := s.db.Exec(ctx, "UPDATE mailboxes SET closed_at=$1 WHERE closed_at IS NULL", now)
	if err != nil {
		return 0, mapErr(err)
	}
	return tag.RowsAffected(), nil
}

func (s *Store) RecordMailboxFailure(ctx context.Context, id string, threshold int64, until time.Time) error {
	_, err := s.db.Exec(ctx, `UPDATE mailboxes SET
			locked_until    = CASE WHEN failed_attempts + 1 >= $2 THEN $3 ELSE locked_until END,
			failed_attempts = CASE WHEN failed_attempts + 1 >= $2 THEN 0 ELSE failed_attempts + 1 END
		WHERE id=$1`, id, threshold, until)
	return mapErr(err)
}

func (s *Store) ResetMailboxFailures(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, "UPDATE mailboxes SET failed_attempts=0 WHERE id=$1 AND failed_attempts <> 0", id)
	return mapErr(err)
}

// ErrMailboxFull is returned when a drop would exceed the mailbox's limits
// (or the mailbox closed or expired meanwhile).
var ErrMailboxFull = domain.E(domain.CodeQuota, "this mailbox is full or no longer accepts files")

// CreateDrop records a drop whose blob is stored. The mailbox's limits and
// the space's quota are checked and charged in the same transaction.
func (s *Store) CreateDrop(ctx context.Context, d *domain.Drop, now time.Time) error {
	return mapErr(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE mailboxes SET used_bytes = used_bytes + $2, used_files = used_files + 1
			WHERE id=$1 AND closed_at IS NULL AND expires_at > $3 AND used_bytes + $2 <= max_bytes AND used_files + 1 <= max_files`,
			d.MailboxID, d.Size, now)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrMailboxFull
		}
		tag, err = tx.Exec(ctx, `UPDATE spaces SET used_bytes = used_bytes + $2
			WHERE id=$1 AND used_bytes + $2 <= quota_bytes AND deleted_at IS NULL`, d.SpaceID, d.Size)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrMailboxFull // the owner's storage is full; senders learn no more than that
		}
		_, err = tx.Exec(ctx, `INSERT INTO mailbox_drops (id, mailbox_id, space_id, blob_key, size, plain_size, header,
				body_hash, sha256, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			d.ID, d.MailboxID, d.SpaceID, d.BlobKey, d.Size, d.PlainSize, d.Header, d.BodyHash, d.SHA256, d.CreatedAt)
		return err
	}))
}

const dropCols = "id, mailbox_id, space_id, blob_key, size, plain_size, header, body_hash, sha256, created_at"

func scanDrops(rows pgx.Rows, err error) ([]*domain.Drop, error) {
	if err != nil {
		return nil, mapErr(err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (*domain.Drop, error) {
		d := &domain.Drop{}
		return d, r.Scan(&d.ID, &d.MailboxID, &d.SpaceID, &d.BlobKey, &d.Size, &d.PlainSize, &d.Header, &d.BodyHash, &d.SHA256, &d.CreatedAt)
	})
	return out, mapErr(err)
}

func (s *Store) ListDrops(ctx context.Context, mailboxID string, limit int) ([]*domain.Drop, error) {
	return scanDrops(s.db.Query(ctx, "SELECT "+dropCols+" FROM mailbox_drops WHERE mailbox_id=$1 ORDER BY created_at, id LIMIT $2", mailboxID, limit))
}

func (s *Store) GetDrop(ctx context.Context, mailboxID, dropID string) (*domain.Drop, error) {
	ds, err := scanDrops(s.db.Query(ctx, "SELECT "+dropCols+" FROM mailbox_drops WHERE mailbox_id=$1 AND id=$2", mailboxID, dropID))
	if err != nil {
		return nil, err
	}
	if len(ds) == 0 {
		return nil, domain.ErrNotFound
	}
	return ds[0], nil
}

// DeleteDrop removes a drop's row and refunds its size to the space. The
// caller deletes the blob (before, for purges; after, for discards).
func (s *Store) DeleteDrop(ctx context.Context, d *domain.Drop) error {
	return mapErr(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		return consumeDrop(ctx, tx, d.ID, d.SpaceID)
	}))
}

// consumeDrop deletes a drop row and refunds its size, inside tx.
func consumeDrop(ctx context.Context, tx pgx.Tx, dropID, spaceID string) error {
	var size int64
	err := tx.QueryRow(ctx, "DELETE FROM mailbox_drops WHERE id=$1 AND space_id=$2 RETURNING size", dropID, spaceID).Scan(&size)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.E(domain.CodePrecondition, "this drop was already filed or discarded")
	}
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "UPDATE spaces SET used_bytes = greatest(used_bytes - $2, 0) WHERE id=$1", spaceID, size)
	return err
}

// FinishedMailboxes returns mailboxes closed or expired before the given
// time (their pending drops are due for deletion).
func (s *Store) FinishedMailboxes(ctx context.Context, before time.Time, limit int) ([]*domain.Mailbox, error) {
	return s.queryMailboxes(ctx, "(m.closed_at < $1 OR m.expires_at < $1) ORDER BY m.id LIMIT $2", before, limit)
}

// DeleteMailbox removes a mailbox with no pending drops.
func (s *Store) DeleteMailbox(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, "DELETE FROM mailboxes WHERE id=$1 AND NOT EXISTS (SELECT 1 FROM mailbox_drops WHERE mailbox_id=$1)", id)
	return mapErr(err)
}

// SubtreeDrops returns pending drops of mailboxes on a folder subtree (for
// permanent deletion: their blobs go first).
func (s *Store) SubtreeDrops(ctx context.Context, rootID string, limit int) ([]*domain.Drop, error) {
	return scanDrops(s.db.Query(ctx, subtreeCTE+"SELECT "+dropCols+` FROM mailbox_drops WHERE mailbox_id IN
		(SELECT id FROM mailboxes WHERE node_id IN (SELECT id FROM sub)) LIMIT $2`, rootID, limit))
}

// SpaceDrops returns pending drops in a space (for deleting the space).
func (s *Store) SpaceDrops(ctx context.Context, spaceID string, limit int) ([]*domain.Drop, error) {
	return scanDrops(s.db.Query(ctx, "SELECT "+dropCols+" FROM mailbox_drops WHERE space_id=$1 LIMIT $2", spaceID, limit))
}
