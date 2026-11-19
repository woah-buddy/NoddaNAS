// Package postgres implements NoddaNAS's metadata store on PostgreSQL.
//
// Every query is parameterized (no string-built SQL with user input), and
// every rule the service relies on for safety (name uniqueness, quota,
// optimistic concurrency, "links are read-only") is enforced inside the same
// statement or transaction as the write, so concurrent requests cannot race
// past it.
package postgres

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/woah-buddy/NoddaNAS/internal/domain"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store is a PostgreSQL-backed store.
type Store struct {
	db *pgxpool.Pool
}

// Open connects to PostgreSQL. The DSN should require TLS (sslmode=verify-full)
// whenever the database is not on a private, trusted network.
func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: invalid DSN: %w", err)
	}
	cfg.ConnConfig.RuntimeParams["application_name"] = "noddanas"
	// A runaway query should fail rather than tie up a connection forever.
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = "30000"
	cfg.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = "60000"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &Store{db: pool}, nil
}

// Close releases all connections.
func (s *Store) Close() { s.db.Close() }

// Ping checks connectivity (used by readiness checks).
func (s *Store) Ping(ctx context.Context) error { return s.db.Ping(ctx) }

// Migrate applies pending migrations. A Postgres advisory lock serializes
// migrations, so many replicas can start at once safely.
func (s *Store) Migrate(ctx context.Context) error {
	conn, err := s.db.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	const lockID = 0x4e444e53 // "NDNS"
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		return err
	}
	defer conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", lockID)

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	files, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(files)
	for _, f := range files {
		base := strings.TrimPrefix(f, "migrations/")
		v, err := strconv.Atoi(strings.SplitN(base, "_", 2)[0])
		if err != nil {
			return fmt.Errorf("postgres: bad migration name %q", base)
		}
		var applied bool
		if err := conn.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)", v).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		sql, err := migrations.ReadFile(f)
		if err != nil {
			return err
		}
		err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(sql)); err != nil {
				return fmt.Errorf("migration %s: %w", base, err)
			}
			_, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", v)
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// ---- error mapping -------------------------------------------------------

func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			return domain.E(domain.CodeConflict, "already exists")
		case "23503": // foreign_key_violation
			return domain.E(domain.CodePrecondition, "referenced item changed")
		}
	}
	return err
}

func isUniqueViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == constraint
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ---- users ---------------------------------------------------------------

const userCols = `id, issuer, subject, coalesce(email, ''), display_name, root_id, quota_bytes, used_bytes, created_at`

func scanUser(row pgx.Row) (*domain.User, error) {
	u := &domain.User{}
	err := row.Scan(&u.ID, &u.Issuer, &u.Subject, &u.Email, &u.DisplayName, &u.RootID, &u.QuotaBytes, &u.UsedBytes, &u.CreatedAt)
	return u, mapErr(err)
}

func (s *Store) GetUser(ctx context.Context, id string) (*domain.User, error) {
	return scanUser(s.db.QueryRow(ctx, "SELECT "+userCols+" FROM users WHERE id=$1", id))
}

func (s *Store) GetUserByIdentity(ctx context.Context, issuer, subject string) (*domain.User, error) {
	return scanUser(s.db.QueryRow(ctx, "SELECT "+userCols+" FROM users WHERE issuer=$1 AND subject=$2", issuer, subject))
}

func (s *Store) GetUserIDByEmail(ctx context.Context, email string) (string, error) {
	var id string
	err := s.db.QueryRow(ctx, "SELECT id FROM users WHERE email=$1", email).Scan(&id)
	return id, mapErr(err)
}

func (s *Store) CreateUser(ctx context.Context, u *domain.User, root *domain.Node) error {
	insert := func(email string) error {
		return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO users (id, issuer, subject, email, display_name, root_id, quota_bytes, used_bytes, created_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7,0,$8)`,
				u.ID, u.Issuer, u.Subject, nullable(email), u.DisplayName, u.RootID, u.QuotaBytes, u.CreatedAt)
			if err != nil {
				return err
			}
			return insertNode(ctx, tx, root, "")
		})
	}
	err := insert(u.Email)
	if isUniqueViolation(err, "users_email_key") {
		// Another account already holds this email. Never let a second
		// account capture shares addressed to it: store no email instead.
		u.Email = ""
		err = insert("")
	}
	return mapErr(err)
}

func (s *Store) UpdateUserProfile(ctx context.Context, id, email, displayName string) error {
	_, err := s.db.Exec(ctx, "UPDATE users SET email=$2, display_name=$3 WHERE id=$1", id, nullable(email), displayName)
	if isUniqueViolation(err, "users_email_key") {
		_, err = s.db.Exec(ctx, "UPDATE users SET email=NULL, display_name=$2 WHERE id=$1", id, displayName)
	}
	return mapErr(err)
}

func (s *Store) SetQuota(ctx context.Context, userID string, quota int64) error {
	tag, err := s.db.Exec(ctx, "UPDATE users SET quota_bytes=$2 WHERE id=$1", userID, quota)
	if err == nil && tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return mapErr(err)
}

// ---- nodes ---------------------------------------------------------------

const nodeCols = `id, owner_id, coalesce(parent_id, ''), name, kind, size, content_type, sha256,
	coalesce(version_id, ''), created_at, modified_at, modified_by, revision, trashed_at`

func scanNode(row pgx.Row) (*domain.Node, error) {
	n := &domain.Node{}
	var kind string
	err := row.Scan(&n.ID, &n.OwnerID, &n.ParentID, &n.Name, &kind, &n.Size, &n.ContentType, &n.SHA256,
		&n.VersionID, &n.CreatedAt, &n.ModifiedAt, &n.ModifiedBy, &n.Revision, &n.TrashedAt)
	n.Kind = domain.Kind(kind)
	return n, mapErr(err)
}

func scanNodes(rows pgx.Rows) ([]*domain.Node, error) {
	defer rows.Close()
	var out []*domain.Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, mapErr(rows.Err())
}

func insertNode(ctx context.Context, tx pgx.Tx, n *domain.Node, nameKey string) error {
	_, err := tx.Exec(ctx, `INSERT INTO nodes (id, owner_id, parent_id, name, name_key, kind, size, content_type, sha256,
			version_id, created_at, modified_at, modified_by, revision)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		n.ID, n.OwnerID, nullable(n.ParentID), n.Name, nameKey, string(n.Kind), n.Size, n.ContentType, n.SHA256,
		nullable(n.VersionID), n.CreatedAt, n.ModifiedAt, n.ModifiedBy, n.Revision)
	return err
}

func (s *Store) GetNode(ctx context.Context, id string) (*domain.Node, error) {
	return scanNode(s.db.QueryRow(ctx, "SELECT "+nodeCols+" FROM nodes WHERE id=$1", id))
}

func (s *Store) GetAncestry(ctx context.Context, id string, max int) ([]*domain.Node, error) {
	rows, err := s.db.Query(ctx, `
		WITH RECURSIVE anc AS (
			SELECT nodes.*, 0 AS depth FROM nodes WHERE id = $1
			UNION ALL
			SELECT n.*, anc.depth + 1 FROM nodes n JOIN anc ON n.id = anc.parent_id WHERE anc.depth + 1 < $2
		)
		SELECT `+nodeCols+` FROM anc ORDER BY depth`, id, max)
	if err != nil {
		return nil, mapErr(err)
	}
	nodes, err := scanNodes(rows)
	if err == nil && len(nodes) == 0 {
		return nil, domain.ErrNotFound
	}
	return nodes, err
}

func (s *Store) GetChildByName(ctx context.Context, parentID, nameKey string) (*domain.Node, error) {
	return scanNode(s.db.QueryRow(ctx, "SELECT "+nodeCols+
		" FROM nodes WHERE parent_id=$1 AND name_key=$2 AND trashed_at IS NULL", parentID, nameKey))
}

func (s *Store) ListChildren(ctx context.Context, parentID, cursor string, limit int) ([]*domain.Node, string, error) {
	rows, err := s.db.Query(ctx, "SELECT "+nodeCols+`, name_key FROM nodes
		WHERE parent_id=$1 AND trashed_at IS NULL AND name_key > $2
		ORDER BY name_key LIMIT $3`, parentID, cursor, limit+1)
	if err != nil {
		return nil, "", mapErr(err)
	}
	defer rows.Close()
	var out []*domain.Node
	var keys []string
	for rows.Next() {
		n := &domain.Node{}
		var kind, key string
		if err := rows.Scan(&n.ID, &n.OwnerID, &n.ParentID, &n.Name, &kind, &n.Size, &n.ContentType, &n.SHA256,
			&n.VersionID, &n.CreatedAt, &n.ModifiedAt, &n.ModifiedBy, &n.Revision, &n.TrashedAt, &key); err != nil {
			return nil, "", mapErr(err)
		}
		n.Kind = domain.Kind(kind)
		out = append(out, n)
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, "", mapErr(err)
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = keys[limit-1]
	}
	return out, next, nil
}

func (s *Store) CreateFolder(ctx context.Context, n *domain.Node, nameKey string) error {
	return mapErr(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		return insertNode(ctx, tx, n, nameKey)
	}))
}

func (s *Store) UpdateNodeLocation(ctx context.Context, n *domain.Node, nameKey string, expectedRev int64) error {
	tag, err := s.db.Exec(ctx, `UPDATE nodes SET parent_id=$2, name=$3, name_key=$4, modified_at=$5, modified_by=$6,
			revision = revision + 1
		WHERE id=$1 AND revision=$7 AND trashed_at IS NULL AND parent_id IS NOT NULL`,
		n.ID, n.ParentID, n.Name, nameKey, n.ModifiedAt, n.ModifiedBy, expectedRev)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return domain.E(domain.CodePrecondition, "the item was changed by someone else; reload and retry")
	}
	n.Revision = expectedRev + 1
	return nil
}

func (s *Store) TrashNode(ctx context.Context, n *domain.Node, at time.Time, expectedRev int64) error {
	tag, err := s.db.Exec(ctx, `UPDATE nodes SET trashed_at=$2, revision = revision + 1
		WHERE id=$1 AND revision=$3 AND trashed_at IS NULL AND parent_id IS NOT NULL`, n.ID, at, expectedRev)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return domain.E(domain.CodePrecondition, "the item was changed by someone else; reload and retry")
	}
	n.TrashedAt, n.Revision = &at, expectedRev+1
	return nil
}

func (s *Store) RestoreNode(ctx context.Context, n *domain.Node, nameKey string) error {
	tag, err := s.db.Exec(ctx, `UPDATE nodes SET trashed_at=NULL, parent_id=$2, name=$3, name_key=$4,
			revision = revision + 1
		WHERE id=$1 AND trashed_at IS NOT NULL AND NOT purging`, n.ID, n.ParentID, n.Name, nameKey)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	n.TrashedAt = nil
	n.Revision++
	return nil
}

func (s *Store) ListTrash(ctx context.Context, ownerID string) ([]*domain.Node, error) {
	rows, err := s.db.Query(ctx, "SELECT "+nodeCols+` FROM nodes
		WHERE owner_id=$1 AND trashed_at IS NOT NULL AND NOT purging ORDER BY trashed_at DESC LIMIT 1000`, ownerID)
	if err != nil {
		return nil, mapErr(err)
	}
	return scanNodes(rows)
}

func (s *Store) MarkPurging(ctx context.Context, nodeID string) error {
	tag, err := s.db.Exec(ctx, `UPDATE nodes SET purging=true, purge_lease=NULL
		WHERE id=$1 AND trashed_at IS NOT NULL AND NOT purging`, nodeID)
	if err == nil && tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return mapErr(err)
}

func (s *Store) ExpireTrash(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := s.db.Exec(ctx, `UPDATE nodes SET purging=true, purge_lease=NULL
		WHERE trashed_at < $1 AND NOT purging`, cutoff)
	return tag.RowsAffected(), mapErr(err)
}

func (s *Store) ClaimPurge(ctx context.Context, lease time.Duration) (*domain.Node, error) {
	// FOR UPDATE SKIP LOCKED turns the nodes table into a work queue that any
	// number of replicas can drain concurrently without double-processing.
	return scanNode(s.db.QueryRow(ctx, `UPDATE nodes SET purge_lease = now() + $1::interval
		WHERE id = (
			SELECT id FROM nodes
			WHERE purging AND (purge_lease IS NULL OR purge_lease < now())
			ORDER BY purge_lease NULLS FIRST LIMIT 1
			FOR UPDATE SKIP LOCKED)
		RETURNING `+nodeCols, fmt.Sprintf("%d milliseconds", lease.Milliseconds())))
}

const subtreeCTE = `WITH RECURSIVE sub AS (
		SELECT id FROM nodes WHERE id = $1
		UNION ALL
		SELECT n.id FROM nodes n JOIN sub ON n.parent_id = sub.id WHERE n.trashed_at IS NULL
	) `

const versionCols = `id, node_id, owner_id, blob_key, wrapped_key, size, sha256, created_at, created_by`

func scanVersions(rows pgx.Rows) ([]*domain.Version, error) {
	defer rows.Close()
	var out []*domain.Version
	for rows.Next() {
		v := &domain.Version{}
		if err := rows.Scan(&v.ID, &v.NodeID, &v.OwnerID, &v.BlobKey, &v.WrappedKey, &v.Size, &v.SHA256, &v.CreatedAt, &v.CreatedBy); err != nil {
			return nil, mapErr(err)
		}
		out = append(out, v)
	}
	return out, mapErr(rows.Err())
}

func (s *Store) SubtreeVersions(ctx context.Context, rootID string, limit int) ([]*domain.Version, error) {
	rows, err := s.db.Query(ctx, subtreeCTE+"SELECT "+versionCols+
		" FROM versions WHERE node_id IN (SELECT id FROM sub) LIMIT $2", rootID, limit)
	if err != nil {
		return nil, mapErr(err)
	}
	return scanVersions(rows)
}

func (s *Store) DeleteVersions(ctx context.Context, versions []*domain.Version) error {
	if len(versions) == 0 {
		return nil
	}
	ids := make([]string, len(versions))
	for i, v := range versions {
		ids[i] = v.ID
	}
	return mapErr(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		// Refund only what was actually deleted in this transaction, so a
		// retried purge can never refund the same bytes twice.
		rows, err := tx.Query(ctx, "DELETE FROM versions WHERE id = ANY($1) RETURNING owner_id, size", ids)
		if err != nil {
			return err
		}
		refunds := map[string]int64{}
		for rows.Next() {
			var owner string
			var size int64
			if err := rows.Scan(&owner, &size); err != nil {
				rows.Close()
				return err
			}
			refunds[owner] += size
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for owner, size := range refunds {
			if _, err := tx.Exec(ctx, "UPDATE users SET used_bytes = greatest(used_bytes - $2, 0) WHERE id=$1", owner, size); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, "UPDATE nodes SET version_id=NULL WHERE version_id = ANY($1)", ids)
		return err
	}))
}

func (s *Store) DeleteSubtree(ctx context.Context, rootID string) error {
	return mapErr(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		// Items trashed separately from inside this folder keep their own
		// trash entry: re-home them under the owner's root so they remain
		// restorable after their old parent disappears.
		if _, err := tx.Exec(ctx, subtreeCTE+`
			UPDATE nodes SET parent_id = u.root_id FROM users u
			WHERE nodes.owner_id = u.id AND nodes.parent_id IN (SELECT id FROM sub)
			  AND nodes.trashed_at IS NOT NULL AND nodes.id <> $1`, rootID); err != nil {
			return err
		}
		// ON DELETE CASCADE removes live descendants and their shares; the
		// RESTRICT foreign key on versions makes this fail if any content is
		// still accounted for, so quota can never silently drift.
		_, err := tx.Exec(ctx, "DELETE FROM nodes WHERE id=$1 AND purging", rootID)
		return err
	}))
}

// ---- content -------------------------------------------------------------

func (s *Store) CommitContent(ctx context.Context, n *domain.Node, nameKey string, v *domain.Version, isNew bool, expectedRev int64) error {
	return mapErr(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if isNew {
			if err := insertNode(ctx, tx, n, nameKey); err != nil {
				return err
			}
		} else {
			tag, err := tx.Exec(ctx, `UPDATE nodes SET size=$2, content_type=$3, sha256=$4, version_id=$5,
					modified_at=$6, modified_by=$7, revision = revision + 1
				WHERE id=$1 AND revision=$8 AND trashed_at IS NULL AND kind='file'`,
				n.ID, n.Size, n.ContentType, n.SHA256, n.VersionID, n.ModifiedAt, n.ModifiedBy, expectedRev)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return domain.E(domain.CodePrecondition, "the file was changed by someone else; reload and retry")
			}
			n.Revision = expectedRev + 1
		}
		if _, err := tx.Exec(ctx, `INSERT INTO versions (`+versionCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			v.ID, v.NodeID, v.OwnerID, v.BlobKey, v.WrappedKey, v.Size, v.SHA256, v.CreatedAt, v.CreatedBy); err != nil {
			return err
		}
		// Atomic quota check: the condition and the increment are one statement.
		tag, err := tx.Exec(ctx, `UPDATE users SET used_bytes = used_bytes + $2
			WHERE id=$1 AND used_bytes + $2 <= quota_bytes`, v.OwnerID, v.Size)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return domain.E(domain.CodeQuota, "storage quota exceeded")
		}
		return nil
	}))
}

func (s *Store) ListVersions(ctx context.Context, nodeID string) ([]*domain.Version, error) {
	rows, err := s.db.Query(ctx, "SELECT "+versionCols+" FROM versions WHERE node_id=$1 ORDER BY created_at DESC, id", nodeID)
	if err != nil {
		return nil, mapErr(err)
	}
	return scanVersions(rows)
}

func (s *Store) GetVersion(ctx context.Context, nodeID, versionID string) (*domain.Version, error) {
	rows, err := s.db.Query(ctx, "SELECT "+versionCols+" FROM versions WHERE node_id=$1 AND id=$2", nodeID, versionID)
	if err != nil {
		return nil, mapErr(err)
	}
	vs, err := scanVersions(rows)
	if err != nil {
		return nil, err
	}
	if len(vs) == 0 {
		return nil, domain.ErrNotFound
	}
	return vs[0], nil
}

// ---- shares --------------------------------------------------------------

const shareCols = `id, kind, node_id, owner_id, created_by, permission, created_at, coalesce(recipient_id, ''),
	coalesce(token_hash, ''), password_hash, expires_at, max_downloads, downloads, failed_attempts, locked_until`

func scanShare(row pgx.Row) (*domain.Share, error) {
	sh := &domain.Share{}
	var kind, perm string
	err := row.Scan(&sh.ID, &kind, &sh.NodeID, &sh.OwnerID, &sh.CreatedBy, &perm, &sh.CreatedAt, &sh.RecipientID,
		&sh.TokenHash, &sh.PasswordHash, &sh.ExpiresAt, &sh.MaxDownloads, &sh.Downloads, &sh.FailedAttempts, &sh.LockedUntil)
	sh.Kind, sh.Permission = domain.ShareKind(kind), domain.Permission(perm)
	return sh, mapErr(err)
}

func scanShares(rows pgx.Rows) ([]*domain.Share, error) {
	defer rows.Close()
	var out []*domain.Share
	for rows.Next() {
		sh, err := scanShare(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sh)
	}
	return out, mapErr(rows.Err())
}

func (s *Store) CreateShare(ctx context.Context, sh *domain.Share) error {
	_, err := s.db.Exec(ctx, `INSERT INTO shares (id, kind, node_id, owner_id, created_by, permission, created_at,
			recipient_id, token_hash, password_hash, expires_at, max_downloads)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		sh.ID, string(sh.Kind), sh.NodeID, sh.OwnerID, sh.CreatedBy, string(sh.Permission), sh.CreatedAt,
		nullable(sh.RecipientID), nullable(sh.TokenHash), sh.PasswordHash, sh.ExpiresAt, sh.MaxDownloads)
	return mapErr(err)
}

func (s *Store) GetShare(ctx context.Context, id string) (*domain.Share, error) {
	return scanShare(s.db.QueryRow(ctx, "SELECT "+shareCols+" FROM shares WHERE id=$1", id))
}

func (s *Store) GetShareByTokenHash(ctx context.Context, h string) (*domain.Share, error) {
	return scanShare(s.db.QueryRow(ctx, "SELECT "+shareCols+" FROM shares WHERE token_hash=$1", h))
}

func (s *Store) DeleteShare(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, "DELETE FROM shares WHERE id=$1", id)
	return mapErr(err)
}

func (s *Store) ListSharesByNode(ctx context.Context, nodeID string) ([]*domain.Share, error) {
	rows, err := s.db.Query(ctx, "SELECT "+shareCols+" FROM shares WHERE node_id=$1 ORDER BY created_at", nodeID)
	if err != nil {
		return nil, mapErr(err)
	}
	return scanShares(rows)
}

func (s *Store) ListSharesByRecipient(ctx context.Context, userID string) ([]*domain.Share, error) {
	rows, err := s.db.Query(ctx, "SELECT "+shareCols+" FROM shares WHERE recipient_id=$1 ORDER BY created_at DESC LIMIT 1000", userID)
	if err != nil {
		return nil, mapErr(err)
	}
	return scanShares(rows)
}

func (s *Store) GetGrants(ctx context.Context, userID string, nodeIDs []string) ([]*domain.Share, error) {
	rows, err := s.db.Query(ctx, "SELECT "+shareCols+
		" FROM shares WHERE kind='user' AND recipient_id=$1 AND node_id = ANY($2)", userID, nodeIDs)
	if err != nil {
		return nil, mapErr(err)
	}
	return scanShares(rows)
}

func (s *Store) RecordLinkDownload(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, `UPDATE shares SET downloads = downloads + 1
		WHERE id=$1 AND (max_downloads = 0 OR downloads < max_downloads)`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return domain.E(domain.CodeGone, "this link has reached its download limit")
	}
	return mapErr(err)
}

func (s *Store) RecordLinkFailure(ctx context.Context, id string, threshold int64, until time.Time) error {
	_, err := s.db.Exec(ctx, `UPDATE shares SET
			locked_until    = CASE WHEN failed_attempts + 1 >= $2 THEN $3 ELSE locked_until END,
			failed_attempts = CASE WHEN failed_attempts + 1 >= $2 THEN 0 ELSE failed_attempts + 1 END
		WHERE id=$1`, id, threshold, until)
	return mapErr(err)
}

func (s *Store) ResetLinkFailures(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, "UPDATE shares SET failed_attempts=0 WHERE id=$1 AND failed_attempts <> 0", id)
	return mapErr(err)
}
