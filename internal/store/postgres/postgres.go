// Package postgres implements FrontDir's metadata store on PostgreSQL.
//
// Every query is parameterized (no SQL built from input), and every rule the
// service relies on for safety (name uniqueness, quota, optimistic
// concurrency, "links are read-only") is enforced inside the same statement
// or transaction as the write, so concurrent requests cannot race past it.
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

	"github.com/woah-buddy/FrontDir/internal/domain"
	"github.com/woah-buddy/FrontDir/internal/service"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store is a PostgreSQL-backed store.
type Store struct {
	db *pgxpool.Pool
}

var _ service.Store = (*Store)(nil)

// Open connects to PostgreSQL. Use sslmode=verify-full whenever the
// database is not on a private, trusted network.
func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: invalid DSN: %w", err)
	}
	cfg.ConnConfig.RuntimeParams["application_name"] = "frontdir"
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

// Migrate applies pending migrations, serialized across replicas by an
// advisory lock.
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
		if err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(sql)); err != nil {
				return fmt.Errorf("migration %s: %w", base, err)
			}
			_, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", v)
			return err
		}); err != nil {
			return err
		}
	}
	return nil
}

// ---- helpers -------------------------------------------------------------------

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
		case "23505":
			return domain.E(domain.CodeConflict, "already exists")
		case "23503":
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

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

var errChanged = domain.E(domain.CodePrecondition, "the item was changed by someone else; reload and retry")

// ---- users -------------------------------------------------------------------------

const userCols = `id, issuer, subject, coalesce(email, ''), display_name, is_admin, admin_granted, personal_space_id,
	enc_pub, sig_pub, self_sig, coalesce(key_bundle, ''), created_at`

func scanUser(row pgx.Row) (*domain.User, error) {
	u := &domain.User{}
	var enc, sig, self *string
	err := row.Scan(&u.ID, &u.Issuer, &u.Subject, &u.Email, &u.DisplayName, &u.Admin, &u.AdminGranted, &u.PersonalSpaceID,
		&enc, &sig, &self, &u.KeyBundle, &u.CreatedAt)
	if enc != nil {
		u.Keys = &domain.PublicKeys{Enc: *enc, Sig: str(sig), SelfSig: str(self)}
	}
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
	return id, mapErr(s.db.QueryRow(ctx, "SELECT id FROM users WHERE email=$1", email).Scan(&id))
}

func (s *Store) CreateUser(ctx context.Context, u *domain.User, sp *domain.Space, root *domain.Node) error {
	insert := func(email string) error {
		return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO users (id, issuer, subject, email, display_name, is_admin,
					personal_space_id, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
				u.ID, u.Issuer, u.Subject, nullable(email), u.DisplayName, u.Admin, u.PersonalSpaceID, u.CreatedAt); err != nil {
				return err
			}
			if err := insertSpace(ctx, tx, sp); err != nil {
				return err
			}
			return insertNode(ctx, tx, root)
		})
	}
	err := insert(u.Email)
	if isUniqueViolation(err, "users_email_key") {
		// Another account holds this email: never let a second account
		// capture shares addressed to it.
		u.Email = ""
		err = insert("")
	}
	return mapErr(err)
}

func (s *Store) UpdateUserProfile(ctx context.Context, id, email, displayName string, admin bool) error {
	_, err := s.db.Exec(ctx, "UPDATE users SET email=$2, display_name=$3, is_admin=$4 WHERE id=$1", id, nullable(email), displayName, admin)
	if isUniqueViolation(err, "users_email_key") {
		_, err = s.db.Exec(ctx, "UPDATE users SET email=NULL, display_name=$2, is_admin=$3 WHERE id=$1", id, displayName, admin)
	}
	return mapErr(err)
}

// orphanedGrants deletes membership rows that carry only a key grant for a
// space the user no longer belongs to through any group.
const orphanedGrants = `DELETE FROM space_members m WHERE m.role IS NULL AND NOT EXISTS (
	SELECT 1 FROM space_groups g JOIN user_groups ug ON ug.group_name = g.group_name
	WHERE g.space_id = m.space_id AND ug.user_id = m.user_id)`

func (s *Store) SyncGroups(ctx context.Context, userID string, groups []string) error {
	return mapErr(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "DELETE FROM user_groups WHERE user_id=$1", userID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO user_groups (user_id, group_name)
			SELECT $1, g FROM unnest($2::text[]) AS g ON CONFLICT DO NOTHING`, userID, groups); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, orphanedGrants+" AND m.user_id = $1", userID)
		return err
	}))
}

func (s *Store) SetKeys(ctx context.Context, userID string, k domain.PublicKeys, bundle string, ps service.SpaceKeys) error {
	return mapErr(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE users SET enc_pub=$2, sig_pub=$3, self_sig=$4, key_bundle=$5
			WHERE id=$1 AND enc_pub IS NULL`, userID, k.Enc, k.Sig, k.SelfSig, bundle)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return domain.E(domain.CodeConflict, "encryption keys are already set up")
		}
		tag, err = tx.Exec(ctx, `UPDATE spaces SET public_key=$2, key_sig=$3, key_signer=$4, root_key=$5
			WHERE owner_user_id=$1 AND kind='personal' AND public_key IS NULL`,
			userID, ps.PublicKey, ps.KeySig, ps.KeySigner, ps.RootKey)
		if err == nil && tag.RowsAffected() == 0 {
			err = domain.E(domain.CodeConflict, "personal space keys are already set up")
		}
		return err
	}))
}

func (s *Store) UpdateKeyBundle(ctx context.Context, userID, bundle string) error {
	tag, err := s.db.Exec(ctx, "UPDATE users SET key_bundle=$2 WHERE id=$1 AND key_bundle IS NOT NULL", userID, bundle)
	if err == nil && tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return mapErr(err)
}

// ---- spaces --------------------------------------------------------------------------

const spaceCols = `id, kind, coalesce(owner_user_id, ''), root_id, name_enc, coalesce(public_key, ''),
	coalesce(key_sig, ''), coalesce(key_signer, ''), coalesce(root_key, ''), quota_bytes, used_bytes,
	created_at, created_by, deleted_at`

func scanSpace(row pgx.Row) (*domain.Space, error) {
	sp := &domain.Space{}
	var kind string
	err := row.Scan(&sp.ID, &kind, &sp.OwnerUserID, &sp.RootID, &sp.NameEnc, &sp.PublicKey, &sp.KeySig,
		&sp.KeySigner, &sp.RootKey, &sp.QuotaBytes, &sp.UsedBytes, &sp.CreatedAt, &sp.CreatedBy, &sp.DeletedAt)
	sp.Kind = domain.SpaceKind(kind)
	return sp, mapErr(err)
}

func scanSpaces(rows pgx.Rows, err error) ([]*domain.Space, error) {
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []*domain.Space
	for rows.Next() {
		sp, err := scanSpace(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sp)
	}
	return out, mapErr(rows.Err())
}

func insertSpace(ctx context.Context, tx pgx.Tx, sp *domain.Space) error {
	_, err := tx.Exec(ctx, `INSERT INTO spaces (id, kind, owner_user_id, root_id, name_enc, public_key, key_sig,
			key_signer, root_key, quota_bytes, created_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		sp.ID, string(sp.Kind), nullable(sp.OwnerUserID), sp.RootID, sp.NameEnc, nullable(sp.PublicKey),
		nullable(sp.KeySig), nullable(sp.KeySigner), nullable(sp.RootKey), sp.QuotaBytes, sp.CreatedAt, sp.CreatedBy)
	return err
}

func (s *Store) GetSpace(ctx context.Context, id string) (*domain.Space, error) {
	return scanSpace(s.db.QueryRow(ctx, "SELECT "+spaceCols+" FROM spaces WHERE id=$1", id))
}

func (s *Store) CreateTeamSpace(ctx context.Context, sp *domain.Space, root *domain.Node, m *domain.Membership) error {
	return mapErr(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if err := insertSpace(ctx, tx, sp); err != nil {
			return err
		}
		if err := insertNode(ctx, tx, root); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO space_members (space_id, user_id, role, grant_key, grant_sig, granted_by, added_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`, m.SpaceID, m.UserID, string(m.DirectRole), m.Grant, m.GrantSig, m.GrantedBy, m.AddedAt)
		return err
	}))
}

func (s *Store) UpdateSpaceName(ctx context.Context, id, nameEnc string) error {
	_, err := s.db.Exec(ctx, "UPDATE spaces SET name_enc=$2 WHERE id=$1 AND kind='team'", id, nameEnc)
	return mapErr(err)
}

func (s *Store) SetSpaceQuota(ctx context.Context, id string, quota int64) error {
	tag, err := s.db.Exec(ctx, "UPDATE spaces SET quota_bytes=$2 WHERE id=$1", id, quota)
	if err == nil && tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return mapErr(err)
}

func (s *Store) MarkSpaceDeleted(ctx context.Context, id string, at time.Time) error {
	tag, err := s.db.Exec(ctx, "UPDATE spaces SET deleted_at=$2 WHERE id=$1 AND kind='team' AND deleted_at IS NULL", id, at)
	if err == nil && tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return mapErr(err)
}

func (s *Store) ListUserSpaces(ctx context.Context, userID string) ([]*domain.Space, error) {
	return scanSpaces(s.db.Query(ctx, "SELECT "+spaceCols+` FROM spaces sp
		WHERE sp.deleted_at IS NULL AND (
			sp.owner_user_id = $1
			OR EXISTS (SELECT 1 FROM space_members m WHERE m.space_id = sp.id AND m.user_id = $1)
			OR EXISTS (SELECT 1 FROM space_groups g JOIN user_groups ug ON ug.group_name = g.group_name
			           WHERE g.space_id = sp.id AND ug.user_id = $1))
		ORDER BY sp.kind, sp.created_at`, userID))
}

func (s *Store) ListTeamSpaces(ctx context.Context) ([]*domain.Space, error) {
	return scanSpaces(s.db.Query(ctx, "SELECT "+spaceCols+" FROM spaces WHERE kind='team' AND deleted_at IS NULL ORDER BY created_at"))
}

func (s *Store) GetMembership(ctx context.Context, spaceID, userID string) (*domain.Membership, error) {
	m := &domain.Membership{SpaceID: spaceID, UserID: userID}
	var role, grant, sig, by *string
	var added *time.Time
	err := s.db.QueryRow(ctx, `SELECT role, grant_key, grant_sig, granted_by, added_at FROM space_members
		WHERE space_id=$1 AND user_id=$2`, spaceID, userID).Scan(&role, &grant, &sig, &by, &added)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, mapErr(err)
	}
	found := err == nil
	m.DirectRole, m.Grant, m.GrantSig, m.GrantedBy = domain.Role(str(role)), str(grant), str(sig), str(by)
	if added != nil {
		m.AddedAt = *added
	}
	rows, err := s.db.Query(ctx, `SELECT g.role FROM space_groups g JOIN user_groups ug ON ug.group_name = g.group_name
		WHERE g.space_id=$1 AND ug.user_id=$2`, spaceID, userID)
	if err != nil {
		return nil, mapErr(err)
	}
	roles, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, mapErr(err)
	}
	for _, r := range roles {
		m.GroupRoles = append(m.GroupRoles, domain.Role(r))
	}
	if !found && len(roles) == 0 {
		return nil, domain.ErrNotFound
	}
	return m, nil
}

func (s *Store) ListMembers(ctx context.Context, spaceID string) ([]*domain.Member, error) {
	rows, err := s.db.Query(ctx, `
		WITH grp AS (
			SELECT ug.user_id, array_agg(g.role) AS roles
			FROM space_groups g JOIN user_groups ug ON ug.group_name = g.group_name
			WHERE g.space_id = $1 GROUP BY ug.user_id)
		SELECT u.id, u.display_name, coalesce(u.email, ''), u.enc_pub, u.sig_pub, u.self_sig,
		       m.role, m.grant_key, m.grant_sig, m.granted_by, m.added_at, grp.roles
		FROM users u
		LEFT JOIN space_members m ON m.space_id = $1 AND m.user_id = u.id
		LEFT JOIN grp ON grp.user_id = u.id
		WHERE m.user_id IS NOT NULL OR grp.user_id IS NOT NULL
		ORDER BY u.display_name, u.id`, spaceID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []*domain.Member
	for rows.Next() {
		mb := &domain.Member{Membership: domain.Membership{SpaceID: spaceID}}
		var enc, sig, self, role, grant, gsig, by *string
		var added *time.Time
		var groles []string
		if err := rows.Scan(&mb.UserID, &mb.DisplayName, &mb.Email, &enc, &sig, &self, &role, &grant, &gsig, &by,
			&added, &groles); err != nil {
			return nil, mapErr(err)
		}
		if enc != nil {
			mb.Keys = &domain.PublicKeys{Enc: *enc, Sig: str(sig), SelfSig: str(self)}
		}
		mb.DirectRole, mb.Grant, mb.GrantSig, mb.GrantedBy = domain.Role(str(role)), str(grant), str(gsig), str(by)
		if added != nil {
			mb.AddedAt = *added
		}
		for _, r := range groles {
			mb.GroupRoles = append(mb.GroupRoles, domain.Role(r))
		}
		if mb.Role() == domain.RoleNone {
			continue // a stale grant without any role is not membership
		}
		out = append(out, mb)
	}
	return out, mapErr(rows.Err())
}

func (s *Store) SetMemberRole(ctx context.Context, spaceID, userID string, role domain.Role, at time.Time) error {
	if role == domain.RoleNone {
		_, err := s.db.Exec(ctx, "UPDATE space_members SET role=NULL WHERE space_id=$1 AND user_id=$2", spaceID, userID)
		if err == nil {
			_, err = s.db.Exec(ctx, orphanedGrants+" AND m.space_id=$1 AND m.user_id=$2", spaceID, userID)
		}
		return mapErr(err)
	}
	_, err := s.db.Exec(ctx, `INSERT INTO space_members (space_id, user_id, role, added_at) VALUES ($1,$2,$3,$4)
		ON CONFLICT (space_id, user_id) DO UPDATE SET role = EXCLUDED.role`, spaceID, userID, string(role), at)
	return mapErr(err)
}

func (s *Store) SetMemberGrant(ctx context.Context, spaceID, userID, grant, sig, by string, at time.Time) error {
	_, err := s.db.Exec(ctx, `INSERT INTO space_members (space_id, user_id, grant_key, grant_sig, granted_by, added_at)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (space_id, user_id) DO UPDATE SET grant_key=EXCLUDED.grant_key, grant_sig=EXCLUDED.grant_sig,
			granted_by=EXCLUDED.granted_by`, spaceID, userID, grant, sig, by, at)
	return mapErr(err)
}

func (s *Store) RemoveMember(ctx context.Context, spaceID, userID string) error {
	_, err := s.db.Exec(ctx, "DELETE FROM space_members WHERE space_id=$1 AND user_id=$2", spaceID, userID)
	return mapErr(err)
}

func (s *Store) ListGroupMappings(ctx context.Context, spaceID string) ([]domain.GroupMapping, error) {
	rows, err := s.db.Query(ctx, "SELECT space_id, group_name, role FROM space_groups WHERE space_id=$1 ORDER BY group_name", spaceID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []domain.GroupMapping
	for rows.Next() {
		var m domain.GroupMapping
		var role string
		if err := rows.Scan(&m.SpaceID, &m.Group, &role); err != nil {
			return nil, mapErr(err)
		}
		m.Role = domain.Role(role)
		out = append(out, m)
	}
	return out, mapErr(rows.Err())
}

func (s *Store) SetGroupMapping(ctx context.Context, m domain.GroupMapping) error {
	_, err := s.db.Exec(ctx, `INSERT INTO space_groups (space_id, group_name, role) VALUES ($1,$2,$3)
		ON CONFLICT (space_id, group_name) DO UPDATE SET role = EXCLUDED.role`, m.SpaceID, m.Group, string(m.Role))
	return mapErr(err)
}

func (s *Store) DeleteGroupMapping(ctx context.Context, spaceID, group string) error {
	return mapErr(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "DELETE FROM space_groups WHERE space_id=$1 AND group_name=$2", spaceID, group); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, orphanedGrants+" AND m.space_id=$1", spaceID)
		return err
	}))
}

func (s *Store) ClaimDeletedSpace(ctx context.Context, lease time.Duration) (*domain.Space, error) {
	return scanSpace(s.db.QueryRow(ctx, `UPDATE spaces SET delete_lease = now() + $1::interval
		WHERE id = (SELECT id FROM spaces WHERE deleted_at IS NOT NULL AND (delete_lease IS NULL OR delete_lease < now())
		            ORDER BY delete_lease NULLS FIRST LIMIT 1 FOR UPDATE SKIP LOCKED)
		RETURNING `+spaceCols, fmt.Sprintf("%d milliseconds", lease.Milliseconds())))
}

func (s *Store) SpaceVersions(ctx context.Context, spaceID string, limit int) ([]*domain.Version, error) {
	rows, err := s.db.Query(ctx, "SELECT "+versionCols+" FROM versions WHERE space_id=$1 LIMIT $2", spaceID, limit)
	if err != nil {
		return nil, mapErr(err)
	}
	return scanVersions(rows)
}

func (s *Store) DeleteSpace(ctx context.Context, spaceID string) error {
	return mapErr(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "DELETE FROM nodes WHERE space_id=$1 AND parent_id IS NULL", spaceID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "DELETE FROM spaces WHERE id=$1 AND deleted_at IS NOT NULL", spaceID)
		return err
	}))
}

// ---- nodes ---------------------------------------------------------------------------

const nodeCols = `id, space_id, coalesce(parent_id, ''), kind, name_enc, name_hash, coalesce(wrapped_key, ''),
	size, plain_size, sha256, coalesce(version_id, ''), created_at, created_by, modified_at, modified_by, revision,
	trashed_at, coalesce(trashed_by, ''), coalesce(restore_key, ''), coalesce(restore_sig, '')`

func scanNode(row pgx.Row) (*domain.Node, error) {
	n := &domain.Node{}
	var kind string
	err := row.Scan(&n.ID, &n.SpaceID, &n.ParentID, &kind, &n.NameEnc, &n.NameHash, &n.WrappedKey, &n.Size,
		&n.PlainSize, &n.SHA256, &n.VersionID, &n.CreatedAt, &n.CreatedBy, &n.ModifiedAt, &n.ModifiedBy, &n.Revision,
		&n.TrashedAt, &n.TrashedBy, &n.RestoreKey, &n.RestoreSig)
	n.Kind = domain.Kind(kind)
	return n, mapErr(err)
}

func scanNodes(rows pgx.Rows, err error) ([]*domain.Node, error) {
	if err != nil {
		return nil, mapErr(err)
	}
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

func insertNode(ctx context.Context, tx pgx.Tx, n *domain.Node) error {
	_, err := tx.Exec(ctx, `INSERT INTO nodes (id, space_id, parent_id, kind, name_enc, name_hash, wrapped_key, size,
			plain_size, sha256, version_id, created_at, created_by, modified_at, modified_by, revision)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		n.ID, n.SpaceID, nullable(n.ParentID), string(n.Kind), n.NameEnc, n.NameHash, nullable(n.WrappedKey), n.Size,
		n.PlainSize, n.SHA256, nullable(n.VersionID), n.CreatedAt, n.CreatedBy, n.ModifiedAt, n.ModifiedBy, n.Revision)
	return err
}

func (s *Store) GetNode(ctx context.Context, id string) (*domain.Node, error) {
	return scanNode(s.db.QueryRow(ctx, "SELECT "+nodeCols+" FROM nodes WHERE id=$1", id))
}

func (s *Store) GetAncestry(ctx context.Context, id string, max int) ([]*domain.Node, error) {
	nodes, err := scanNodes(s.db.Query(ctx, `
		WITH RECURSIVE anc AS (
			SELECT nodes.*, 0 AS depth FROM nodes WHERE id = $1
			UNION ALL
			SELECT n.*, anc.depth + 1 FROM nodes n JOIN anc ON n.id = anc.parent_id WHERE anc.depth + 1 < $2
		)
		SELECT `+nodeCols+` FROM anc ORDER BY depth`, id, max))
	if err == nil && len(nodes) == 0 {
		return nil, domain.ErrNotFound
	}
	return nodes, err
}

func (s *Store) GetChildByHash(ctx context.Context, parentID, hash string) (*domain.Node, error) {
	return scanNode(s.db.QueryRow(ctx, "SELECT "+nodeCols+
		" FROM nodes WHERE parent_id=$1 AND name_hash=$2 AND trashed_at IS NULL", parentID, hash))
}

func (s *Store) ListChildren(ctx context.Context, parentID, cursor string, limit int) ([]*domain.Node, string, error) {
	nodes, err := scanNodes(s.db.Query(ctx, "SELECT "+nodeCols+` FROM nodes
		WHERE parent_id=$1 AND trashed_at IS NULL AND id > $2 ORDER BY id LIMIT $3`, parentID, cursor, limit+1))
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(nodes) > limit {
		nodes = nodes[:limit]
		next = nodes[limit-1].ID
	}
	return nodes, next, nil
}

func (s *Store) CreateFolder(ctx context.Context, n *domain.Node) error {
	return mapErr(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error { return insertNode(ctx, tx, n) }))
}

func (s *Store) UpdateNodeLocation(ctx context.Context, n *domain.Node, expectedRev int64) error {
	tag, err := s.db.Exec(ctx, `UPDATE nodes SET parent_id=$2, name_enc=$3, name_hash=$4, wrapped_key=$5,
			modified_at=$6, modified_by=$7, revision = revision + 1
		WHERE id=$1 AND revision=$8 AND trashed_at IS NULL AND parent_id IS NOT NULL`,
		n.ID, n.ParentID, n.NameEnc, n.NameHash, n.WrappedKey, n.ModifiedAt, n.ModifiedBy, expectedRev)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return errChanged
	}
	n.Revision = expectedRev + 1
	return nil
}

func (s *Store) TrashNode(ctx context.Context, n *domain.Node, expectedRev int64) error {
	tag, err := s.db.Exec(ctx, `UPDATE nodes SET trashed_at=$2, trashed_by=$3, restore_key=$4, restore_sig=$5,
			revision = revision + 1
		WHERE id=$1 AND revision=$6 AND trashed_at IS NULL AND parent_id IS NOT NULL`,
		n.ID, n.TrashedAt, n.TrashedBy, n.RestoreKey, n.RestoreSig, expectedRev)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return errChanged
	}
	n.Revision = expectedRev + 1
	return nil
}

func (s *Store) RestoreNode(ctx context.Context, n *domain.Node) error {
	tag, err := s.db.Exec(ctx, `UPDATE nodes SET trashed_at=NULL, trashed_by=NULL, restore_key=NULL, restore_sig=NULL,
			parent_id=$2, name_enc=$3, name_hash=$4, wrapped_key=$5, revision = revision + 1
		WHERE id=$1 AND trashed_at IS NOT NULL AND NOT purging`, n.ID, n.ParentID, n.NameEnc, n.NameHash, n.WrappedKey)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	n.TrashedAt, n.TrashedBy, n.RestoreKey, n.RestoreSig = nil, "", "", ""
	n.Revision++
	return nil
}

func (s *Store) ListTrash(ctx context.Context, spaceID string) ([]*domain.Node, error) {
	return scanNodes(s.db.Query(ctx, "SELECT "+nodeCols+` FROM nodes
		WHERE space_id=$1 AND trashed_at IS NOT NULL AND NOT purging ORDER BY trashed_at DESC LIMIT 1000`, spaceID))
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
	tag, err := s.db.Exec(ctx, "UPDATE nodes SET purging=true, purge_lease=NULL WHERE trashed_at < $1 AND NOT purging", cutoff)
	return tag.RowsAffected(), mapErr(err)
}

func (s *Store) ClaimPurge(ctx context.Context, lease time.Duration) (*domain.Node, error) {
	// FOR UPDATE SKIP LOCKED turns the table into a work queue that any
	// number of replicas can drain without double-processing.
	return scanNode(s.db.QueryRow(ctx, `UPDATE nodes SET purge_lease = now() + $1::interval
		WHERE id = (SELECT id FROM nodes WHERE purging AND (purge_lease IS NULL OR purge_lease < now())
		            ORDER BY purge_lease NULLS FIRST LIMIT 1 FOR UPDATE SKIP LOCKED)
		RETURNING `+nodeCols, fmt.Sprintf("%d milliseconds", lease.Milliseconds())))
}

const subtreeCTE = `WITH RECURSIVE sub AS (
		SELECT id FROM nodes WHERE id = $1
		UNION ALL
		SELECT n.id FROM nodes n JOIN sub ON n.parent_id = sub.id WHERE n.trashed_at IS NULL
	) `

const versionCols = `id, node_id, space_id, blob_key, size, sha256, created_at, created_by, signer_id, header, body_hash, trailer,
	record, record_sig, seq, record_hash`

// ListVersionBlobs pages through every stored file version in blob-key
// order (for storage verification).
func (s *Store) ListVersionBlobs(ctx context.Context, after string, limit int) ([]*domain.Version, error) {
	rows, err := s.db.Query(ctx, "SELECT "+versionCols+" FROM versions WHERE blob_key > $1 ORDER BY blob_key LIMIT $2", after, limit)
	if err != nil {
		return nil, mapErr(err)
	}
	return scanVersions(rows)
}

func scanVersions(rows pgx.Rows) ([]*domain.Version, error) {
	defer rows.Close()
	var out []*domain.Version
	for rows.Next() {
		v := &domain.Version{}
		var signer *string
		var seq *int64
		if err := rows.Scan(&v.ID, &v.NodeID, &v.SpaceID, &v.BlobKey, &v.Size, &v.SHA256, &v.CreatedAt, &v.CreatedBy,
			&signer, &v.Header, &v.BodyHash, &v.Trailer, &v.Record, &v.RecordSig, &seq, &v.RecordHash); err != nil {
			return nil, mapErr(err)
		}
		if signer != nil {
			v.SignerID = *signer
		}
		if seq != nil {
			v.Seq = *seq
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
		// Refund only what this transaction actually deleted, so a retried
		// purge never refunds the same bytes twice.
		rows, err := tx.Query(ctx, "DELETE FROM versions WHERE id = ANY($1) RETURNING space_id, size", ids)
		if err != nil {
			return err
		}
		refunds := map[string]int64{}
		for rows.Next() {
			var sp string
			var size int64
			if err := rows.Scan(&sp, &size); err != nil {
				rows.Close()
				return err
			}
			refunds[sp] += size
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for sp, size := range refunds {
			if _, err := tx.Exec(ctx, "UPDATE spaces SET used_bytes = greatest(used_bytes - $2, 0) WHERE id=$1", sp, size); err != nil {
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
		// trash entry (and their sealed restore key), so re-home them under
		// the space root to keep them restorable.
		if _, err := tx.Exec(ctx, subtreeCTE+`
			UPDATE nodes SET parent_id = sp.root_id FROM spaces sp
			WHERE nodes.space_id = sp.id AND nodes.parent_id IN (SELECT id FROM sub)
			  AND nodes.trashed_at IS NOT NULL AND nodes.id <> $1`, rootID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "DELETE FROM nodes WHERE id=$1 AND purging", rootID)
		return err
	}))
}

// ---- content -------------------------------------------------------------------------

// CommitContent stores a new file or version. With dropID, it also files
// that mailbox drop: the drop's row goes and its size is refunded in the
// same transaction that charges the new version, so filing never needs
// room for the file twice.
func (s *Store) CommitContent(ctx context.Context, n *domain.Node, v *domain.Version, isNew bool, expectedRev int64, dropID string) error {
	return mapErr(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if dropID != "" {
			if err := consumeDrop(ctx, tx, dropID, v.SpaceID); err != nil {
				return err
			}
		}
		if isNew {
			if err := insertNode(ctx, tx, n); err != nil {
				return err
			}
		} else {
			tag, err := tx.Exec(ctx, `UPDATE nodes SET size=$2, plain_size=$3, sha256=$4, version_id=$5, modified_at=$6,
					modified_by=$7, revision = revision + 1
				WHERE id=$1 AND revision=$8 AND trashed_at IS NULL AND kind='file'`,
				n.ID, n.Size, n.PlainSize, n.SHA256, n.VersionID, n.ModifiedAt, n.ModifiedBy, expectedRev)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return errChanged
			}
			n.Revision = expectedRev + 1
		}
		var seq *int64
		if v.Seq > 0 {
			seq = &v.Seq
		}
		if _, err := tx.Exec(ctx, `INSERT INTO versions (`+versionCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
			v.ID, v.NodeID, v.SpaceID, v.BlobKey, v.Size, v.SHA256, v.CreatedAt, v.CreatedBy,
			v.SignerID, v.Header, v.BodyHash, v.Trailer, v.Record, v.RecordSig, seq, v.RecordHash); err != nil {
			if isUniqueViolation(err, "versions_node_seq") {
				return domain.E(domain.CodePrecondition, "the file changed while you were saving; reload and retry")
			}
			return err
		}
		// Atomic quota check: condition and increment in one statement.
		tag, err := tx.Exec(ctx, `UPDATE spaces SET used_bytes = used_bytes + $2
			WHERE id=$1 AND used_bytes + $2 <= quota_bytes AND deleted_at IS NULL`, v.SpaceID, v.Size)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return domain.E(domain.CodeQuota, "storage quota exceeded")
		}
		return nil
	}))
}

// VersionsWithoutDigest returns versions whose attribution digest has not
// been computed yet (stored before it was recorded at upload).
func (s *Store) VersionsWithoutDigest(ctx context.Context, limit int) ([]*domain.Version, error) {
	rows, err := s.db.Query(ctx, "SELECT "+versionCols+" FROM versions WHERE body_hash IS NULL ORDER BY id LIMIT $1", limit)
	if err != nil {
		return nil, mapErr(err)
	}
	return scanVersions(rows)
}

// SetVersionDigest records a version's attribution digest, unless it is
// already known. Empty values record that it cannot be computed.
func (s *Store) SetVersionDigest(ctx context.Context, v *domain.Version) error {
	_, err := s.db.Exec(ctx, `UPDATE versions SET signer_id = NULLIF($2, ''), header = $3, body_hash = $4, trailer = $5
		WHERE id = $1 AND body_hash IS NULL`, v.ID, v.SignerID, nonNil(v.Header), nonNil(v.BodyHash), nonNil(v.Trailer))
	return mapErr(err)
}

// nonNil turns a nil slice into an empty one, which pgx stores as an empty
// bytea rather than NULL.
func nonNil(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
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

// ---- shares ----------------------------------------------------------------------------

const shareCols = `id, kind, node_id, space_id, created_by, permission, created_at, coalesce(recipient_id, ''),
	coalesce(sealed_key, ''), coalesce(share_sig, ''), coalesce(token_hash, ''), coalesce(link_key, ''),
	password_hash, expires_at, max_downloads, downloads, failed_attempts, locked_until`

func scanShare(row pgx.Row) (*domain.Share, error) {
	sh := &domain.Share{}
	var kind, perm string
	err := row.Scan(&sh.ID, &kind, &sh.NodeID, &sh.SpaceID, &sh.CreatedBy, &perm, &sh.CreatedAt, &sh.RecipientID,
		&sh.SealedKey, &sh.ShareSig, &sh.TokenHash, &sh.LinkKey, &sh.PasswordHash, &sh.ExpiresAt, &sh.MaxDownloads,
		&sh.Downloads, &sh.FailedAttempts, &sh.LockedUntil)
	sh.Kind, sh.Permission = domain.ShareKind(kind), domain.Permission(perm)
	return sh, mapErr(err)
}

func scanShares(rows pgx.Rows, err error) ([]*domain.Share, error) {
	if err != nil {
		return nil, mapErr(err)
	}
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
	_, err := s.db.Exec(ctx, `INSERT INTO shares (id, kind, node_id, space_id, created_by, permission, created_at,
			recipient_id, sealed_key, share_sig, token_hash, link_key, password_hash, expires_at, max_downloads)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		sh.ID, string(sh.Kind), sh.NodeID, sh.SpaceID, sh.CreatedBy, string(sh.Permission), sh.CreatedAt,
		nullable(sh.RecipientID), nullable(sh.SealedKey), nullable(sh.ShareSig), nullable(sh.TokenHash),
		nullable(sh.LinkKey), sh.PasswordHash, sh.ExpiresAt, sh.MaxDownloads)
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
	return scanShares(s.db.Query(ctx, "SELECT "+shareCols+" FROM shares WHERE node_id=$1 ORDER BY created_at", nodeID))
}

func (s *Store) ListSharesByRecipient(ctx context.Context, userID string) ([]*domain.Share, error) {
	return scanShares(s.db.Query(ctx, "SELECT "+shareCols+" FROM shares WHERE recipient_id=$1 ORDER BY created_at DESC LIMIT 1000", userID))
}

// GetContacts returns a user's sealed contact list ("" if none) and its revision.
func (s *Store) GetContacts(ctx context.Context, userID string) (string, int64, error) {
	var enc *string
	var rev int64
	err := s.db.QueryRow(ctx, "SELECT contacts_enc, contacts_rev FROM users WHERE id=$1", userID).Scan(&enc, &rev)
	if err != nil {
		return "", 0, mapErr(err)
	}
	if enc == nil {
		return "", rev, nil
	}
	return *enc, rev, nil
}

// SetContacts replaces a user's sealed contact list if its revision is still
// expectRev, in one statement, and returns the new revision.
func (s *Store) SetContacts(ctx context.Context, userID, enc string, expectRev int64) (int64, error) {
	var rev int64
	err := s.db.QueryRow(ctx, `UPDATE users SET contacts_enc=$2, contacts_rev=contacts_rev+1
		WHERE id=$1 AND contacts_rev=$3 RETURNING contacts_rev`, userID, enc, expectRev).Scan(&rev)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, domain.E(domain.CodePrecondition, "the contact list changed on another device; reload and try again")
	}
	if err != nil {
		return 0, mapErr(err)
	}
	return rev, nil
}

// ListSharesByCreator returns up to limit shares the user created, newest first.
func (s *Store) ListSharesByCreator(ctx context.Context, userID string, limit int) ([]*domain.Share, error) {
	return scanShares(s.db.Query(ctx, "SELECT "+shareCols+" FROM shares WHERE created_by=$1 ORDER BY created_at DESC LIMIT $2", userID, limit))
}

// DeleteLinksByCreator revokes every public link the user created, in one
// statement, and reports how many there were.
func (s *Store) DeleteLinksByCreator(ctx context.Context, userID string) (int64, error) {
	tag, err := s.db.Exec(ctx, "DELETE FROM shares WHERE kind='link' AND created_by=$1", userID)
	if err != nil {
		return 0, mapErr(err)
	}
	return tag.RowsAffected(), nil
}

// DeleteAllLinks revokes every public link on the instance. It is a separate
// method (not DeleteLinksByCreator with an empty user) so that no input
// value can widen a per-user revocation into a global one.
func (s *Store) DeleteAllLinks(ctx context.Context) (int64, error) {
	tag, err := s.db.Exec(ctx, "DELETE FROM shares WHERE kind='link'")
	if err != nil {
		return 0, mapErr(err)
	}
	return tag.RowsAffected(), nil
}

func (s *Store) GetGrants(ctx context.Context, userID string, nodeIDs []string) ([]*domain.Share, error) {
	return scanShares(s.db.Query(ctx, "SELECT "+shareCols+
		" FROM shares WHERE kind='user' AND recipient_id=$1 AND node_id = ANY($2)", userID, nodeIDs))
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
