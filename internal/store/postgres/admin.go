package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/woah-buddy/NoddaNAS/internal/domain"
	"github.com/woah-buddy/NoddaNAS/internal/service"
)

// ---- administration ------------------------------------------------------------------

// ListUsers lists accounts for the admin area, optionally filtered by a
// case-insensitive substring of the email or display name.
func (s *Store) ListUsers(ctx context.Context, query string, limit int) ([]service.UserSummary, error) {
	rows, err := s.db.Query(ctx, `SELECT u.id, u.display_name, coalesce(u.email, ''), u.issuer, u.is_admin, u.admin_granted,
			u.enc_pub IS NOT NULL, u.personal_space_id, sp.quota_bytes, sp.used_bytes, u.created_at
		FROM users u JOIN spaces sp ON sp.id = u.personal_space_id
		WHERE $1 = '' OR strpos(lower(coalesce(u.email, '')), lower($1)) > 0 OR strpos(lower(u.display_name), lower($1)) > 0
		ORDER BY lower(u.display_name), u.id LIMIT $2`, query, limit)
	if err != nil {
		return nil, mapErr(err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (service.UserSummary, error) {
		var u service.UserSummary
		err := r.Scan(&u.ID, &u.DisplayName, &u.Email, &u.Issuer, &u.Admin, &u.AdminGranted, &u.KeysSetUp,
			&u.PersonalSpaceID, &u.QuotaBytes, &u.UsedBytes, &u.CreatedAt)
		return u, err
	})
	return out, mapErr(err)
}

// adminExpr is the effective administrator flag of a users row u, given the
// administrator groups as $1.
const adminExpr = `(u.admin_granted OR EXISTS (SELECT 1 FROM user_groups g WHERE g.user_id = u.id AND g.group_name = ANY($1::text[])))`

// SetAdminGranted appoints or removes an administrator and recomputes their
// effective flag in the same statement.
func (s *Store) SetAdminGranted(ctx context.Context, userID string, grant bool, adminGroups []string) error {
	tag, err := s.db.Exec(ctx, `UPDATE users u SET admin_granted = $3,
			is_admin = $3 OR EXISTS (SELECT 1 FROM user_groups g WHERE g.user_id = u.id AND g.group_name = ANY($1::text[]))
		WHERE u.id = $2`, adminGroups, userID, grant)
	if err == nil && tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return mapErr(err)
}

// RecomputeAdmins re-derives every account's administrator flag after the
// administrator groups changed, so the change takes effect immediately
// rather than at each person's next sign-in.
func (s *Store) RecomputeAdmins(ctx context.Context, adminGroups []string) (int64, error) {
	tag, err := s.db.Exec(ctx, `UPDATE users u SET is_admin = `+adminExpr+` WHERE is_admin IS DISTINCT FROM `+adminExpr, adminGroups)
	if err != nil {
		return 0, mapErr(err)
	}
	return tag.RowsAffected(), nil
}

// UserGroups returns the groups the user had at their last sign-in.
func (s *Store) UserGroups(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.Query(ctx, "SELECT group_name FROM user_groups WHERE user_id=$1 ORDER BY group_name", userID)
	if err != nil {
		return nil, mapErr(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	return out, mapErr(err)
}

// IssuerCounts counts accounts per identity issuer (OIDC issuer, or
// "saml:" + IdP entity ID).
func (s *Store) IssuerCounts(ctx context.Context) (map[string]int64, error) {
	rows, err := s.db.Query(ctx, "SELECT issuer, count(*) FROM users GROUP BY issuer")
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var iss string
		var n int64
		if err := rows.Scan(&iss, &n); err != nil {
			return nil, mapErr(err)
		}
		out[iss] = n
	}
	return out, mapErr(rows.Err())
}

// ---- web settings ---------------------------------------------------------------------

// GetSettings returns the saved settings document and its revision (0 and
// an empty document if nothing was ever saved).
func (s *Store) GetSettings(ctx context.Context) (int64, map[string]string, error) {
	var rev int64
	var raw []byte
	err := s.db.QueryRow(ctx, "SELECT revision, doc FROM settings WHERE id = 1").Scan(&rev, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, map[string]string{}, nil
	}
	if err != nil {
		return 0, nil, mapErr(err)
	}
	doc := map[string]string{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return 0, nil, err
	}
	return rev, doc, nil
}

// SettingsRevision is a cheap check for changes made by another replica.
func (s *Store) SettingsRevision(ctx context.Context) (int64, error) {
	var rev int64
	err := s.db.QueryRow(ctx, "SELECT coalesce(max(revision), 0) FROM settings").Scan(&rev)
	return rev, mapErr(err)
}

// PutSettings replaces the document if its revision is still prevRev, and
// returns the new revision. A concurrent change yields a precondition error.
func (s *Store) PutSettings(ctx context.Context, prevRev int64, doc map[string]string, by string, now time.Time) (int64, error) {
	raw, err := json.Marshal(doc)
	if err != nil {
		return 0, err
	}
	var rev int64
	err = s.db.QueryRow(ctx, `INSERT INTO settings (id, revision, doc, updated_at, updated_by) VALUES (1, $1 + 1, $2, $3, $4)
		ON CONFLICT (id) DO UPDATE SET revision = settings.revision + 1, doc = $2, updated_at = $3, updated_by = $4
			WHERE settings.revision = $1
		RETURNING revision`, prevRev, raw, now, by).Scan(&rev)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, domain.E(domain.CodePrecondition, "settings were changed by someone else; reload and try again")
	}
	return rev, mapErr(err)
}

// ---- setup link -----------------------------------------------------------------------

// PutSetupToken stores the hash of a new setup token, replacing any other.
func (s *Store) PutSetupToken(ctx context.Context, hash string, expires time.Time) error {
	_, err := s.db.Exec(ctx, `INSERT INTO setup_token (id, token_hash, expires_at) VALUES (1, $1, $2)
		ON CONFLICT (id) DO UPDATE SET token_hash = $1, expires_at = $2`, hash, expires)
	return mapErr(err)
}

// SetupTokenValid reports whether hash is the current, unexpired setup token.
func (s *Store) SetupTokenValid(ctx context.Context, hash string, now time.Time) (bool, error) {
	var ok bool
	err := s.db.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM setup_token WHERE token_hash = $1 AND expires_at > $2)", hash, now).Scan(&ok)
	return ok, mapErr(err)
}

// ClaimSetup consumes the setup token and makes userID an administrator,
// atomically: of two people racing through the same link, one wins.
func (s *Store) ClaimSetup(ctx context.Context, hash, userID string, now time.Time) (bool, error) {
	claimed := false
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "DELETE FROM setup_token WHERE token_hash = $1 AND expires_at > $2", hash, now)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		tag, err = tx.Exec(ctx, "UPDATE users SET admin_granted = true, is_admin = true WHERE id = $1", userID)
		if err == nil && tag.RowsAffected() == 1 {
			claimed = true
		} else if err == nil {
			err = domain.ErrNotFound
		}
		return err
	})
	return claimed, mapErr(err)
}

// DeleteSetupToken removes any setup token.
func (s *Store) DeleteSetupToken(ctx context.Context) error {
	_, err := s.db.Exec(ctx, "DELETE FROM setup_token")
	return mapErr(err)
}
