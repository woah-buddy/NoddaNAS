package postgres

import (
	"context"
	"time"

	"github.com/woah-buddy/FrontDir/internal/auth"
	"github.com/woah-buddy/FrontDir/internal/domain"
)

// Session, login-request and app-password persistence. Only hashes of the
// bearer secrets are stored; see internal/secure.HashToken.

func (s *Store) CreateLoginRequest(ctx context.Context, r *auth.LoginRequest) error {
	_, err := s.db.Exec(ctx, `INSERT INTO login_requests (token_hash, kind, state, nonce, pkce_verifier, return_to, reauth, setup_hash, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, r.TokenHash, r.Kind, r.State, r.Nonce, r.Verifier, r.ReturnTo, r.Reauth, nullable(r.Setup), r.ExpiresAt)
	return mapErr(err)
}

// ConsumeLoginRequest deletes and returns the request in one statement, so a
// login request can be used at most once (no replay of the callback).
func (s *Store) ConsumeLoginRequest(ctx context.Context, tokenHash string, now time.Time) (*auth.LoginRequest, error) {
	r := &auth.LoginRequest{}
	err := s.db.QueryRow(ctx, `DELETE FROM login_requests WHERE token_hash=$1
		RETURNING token_hash, kind, state, nonce, pkce_verifier, return_to, reauth, coalesce(setup_hash, ''), expires_at`, tokenHash).
		Scan(&r.TokenHash, &r.Kind, &r.State, &r.Nonce, &r.Verifier, &r.ReturnTo, &r.Reauth, &r.Setup, &r.ExpiresAt)
	if err != nil {
		return nil, mapErr(err)
	}
	if !now.Before(r.ExpiresAt) {
		return nil, domain.ErrNotFound
	}
	return r, nil
}

func (s *Store) CreateSession(ctx context.Context, ss *auth.Session) error {
	_, err := s.db.Exec(ctx, `INSERT INTO sessions (token_hash, user_id, created_at, last_seen_at, expires_at, reauth_at)
		VALUES ($1,$2,$3,$4,$5,$6)`, ss.TokenHash, ss.UserID, ss.CreatedAt, ss.LastSeenAt, ss.ExpiresAt, ss.ReauthAt)
	return mapErr(err)
}

func (s *Store) GetSession(ctx context.Context, tokenHash string) (*auth.Session, error) {
	ss := &auth.Session{}
	err := s.db.QueryRow(ctx, `SELECT token_hash, user_id, created_at, last_seen_at, expires_at, reauth_at
		FROM sessions WHERE token_hash=$1`, tokenHash).
		Scan(&ss.TokenHash, &ss.UserID, &ss.CreatedAt, &ss.LastSeenAt, &ss.ExpiresAt, &ss.ReauthAt)
	return ss, mapErr(err)
}

func (s *Store) TouchSession(ctx context.Context, tokenHash string, now time.Time) error {
	_, err := s.db.Exec(ctx, "UPDATE sessions SET last_seen_at=$2 WHERE token_hash=$1", tokenHash, now)
	return mapErr(err)
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.Exec(ctx, "DELETE FROM sessions WHERE token_hash=$1", tokenHash)
	return mapErr(err)
}

// DeleteAllSessions ends every browser session on the instance.
func (s *Store) DeleteAllSessions(ctx context.Context) (int64, error) {
	tag, err := s.db.Exec(ctx, "DELETE FROM sessions")
	if err != nil {
		return 0, mapErr(err)
	}
	return tag.RowsAffected(), nil
}

func (s *Store) DeleteUserSessions(ctx context.Context, userID string) error {
	_, err := s.db.Exec(ctx, "DELETE FROM sessions WHERE user_id=$1", userID)
	return mapErr(err)
}

// #nosec G101 -- column names, not a credential (only token hashes are stored)
const appPasswordCols = `id, user_id, name, token_hash, read_only, created_at, last_used_at, expires_at`

func (s *Store) CreateAppPassword(ctx context.Context, ap *domain.AppPassword) error {
	_, err := s.db.Exec(ctx, `INSERT INTO app_passwords (`+appPasswordCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		ap.ID, ap.UserID, ap.Name, ap.TokenHash, ap.ReadOnly, ap.CreatedAt, ap.LastUsedAt, ap.ExpiresAt)
	return mapErr(err)
}

func (s *Store) GetAppPassword(ctx context.Context, tokenHash string) (*domain.AppPassword, error) {
	ap := &domain.AppPassword{}
	err := s.db.QueryRow(ctx, "SELECT "+appPasswordCols+" FROM app_passwords WHERE token_hash=$1", tokenHash).
		Scan(&ap.ID, &ap.UserID, &ap.Name, &ap.TokenHash, &ap.ReadOnly, &ap.CreatedAt, &ap.LastUsedAt, &ap.ExpiresAt)
	return ap, mapErr(err)
}

func (s *Store) TouchAppPassword(ctx context.Context, id string, now time.Time) error {
	_, err := s.db.Exec(ctx, "UPDATE app_passwords SET last_used_at=$2 WHERE id=$1", id, now)
	return mapErr(err)
}

func (s *Store) ListAppPasswords(ctx context.Context, userID string) ([]*domain.AppPassword, error) {
	rows, err := s.db.Query(ctx, "SELECT "+appPasswordCols+" FROM app_passwords WHERE user_id=$1 ORDER BY created_at", userID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []*domain.AppPassword
	for rows.Next() {
		ap := &domain.AppPassword{}
		if err := rows.Scan(&ap.ID, &ap.UserID, &ap.Name, &ap.TokenHash, &ap.ReadOnly, &ap.CreatedAt, &ap.LastUsedAt, &ap.ExpiresAt); err != nil {
			return nil, mapErr(err)
		}
		out = append(out, ap)
	}
	return out, mapErr(rows.Err())
}

func (s *Store) DeleteAppPassword(ctx context.Context, userID, id string) error {
	tag, err := s.db.Exec(ctx, "DELETE FROM app_passwords WHERE user_id=$1 AND id=$2", userID, id)
	if err == nil && tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return mapErr(err)
}

// DeleteUserAppPasswords removes all of a user's app passwords.
func (s *Store) DeleteUserAppPasswords(ctx context.Context, userID string) (int64, error) {
	tag, err := s.db.Exec(ctx, "DELETE FROM app_passwords WHERE user_id=$1", userID)
	if err != nil {
		return 0, mapErr(err)
	}
	return tag.RowsAffected(), nil
}

func (s *Store) DeleteExpiredAuth(ctx context.Context, now time.Time) error {
	for _, q := range []string{
		"DELETE FROM login_requests WHERE expires_at < $1",
		"DELETE FROM sessions WHERE expires_at < $1",
		"DELETE FROM app_passwords WHERE expires_at IS NOT NULL AND expires_at < $1",
	} {
		if _, err := s.db.Exec(ctx, q, now); err != nil {
			return mapErr(err)
		}
	}
	return nil
}
