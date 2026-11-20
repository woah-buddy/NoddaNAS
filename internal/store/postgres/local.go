package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/woah-buddy/FrontDir/internal/auth"
	"github.com/woah-buddy/FrontDir/internal/domain"
)

// Local accounts: passwords, TOTP and the tickets of sign-in and enrolment.

const localLoginCols = `user_id, login, password_hash, totp_secret, totp_last_step, failed_attempts, locked_until, created_at, created_by`

func scanLocalLogin(row pgx.Row) (*auth.LocalLogin, error) {
	l := &auth.LocalLogin{}
	err := row.Scan(&l.UserID, &l.Login, &l.PasswordHash, &l.TOTPSecret, &l.TOTPLastStep, &l.FailedAttempts, &l.LockedUntil, &l.CreatedAt, &l.CreatedBy)
	return l, mapErr(err)
}

// EnsureLocalLogin creates a user's local login row unless it exists.
func (s *Store) EnsureLocalLogin(ctx context.Context, l *auth.LocalLogin) error {
	_, err := s.db.Exec(ctx, `INSERT INTO local_logins (user_id, login, created_at, created_by) VALUES ($1,$2,$3,$4)
		ON CONFLICT (user_id) DO NOTHING`, l.UserID, l.Login, l.CreatedAt, l.CreatedBy)
	if isUniqueViolation(err, "local_logins_login_key") {
		return domain.E(domain.CodeConflict, "another local account signs in with this email")
	}
	return mapErr(err)
}

func (s *Store) GetLocalLogin(ctx context.Context, userID string) (*auth.LocalLogin, error) {
	return scanLocalLogin(s.db.QueryRow(ctx, "SELECT "+localLoginCols+" FROM local_logins WHERE user_id=$1", userID))
}

func (s *Store) GetLocalLoginByLogin(ctx context.Context, login string) (*auth.LocalLogin, error) {
	return scanLocalLogin(s.db.QueryRow(ctx, "SELECT "+localLoginCols+" FROM local_logins WHERE login=$1", login))
}

// SetLocalCredentials stores a confirmed password and TOTP secret, replaces
// the recovery codes, clears failures, and deletes the user's invite,
// reset and enrolment tickets, in one transaction.
func (s *Store) SetLocalCredentials(ctx context.Context, userID, passwordHash, totpSecret string, step int64, recoveryHashes []string) error {
	return mapErr(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE local_logins SET password_hash=$2, totp_secret=$3, totp_last_step=$4,
			failed_attempts=0, locked_until=NULL WHERE user_id=$1`, userID, passwordHash, totpSecret, step)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		if _, err := tx.Exec(ctx, "DELETE FROM local_recovery_codes WHERE user_id=$1", userID); err != nil {
			return err
		}
		for _, h := range recoveryHashes {
			if _, err := tx.Exec(ctx, "INSERT INTO local_recovery_codes (user_id, code_hash) VALUES ($1,$2)", userID, h); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, "DELETE FROM local_tickets WHERE user_id=$1 AND kind IN ('invite','reset','enroll')", userID)
		return err
	}))
}

// DisableLocalLogin removes a user's password, TOTP secret and recovery
// codes: they cannot sign in until they finish a reset.
func (s *Store) DisableLocalLogin(ctx context.Context, userID string) error {
	return mapErr(pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "UPDATE local_logins SET password_hash='', totp_secret='', totp_last_step=0 WHERE user_id=$1", userID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM local_recovery_codes WHERE user_id=$1", userID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "DELETE FROM local_tickets WHERE user_id=$1", userID)
		return err
	}))
}

// RecordLocalFailure counts a failed password or code; at threshold the
// account locks until the given time and the count starts again.
func (s *Store) RecordLocalFailure(ctx context.Context, userID string, threshold int, until time.Time) error {
	_, err := s.db.Exec(ctx, `UPDATE local_logins SET
			locked_until    = CASE WHEN failed_attempts + 1 >= $2 THEN $3 ELSE locked_until END,
			failed_attempts = CASE WHEN failed_attempts + 1 >= $2 THEN 0 ELSE failed_attempts + 1 END
		WHERE user_id=$1`, userID, threshold, until)
	return mapErr(err)
}

func (s *Store) ResetLocalFailures(ctx context.Context, userID string) error {
	_, err := s.db.Exec(ctx, "UPDATE local_logins SET failed_attempts=0 WHERE user_id=$1 AND failed_attempts <> 0", userID)
	return mapErr(err)
}

// AdvanceTOTP records that a code for step was used. It fails (false) if a
// code for that step or a later one was already accepted: each code once.
func (s *Store) AdvanceTOTP(ctx context.Context, userID string, step int64) (bool, error) {
	tag, err := s.db.Exec(ctx, "UPDATE local_logins SET totp_last_step=$2 WHERE user_id=$1 AND totp_last_step < $2", userID, step)
	if err != nil {
		return false, mapErr(err)
	}
	return tag.RowsAffected() == 1, nil
}

// UseRecoveryCode consumes a recovery code; false if it is not (or no
// longer) one of the user's.
func (s *Store) UseRecoveryCode(ctx context.Context, userID, codeHash string) (bool, error) {
	tag, err := s.db.Exec(ctx, "DELETE FROM local_recovery_codes WHERE user_id=$1 AND code_hash=$2", userID, codeHash)
	if err != nil {
		return false, mapErr(err)
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Store) CountRecoveryCodes(ctx context.Context, userID string) (int, error) {
	var n int
	err := s.db.QueryRow(ctx, "SELECT count(*) FROM local_recovery_codes WHERE user_id=$1", userID).Scan(&n)
	return n, mapErr(err)
}

func (s *Store) CreateLocalTicket(ctx context.Context, t *auth.LocalTicket) error {
	_, err := s.db.Exec(ctx, `INSERT INTO local_tickets (token_hash, user_id, kind, parent, pending_password, pending_secret,
			created_at, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		t.TokenHash, t.UserID, t.Kind, t.Parent, t.PendingPassword, t.PendingSecret, t.CreatedAt, t.ExpiresAt)
	return mapErr(err)
}

// GetLocalTicket returns a ticket that has not expired.
func (s *Store) GetLocalTicket(ctx context.Context, tokenHash string, now time.Time) (*auth.LocalTicket, error) {
	t := &auth.LocalTicket{}
	err := s.db.QueryRow(ctx, `SELECT token_hash, user_id, kind, parent, pending_password, pending_secret, attempts, created_at, expires_at
		FROM local_tickets WHERE token_hash=$1 AND expires_at > $2`, tokenHash, now).
		Scan(&t.TokenHash, &t.UserID, &t.Kind, &t.Parent, &t.PendingPassword, &t.PendingSecret, &t.Attempts, &t.CreatedAt, &t.ExpiresAt)
	return t, mapErr(err)
}

// BumpTicketAttempts counts a wrong code against a ticket, deleting it at
// the limit. It reports whether the ticket survives.
func (s *Store) BumpTicketAttempts(ctx context.Context, tokenHash string, limit int) (bool, error) {
	var n int
	err := s.db.QueryRow(ctx, "UPDATE local_tickets SET attempts = attempts + 1 WHERE token_hash=$1 RETURNING attempts", tokenHash).Scan(&n)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, mapErr(err)
	}
	if n >= limit {
		_, err = s.db.Exec(ctx, "DELETE FROM local_tickets WHERE token_hash=$1", tokenHash)
		return false, mapErr(err)
	}
	return true, nil
}

// ConsumeLocalTicket deletes a ticket, reporting whether it existed (so
// two requests cannot both use it).
func (s *Store) ConsumeLocalTicket(ctx context.Context, tokenHash string) (bool, error) {
	tag, err := s.db.Exec(ctx, "DELETE FROM local_tickets WHERE token_hash=$1", tokenHash)
	if err != nil {
		return false, mapErr(err)
	}
	return tag.RowsAffected() == 1, nil
}

// DeleteLocalTickets deletes a user's tickets of the given kinds.
func (s *Store) DeleteLocalTickets(ctx context.Context, userID string, kinds []string) error {
	_, err := s.db.Exec(ctx, "DELETE FROM local_tickets WHERE user_id=$1 AND kind = ANY($2::text[])", userID, kinds)
	return mapErr(err)
}

// SetSessionReauth records a fresh confirmation of who is behind a session.
func (s *Store) SetSessionReauth(ctx context.Context, tokenHash string, at time.Time) error {
	_, err := s.db.Exec(ctx, "UPDATE sessions SET reauth_at=$2 WHERE token_hash=$1", tokenHash, at)
	return mapErr(err)
}
