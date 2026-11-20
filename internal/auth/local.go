package auth

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/woah-buddy/FrontDir/internal/domain"
	"github.com/woah-buddy/FrontDir/internal/secure"
	"github.com/woah-buddy/FrontDir/internal/validate"
)

// Local accounts: an email, a password and a one-time code from an
// authenticator app (TOTP, RFC 6238), for people without an account at an
// identity provider, or for servers without one.
//
// Every local account has both factors; there is no password-only sign-in.
// Accounts are created by an administrator (or, for the first one, through
// the setup link), who passes on a one-time invite link; the person sets
// their password and adds FrontDir to their authenticator app, and only a
// correct first code makes either take effect. A lost authenticator is
// recovered with single-use recovery codes, or a reset link from an
// administrator or the operator (`frontdir reset-mfa`).
//
// Defences: Argon2id password hashes; TOTP secrets encrypted with a key
// derived from the settings key; each code accepted once; per-account
// lockout after repeated failures (passwords and codes alike), on top of
// the per-address rate limit; the same answer and the same work whether
// or not an account exists, so the login form does not reveal who has one.
//
// The login password is separate from the encryption passphrase, and must
// stay so: the server sees the login password, and must never learn the
// passphrase. The web app refuses a passphrase equal to the login password.

// LocalLogin is a local account's credentials.
type LocalLogin struct {
	UserID         string
	Login          string // lower-case email
	PasswordHash   string
	TOTPSecret     string // sealed
	TOTPLastStep   int64
	FailedAttempts int
	LockedUntil    *time.Time
	CreatedAt      time.Time
	CreatedBy      string
}

// Usable reports whether the account has a password and an authenticator.
func (l *LocalLogin) Usable() bool { return l.PasswordHash != "" && l.TOTPSecret != "" }

// LocalTicket is one step of sign-in or enrolment.
type LocalTicket struct {
	TokenHash       string
	UserID          string
	Kind            string // invite, reset, enroll, mfa
	Parent          string // enroll: the invite or reset ticket it continues
	PendingPassword string // enroll: the chosen password's hash
	PendingSecret   string // enroll: the new TOTP secret, sealed
	Attempts        int
	CreatedAt       time.Time
	ExpiresAt       time.Time
}

// LocalStore persists local accounts.
type LocalStore interface {
	EnsureLocalLogin(ctx context.Context, l *LocalLogin) error
	GetLocalLogin(ctx context.Context, userID string) (*LocalLogin, error)
	GetLocalLoginByLogin(ctx context.Context, login string) (*LocalLogin, error)
	SetLocalCredentials(ctx context.Context, userID, passwordHash, totpSecret string, step int64, recoveryHashes []string) error
	DisableLocalLogin(ctx context.Context, userID string) error
	RecordLocalFailure(ctx context.Context, userID string, threshold int, until time.Time) error
	ResetLocalFailures(ctx context.Context, userID string) error
	AdvanceTOTP(ctx context.Context, userID string, step int64) (bool, error)
	UseRecoveryCode(ctx context.Context, userID, codeHash string) (bool, error)
	CountRecoveryCodes(ctx context.Context, userID string) (int, error)
	CreateLocalTicket(ctx context.Context, t *LocalTicket) error
	GetLocalTicket(ctx context.Context, tokenHash string, now time.Time) (*LocalTicket, error)
	BumpTicketAttempts(ctx context.Context, tokenHash string, limit int) (bool, error)
	ConsumeLocalTicket(ctx context.Context, tokenHash string) (bool, error)
	DeleteLocalTickets(ctx context.Context, userID string, kinds []string) error
	SetSessionReauth(ctx context.Context, tokenHash string, at time.Time) error
}

const (
	InviteTTL        = 7 * 24 * time.Hour
	ResetTTL         = 24 * time.Hour
	enrollTTL        = 15 * time.Minute
	mfaTTL           = 5 * time.Minute
	ticketAttempts   = 5  // wrong codes per ticket
	localMaxFailures = 10 // wrong passwords or codes per account, then a lockout
	localLockout     = 15 * time.Minute
	recoveryCodes    = 10
	minPassword      = 12
	totpAADPrefix    = "frontdir/totp/v1\x00"
	purposeTicket    = "frontdir/local-ticket/v1"
	purposeRecovery  = "frontdir/recovery-code/v1"
)

// Errors that leave nothing to learn: the same for an unknown account, a
// wrong password, a locked account, a wrong code or an expired step.
var (
	ErrLocalSignIn = domain.E(domain.CodeUnauthorized, "wrong email, password or code, or too many attempts: try again in a while")
	ErrLocalLink   = domain.E(domain.CodeUnauthorized, "this link is not valid or has expired; ask an administrator for a new one")
	errLocalOff    = domain.E(domain.CodeForbidden, "local accounts are not enabled on this server")
	errNoSealer    = domain.E(domain.CodePrecondition, "local accounts need FRONTDIR_SETTINGS_KEY (one-time-code secrets are encrypted with it)")
)

// dummyHash is verified against when there is no account, so that an
// unknown email costs the same time as a wrong password.
var dummyHash = secure.HashPassword(secure.NewToken())

// SetLocalSealer sets the key that encrypts TOTP secrets (derived from the
// settings key). Without it, local accounts are unavailable.
func (m *Manager) SetLocalSealer(s *secure.Sealer) { m.sealer.Store(s) }

func (m *Manager) local() (LocalStore, *secure.Sealer, error) {
	ls, ok := m.store.(LocalStore)
	if !ok {
		return nil, nil, errLocalOff
	}
	if !m.svc.LocalAccountsOn() {
		return nil, nil, errLocalOff
	}
	sealer := m.sealer.Load()
	if sealer == nil {
		return nil, nil, errNoSealer
	}
	return ls, sealer, nil
}

// LocalEnabled reports whether local sign-in is available.
func (m *Manager) LocalEnabled() bool {
	_, _, err := m.local()
	return err == nil
}

// CheckLocalPassword applies the password rules: at least 12 characters,
// not mostly one character, not containing the email's name, not a
// well-known password. (The encryption passphrase is a different secret:
// the web app refuses to reuse one as the other.)
func CheckLocalPassword(password, email string) error {
	n := utf8.RuneCountInString(password)
	if n < minPassword || len(password) > 256 {
		return domain.E(domain.CodeInvalid, "use at least %d characters (a few unrelated words work well)", minPassword)
	}
	lower := strings.ToLower(password)
	counts := map[rune]int{}
	for _, r := range lower {
		counts[r]++
	}
	if len(counts) < 5 {
		return domain.E(domain.CodeInvalid, "this password repeats too few different characters")
	}
	if name, _, _ := strings.Cut(strings.ToLower(email), "@"); len(name) >= 4 && strings.Contains(lower, name) {
		return domain.E(domain.CodeInvalid, "the password must not contain your email address")
	}
	for _, w := range commonPasswords {
		if strings.Contains(lower, w) && n < len(w)+6 {
			return domain.E(domain.CodeInvalid, "this password is too close to a well-known one")
		}
	}
	return nil
}

// commonPasswords are cores of the most used passwords; a password that is
// little more than one of them is refused. (Not a full breached-password
// list; long passphrases are the real defence.)
var commonPasswords = []string{"password", "passw0rd", "123456", "qwerty", "letmein", "welcome", "admin", "iloveyou",
	"monkey", "dragon", "football", "baseball", "sunshine", "princess", "abc123", "111111", "trustno1", "master",
	"shadow", "superman", "michael", "starwars", "whatever", "freedom", "frontdir", "changeme", "secret", "login"}

// NewLocalInvite prepares a local account for its owner to set up: it
// creates the login row if needed and returns a one-time invite token.
// With reset, the account's current password, authenticator, recovery
// codes and sessions stop working at once, and the token is a reset link.
func (m *Manager) NewLocalInvite(ctx context.Context, user *domain.User, createdBy string, reset bool) (string, time.Time, error) {
	ls, _, err := m.local()
	if err != nil {
		return "", time.Time{}, err
	}
	email, err := validate.Email(user.Email)
	if err != nil || user.Issuer != domain.IssuerLocal {
		return "", time.Time{}, domain.E(domain.CodeInvalid, "not a local account with an email address")
	}
	now := m.now()
	if err := ls.EnsureLocalLogin(ctx, &LocalLogin{UserID: user.ID, Login: email, CreatedAt: now, CreatedBy: createdBy}); err != nil {
		return "", time.Time{}, err
	}
	kind, ttl := "invite", InviteTTL
	if reset {
		kind, ttl = "reset", ResetTTL
		if err := ls.DisableLocalLogin(ctx, user.ID); err != nil {
			return "", time.Time{}, err
		}
		if err := m.store.DeleteUserSessions(ctx, user.ID); err != nil {
			return "", time.Time{}, err
		}
	}
	if err := ls.DeleteLocalTickets(ctx, user.ID, []string{"invite", "reset", "enroll"}); err != nil {
		return "", time.Time{}, err
	}
	token := secure.NewToken()
	exp := now.Add(ttl)
	t := &LocalTicket{TokenHash: secure.HashToken(purposeTicket, token), UserID: user.ID, Kind: kind, CreatedAt: now, ExpiresAt: exp}
	if err := ls.CreateLocalTicket(ctx, t); err != nil {
		return "", time.Time{}, err
	}
	m.log.InfoContext(ctx, "audit", "event", "local."+kind+".issued", "user", user.ID, "by", createdBy)
	return token, exp, nil
}

func (m *Manager) ticket(ctx context.Context, ls LocalStore, token string, kinds ...string) (*LocalTicket, error) {
	if !secure.ValidToken(token) {
		return nil, ErrLocalLink
	}
	t, err := ls.GetLocalTicket(ctx, secure.HashToken(purposeTicket, token), m.now())
	if errors.Is(err, domain.ErrNotFound) {
		return nil, ErrLocalLink
	}
	if err != nil {
		return nil, err
	}
	for _, k := range kinds {
		if t.Kind == k {
			return t, nil
		}
	}
	return nil, ErrLocalLink
}

// LocalInvite describes an invite or reset link to the person opening it.
type LocalInvite struct {
	User  *domain.User
	Reset bool
}

// OpenLocalInvite checks an invite or reset token.
func (m *Manager) OpenLocalInvite(ctx context.Context, token string) (*LocalInvite, error) {
	ls, _, err := m.local()
	if err != nil {
		return nil, err
	}
	t, err := m.ticket(ctx, ls, token, "invite", "reset")
	if err != nil {
		return nil, err
	}
	u, err := m.svc.UserByID(ctx, t.UserID)
	if err != nil {
		return nil, err
	}
	return &LocalInvite{User: u, Reset: t.Kind == "reset"}, nil
}

// Enrollment is the authenticator to add: the secret as a URI (for a QR
// code) and as text, and the token to confirm it with.
type Enrollment struct {
	Token  string
	URI    string
	Secret string
}

// StartLocalEnroll takes the new password for an invite or reset and makes
// a TOTP secret. Neither takes effect until FinishLocalEnroll confirms a
// code from the authenticator app.
func (m *Manager) StartLocalEnroll(ctx context.Context, token, password, issuer string) (*Enrollment, error) {
	ls, sealer, err := m.local()
	if err != nil {
		return nil, err
	}
	parent, err := m.ticket(ctx, ls, token, "invite", "reset")
	if err != nil {
		return nil, err
	}
	u, err := m.svc.UserByID(ctx, parent.UserID)
	if err != nil {
		return nil, err
	}
	if err := CheckLocalPassword(password, u.Email); err != nil {
		return nil, err
	}
	if err := ls.DeleteLocalTickets(ctx, u.ID, []string{"enroll"}); err != nil {
		return nil, err
	}
	secret := secure.NewTOTPSecret()
	et := secure.NewToken()
	now := m.now()
	t := &LocalTicket{TokenHash: secure.HashToken(purposeTicket, et), UserID: u.ID, Kind: "enroll", Parent: parent.TokenHash,
		PendingPassword: secure.HashPassword(password), PendingSecret: sealer.Seal(totpAADPrefix+u.ID, secret),
		CreatedAt: now, ExpiresAt: now.Add(enrollTTL)}
	if err := ls.CreateLocalTicket(ctx, t); err != nil {
		return nil, err
	}
	return &Enrollment{Token: et, URI: secure.TOTPURI(issuer, u.Email, secret), Secret: secure.TOTPSecretText(secret)}, nil
}

// FinishLocalEnroll confirms the authenticator with its first code. Then
// the password and secret take effect, the invite or reset is used up,
// fresh recovery codes are made (returned once), and the person is signed
// in. After a reset, every other session has already ended.
func (m *Manager) FinishLocalEnroll(ctx context.Context, token, code string) (*LoginResult, []string, error) {
	ls, sealer, err := m.local()
	if err != nil {
		return nil, nil, err
	}
	t, err := m.ticket(ctx, ls, token, "enroll")
	if err != nil {
		return nil, nil, err
	}
	secret, err := sealer.Open(totpAADPrefix+t.UserID, t.PendingSecret)
	if err != nil {
		return nil, nil, err
	}
	now := m.now()
	step, ok := secure.VerifyTOTP(secret, code, now, 0)
	if !ok {
		if _, err := ls.BumpTicketAttempts(ctx, t.TokenHash, ticketAttempts); err != nil {
			return nil, nil, err
		}
		return nil, nil, domain.E(domain.CodeUnauthorized, "that code is not right: check the time on your phone, and type the newest code")
	}
	// The invite or reset must still be valid (an administrator may have
	// issued a new one), and is consumed with this ticket.
	if okParent, err := ls.ConsumeLocalTicket(ctx, t.Parent); err != nil || !okParent {
		return nil, nil, ErrLocalLink
	}
	if okT, err := ls.ConsumeLocalTicket(ctx, t.TokenHash); err != nil || !okT {
		return nil, nil, ErrLocalLink
	}
	codes := make([]string, recoveryCodes)
	hashes := make([]string, recoveryCodes)
	for i := range codes {
		codes[i] = secure.NewRecoveryCode()
		hashes[i] = secure.HashToken(purposeRecovery, secure.NormalizeRecoveryCode(codes[i]))
	}
	if err := ls.SetLocalCredentials(ctx, t.UserID, t.PendingPassword, sealer.Seal(totpAADPrefix+t.UserID, secret), step, hashes); err != nil {
		return nil, nil, err
	}
	u, err := m.svc.UserByID(ctx, t.UserID)
	if err != nil {
		return nil, nil, err
	}
	m.log.InfoContext(ctx, "audit", "event", "local.enrolled", "user", u.ID)
	return &LoginResult{User: u, ReturnTo: "/", ReauthAt: now}, codes, nil
}

// StartLocalLogin checks an email and password and returns a ticket for
// the second step (the one-time code). Every failure looks the same.
func (m *Manager) StartLocalLogin(ctx context.Context, email, password string) (string, error) {
	ls, _, err := m.local()
	if err != nil {
		return "", err
	}
	l, err := m.lookupLocal(ctx, ls, email)
	if err != nil {
		return "", err
	}
	if l == nil || !l.Usable() || l.locked(m.now()) {
		secure.VerifyPassword(password, dummyHash) // same work as a real check
		return "", ErrLocalSignIn
	}
	if !secure.VerifyPassword(password, l.PasswordHash) {
		return "", m.localFailure(ctx, ls, l.UserID, "password")
	}
	token := secure.NewToken()
	now := m.now()
	if err := ls.CreateLocalTicket(ctx, &LocalTicket{TokenHash: secure.HashToken(purposeTicket, token), UserID: l.UserID, Kind: "mfa",
		CreatedAt: now, ExpiresAt: now.Add(mfaTTL)}); err != nil {
		return "", err
	}
	return token, nil
}

// FinishLocalLogin checks the one-time code (or a recovery code) for a
// ticket from StartLocalLogin and completes the sign-in.
func (m *Manager) FinishLocalLogin(ctx context.Context, token, code string) (*LoginResult, error) {
	ls, sealer, err := m.local()
	if err != nil {
		return nil, err
	}
	t, err := m.ticket(ctx, ls, token, "mfa")
	if err != nil {
		return nil, ErrLocalSignIn
	}
	l, err := ls.GetLocalLogin(ctx, t.UserID)
	if err != nil {
		return nil, err
	}
	now := m.now()
	if !l.Usable() || l.locked(now) {
		return nil, ErrLocalSignIn
	}
	usedRecovery, err := m.secondFactor(ctx, ls, sealer, l, code)
	if err != nil {
		if _, berr := ls.BumpTicketAttempts(ctx, t.TokenHash, ticketAttempts); berr != nil {
			return nil, berr
		}
		return nil, err
	}
	if ok, err := ls.ConsumeLocalTicket(ctx, t.TokenHash); err != nil || !ok {
		return nil, ErrLocalSignIn // used concurrently
	}
	if err := ls.ResetLocalFailures(ctx, l.UserID); err != nil {
		return nil, err
	}
	u, err := m.svc.UserByID(ctx, l.UserID)
	if err != nil {
		return nil, err
	}
	if usedRecovery {
		m.log.WarnContext(ctx, "audit", "event", "local.recovery_code_used", "user", u.ID)
	}
	return &LoginResult{User: u, ReturnTo: "/", ReauthAt: now}, nil
}

// secondFactor checks a TOTP code (each accepted once) or a recovery code
// (each usable once), counting failures against the account.
func (m *Manager) secondFactor(ctx context.Context, ls LocalStore, sealer *secure.Sealer, l *LocalLogin, code string) (recovery bool, err error) {
	norm := secure.NormalizeRecoveryCode(code)
	if len(norm) == 16 {
		ok, err := ls.UseRecoveryCode(ctx, l.UserID, secure.HashToken(purposeRecovery, norm))
		if err != nil {
			return false, err
		}
		if !ok {
			return false, m.localFailure(ctx, ls, l.UserID, "recovery code")
		}
		return true, nil
	}
	secret, err := sealer.Open(totpAADPrefix+l.UserID, l.TOTPSecret)
	if err != nil {
		return false, err
	}
	step, ok := secure.VerifyTOTP(secret, code, m.now(), l.TOTPLastStep)
	if ok {
		if ok, err = ls.AdvanceTOTP(ctx, l.UserID, step); err != nil {
			return false, err
		}
	}
	if !ok {
		return false, m.localFailure(ctx, ls, l.UserID, "code")
	}
	return false, nil
}

func (m *Manager) localFailure(ctx context.Context, ls LocalStore, userID, what string) error {
	if err := ls.RecordLocalFailure(ctx, userID, localMaxFailures, m.now().Add(localLockout)); err != nil {
		return err
	}
	m.log.WarnContext(ctx, "audit", "event", "local.login_failed", "user", userID, "factor", what)
	return ErrLocalSignIn
}

func (l *LocalLogin) locked(now time.Time) bool {
	return l.LockedUntil != nil && now.Before(*l.LockedUntil)
}

func (m *Manager) lookupLocal(ctx context.Context, ls LocalStore, email string) (*LocalLogin, error) {
	e, err := validate.Email(email)
	if err != nil {
		return nil, nil
	}
	l, err := ls.GetLocalLoginByLogin(ctx, e)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, nil
	}
	return l, err
}

// LocalReauth confirms who is behind a session ("confirm it's you") with
// the password and a one-time code, and marks the session as freshly
// confirmed, as an identity provider's re-authentication does.
func (m *Manager) LocalReauth(ctx context.Context, sessionToken, userID, password, code string) error {
	ls, sealer, err := m.local()
	if err != nil {
		return err
	}
	l, err := ls.GetLocalLogin(ctx, userID)
	if errors.Is(err, domain.ErrNotFound) {
		return domain.E(domain.CodeInvalid, "this account signs in through an identity provider")
	}
	if err != nil {
		return err
	}
	now := m.now()
	if !l.Usable() || l.locked(now) {
		return ErrLocalSignIn
	}
	if !secure.VerifyPassword(password, l.PasswordHash) {
		return m.localFailure(ctx, ls, l.UserID, "password")
	}
	if _, err := m.secondFactor(ctx, ls, sealer, l, code); err != nil {
		return err
	}
	if err := ls.ResetLocalFailures(ctx, l.UserID); err != nil {
		return err
	}
	if !secure.ValidToken(sessionToken) {
		return ErrBadCredentials
	}
	return ls.SetSessionReauth(ctx, secure.HashToken(secure.PurposeSession, sessionToken), now)
}

// DisableLocal stops a local account signing in (operator offboarding):
// password, authenticator and recovery codes are removed. A reset link
// brings it back.
func (m *Manager) DisableLocal(ctx context.Context, userID string) error {
	ls, ok := m.store.(LocalStore)
	if !ok {
		return nil
	}
	return ls.DisableLocalLogin(ctx, userID)
}

// RecoveryCodesLeft reports how many recovery codes a local account has.
func (m *Manager) RecoveryCodesLeft(ctx context.Context, userID string) (int, error) {
	ls, ok := m.store.(LocalStore)
	if !ok {
		return 0, nil
	}
	return ls.CountRecoveryCodes(ctx, userID)
}
