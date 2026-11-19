package settings

import (
	"context"
	"time"

	"github.com/woah-buddy/NoddaNAS/internal/config"
	"github.com/woah-buddy/NoddaNAS/internal/domain"
	"github.com/woah-buddy/NoddaNAS/internal/secure"
)

// The one-time setup link.
//
// A new server has no sign-in method, so nobody can sign in to configure
// one: a chicken-and-egg problem. The person who runs the server solves it
// from the server's shell with `noddanas setup-link`, which prints a link
// that works once:
//
//   - The token is 256 random bits. Only its hash is stored, there is at
//     most one, and it expires after 24 hours.
//   - It is printed to the operator's terminal only, never logged: the
//     server log says "run noddanas setup-link", not the link.
//   - It sits in the URL fragment (/setup#token), which browsers never send
//     to servers, proxies or Referer headers; the page reads it and sends it
//     in a request body.
//   - It allows only sign-in settings (and who may sign in), and only until
//     someone signs in through it. That person becomes an administrator,
//     and the token is deleted in the same transaction.
//
// The link is also the way back in when no administrator can sign in (the
// identity provider changed, the last administrator left): the operator
// has shell access, which already outranks any administrator.

// SetupTTL is how long a setup link works.
const SetupTTL = 24 * time.Hour

// NewSetupLink creates a setup token, replacing any earlier one, and
// returns the link to open.
func NewSetupLink(ctx context.Context, store Store, fixed *config.Config, now time.Time) (string, time.Time, error) {
	token := secure.NewToken()
	exp := now.Add(SetupTTL)
	if err := store.PutSetupToken(ctx, secure.HashToken(secure.PurposeSetup, token), exp); err != nil {
		return "", time.Time{}, err
	}
	return fixed.PublicURL.String() + "/setup#" + token, exp, nil
}

var errBadSetupToken = domain.E(domain.CodeUnauthorized,
	"this setup link is not valid or has expired; run `noddanas setup-link` on the server for a new one")

func (m *Manager) setupHash(ctx context.Context, token string) (string, error) {
	if !secure.ValidToken(token) {
		return "", errBadSetupToken
	}
	h := secure.HashToken(secure.PurposeSetup, token)
	ok, err := m.store.SetupTokenValid(ctx, h, m.now())
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errBadSetupToken
	}
	return h, nil
}

// setupGroups are the settings the setup link may change.
func setupGroups(s config.Setting) bool {
	return s.Group == "oidc" || s.Group == "saml" || s.Group == "access"
}

// SetupView returns the sign-in settings for the setup page.
func (m *Manager) SetupView(ctx context.Context, token string) (*View, error) {
	if _, err := m.setupHash(ctx, token); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.viewLocked(setupGroups), nil
}

// SetupSave changes sign-in settings with the setup link.
func (m *Manager) SetupSave(ctx context.Context, token string, req UpdateRequest) (*View, error) {
	if _, err := m.setupHash(ctx, token); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.updateLocked(ctx, &actor{id: "setup-link"}, req, setupGroups); err != nil {
		return nil, err
	}
	return m.viewLocked(setupGroups), nil
}

// SetupLogin checks the token before a sign-in that will complete setup,
// and returns the hash to carry through the sign-in.
func (m *Manager) SetupLogin(ctx context.Context, token string) (string, error) {
	if m.SetupMode() {
		return "", domain.E(domain.CodePrecondition, "save a sign-in method first")
	}
	return m.setupHash(ctx, token)
}

// ClaimSetup finishes setup: the person who just signed in through the
// setup link becomes an administrator and the link stops working. It
// reports false if the link was used or expired in the meantime.
func (m *Manager) ClaimSetup(ctx context.Context, hash, userID string) (bool, error) {
	ok, err := m.store.ClaimSetup(ctx, hash, userID, m.now())
	if err != nil {
		return false, err
	}
	if ok {
		m.log.InfoContext(ctx, "audit", "event", "setup.completed", "user", userID)
	}
	return ok, nil
}
