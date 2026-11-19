package service

import (
	"context"

	"github.com/woah-buddy/NoddaNAS/internal/domain"
	"github.com/woah-buddy/NoddaNAS/internal/e2ee"
	"github.com/woah-buddy/NoddaNAS/internal/validate"
)

// Contacts returns the caller's sealed verified-contacts list ("" if they
// have none yet) and its revision. The server cannot read it (E2EE.md §8).
func (s *Service) Contacts(ctx context.Context, p Principal) (string, int64, error) {
	if p.UserID == "" {
		return "", 0, domain.ErrUnauthorized
	}
	return s.store.GetContacts(ctx, p.UserID)
}

// SetContacts replaces the caller's sealed contact list. revision must be
// the one the client read, so concurrent edits from two devices are
// detected rather than lost.
func (s *Service) SetContacts(ctx context.Context, p Principal, sealed string, revision int64) (int64, error) {
	if p.UserID == "" {
		return 0, domain.ErrUnauthorized
	}
	if p.ReadOnly {
		return 0, domain.E(domain.CodeForbidden, "this credential is read-only")
	}
	if err := validate.Opaque("contacts", sealed, 12+16+1, e2ee.MaxContactsSize); err != nil {
		return 0, err
	}
	if revision < 0 {
		return 0, domain.E(domain.CodeInvalid, "invalid revision")
	}
	rev, err := s.store.SetContacts(ctx, p.UserID, sealed, revision)
	if err != nil {
		return 0, err
	}
	s.audit(ctx, "contacts.update", p, "revision", rev) // content is encrypted; nothing else to log
	return rev, nil
}
