package e2ee

import (
	"encoding/json"
	"errors"
	"regexp"
	"unicode/utf8"
)

// Verified contacts (docs/E2EE.md §8).
//
// A user marks another user as verified after comparing key fingerprints
// over some other channel. The list is sealed under a key derived from the
// user's master key, with the user's ID as associated data, and stored on
// the server: the server cannot read it, cannot add to it, and cannot hand
// one user's list to another. It can only withhold it or serve an older
// copy, which leaves people "not verified" rather than falsely verified.

// Contact records one verification.
type Contact struct {
	FP         string `json:"fp"`              // fingerprint at verification time
	Name       string `json:"name"`            // display name shown at verification time
	Email      string `json:"email,omitempty"` // email shown at verification time
	VerifiedAt int64  `json:"verifiedAt"`      // Unix milliseconds
}

// Contacts is the plaintext of a sealed contact list.
type Contacts struct {
	V        int                `json:"v"`
	Contacts map[string]Contact `json:"contacts"` // keyed by user ID
}

// MaxContactsSize bounds a sealed contact list (bytes, before base64). It
// keeps the upload under the server's 64 KiB JSON body limit and allows
// roughly 300 verified people.
const MaxContactsSize = 46 << 10

var (
	idRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
	fpRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

func (a *Account) contactsKey() []byte { return kdf(a.MK, nil, "mk/contacts") }

// SealContacts encrypts a contact list for storage on the server.
func (a *Account) SealContacts(c *Contacts) (string, error) {
	if err := c.validate(); err != nil {
		return "", err
	}
	pt, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	if len(pt)+12+16 > MaxContactsSize {
		return "", errors.New("e2ee: contact list too large")
	}
	return B64(gcmSeal(a.contactsKey(), pt, join("contacts", a.UserID))), nil
}

// OpenContacts decrypts and validates a sealed contact list.
func (a *Account) OpenContacts(sealed string) (*Contacts, error) {
	ct, err := UnB64(sealed)
	if err != nil {
		return nil, ErrAuth
	}
	pt, err := gcmOpen(a.contactsKey(), ct, join("contacts", a.UserID))
	if err != nil {
		return nil, err
	}
	var c Contacts
	if err := json.Unmarshal(pt, &c); err != nil {
		return nil, errors.New("e2ee: malformed contact list")
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Contacts) validate() error {
	if c.V != 1 || c.Contacts == nil {
		return errors.New("e2ee: unsupported contact list version")
	}
	for id, ct := range c.Contacts {
		if !idRE.MatchString(id) || !fpRE.MatchString(ct.FP) || !utf8.ValidString(ct.Name) || len(ct.Name) > 200 ||
			len(ct.Email) > 320 || ct.VerifiedAt <= 0 {
			return errors.New("e2ee: malformed contact entry")
		}
	}
	return nil
}
