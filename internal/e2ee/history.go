package e2ee

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
)

// Signed version history (docs/E2EE.md §5c).
//
// The container signature (§5, §5b) proves who wrote a version. It says
// nothing about when the version was saved, who put it there (a restore
// re-stores someone else's container), or where it sits in the file's
// history: the server decides all of that. So whoever stores a version
// also signs a small record about it, and each record names the one
// before it (a hash chain, like commits in git):
//
//	{"v":1, "node", "seq", "prev", "container", "kind", "at", "by", "fp"}
//	sig = Ed25519(by, "L/version-record" \0 || record bytes)
//
// seq counts up by one per version; prev is the hash of the previous
// version's record ("" for the first); container is SHA-256 of the
// container's prefix, which identifies one container (it holds a fresh
// salt, and the author's signature ties it to the body); kind is "save"
// (the signer encrypted it) or "restore" (the signer stored an existing
// container again); at is the signer's clock, in Unix milliseconds.
//
// With the chain, the server can no longer reorder versions, slip one in,
// drop one from the middle, or relabel who stored one or when. It can
// still present an older chain as if it were current (cut the newest
// versions off the end) or show different people different chains. Those
// are caught by remembering (CheckFresh): a client that once saw version n
// notices a history that ends before n, or a different version n.

// Version record kinds.
const (
	KindSave    = "save"
	KindRestore = "restore"
)

// MaxRecordLen bounds a record's encoded size.
const MaxRecordLen = 1024

// maxSafeInt is the largest integer JavaScript represents exactly.
const maxSafeInt = 1<<53 - 1

// VersionRecord is what the uploader of a version signs.
type VersionRecord struct {
	V         int    `json:"v"`
	Node      string `json:"node"`
	Seq       int64  `json:"seq"`
	Prev      string `json:"prev"`
	Container string `json:"container"`
	Kind      string `json:"kind"`
	At        int64  `json:"at"`
	By        string `json:"by"`
	FP        string `json:"fp"`
}

// SignedRecord is a record as stored: its exact bytes, its signature, and
// the parsed fields.
type SignedRecord struct {
	VersionRecord
	Raw []byte
	Sig []byte
}

// Errors from history checks.
var (
	// ErrHistory means a file's version history does not check out: a
	// record is forged or misplaced, or the chain is broken.
	ErrHistory = errors.New("e2ee: the file's version history has been tampered with")
	// ErrRolledBack means the server shows an older state of the file than
	// this client has seen before.
	ErrRolledBack = errors.New("e2ee: the file has gone back in time: you have seen a newer version than the server now shows")
	// ErrForked means the server shows a version history that differs from
	// one this client has seen before.
	ErrForked = errors.New("e2ee: the file's history differs from the one you saw before")
)

func historyErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrHistory, fmt.Sprintf(format, a...))
}

func recordMsg(raw []byte) []byte { return append(append(join("version-record"), 0), raw...) }

// Hash returns SHA-256 of the prefix: the container identifier records use.
func (p *Prefix) Hash() []byte { return sum(p.raw) }

// SignRecord signs rec as signer, filling in v, by and fp.
func SignRecord(signer *Account, rec VersionRecord) (*SignedRecord, error) {
	rec.V, rec.By, rec.FP = 1, signer.UserID, signer.Fingerprint()
	raw, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	if err := rec.validate(len(raw)); err != nil {
		return nil, err
	}
	return &SignedRecord{VersionRecord: rec, Raw: raw, Sig: sign(signer.Sig, recordMsg(raw))}, nil
}

// ParseRecord parses a stored record and checks its shape, but not its
// signature (the server uses it to keep honest history; clients also
// Verify). raw and sig are the decoded bytes.
func ParseRecord(raw, sig []byte) (*SignedRecord, error) {
	if len(raw) == 0 || len(raw) > MaxRecordLen || len(sig) != 64 {
		return nil, historyErr("malformed version record")
	}
	var rec VersionRecord
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil || dec.More() {
		return nil, historyErr("malformed version record")
	}
	if err := rec.validate(len(raw)); err != nil {
		return nil, err
	}
	// Only the canonical encoding (what SignRecord and the browser produce:
	// these keys in this order, no spaces) is accepted, so Go and the
	// browser can never read the same bytes differently (key case, number
	// formats, duplicate keys).
	if canon, err := json.Marshal(rec); err != nil || !bytes.Equal(canon, raw) {
		return nil, historyErr("version record is not canonically encoded")
	}
	return &SignedRecord{VersionRecord: rec, Raw: bytes.Clone(raw), Sig: bytes.Clone(sig)}, nil
}

func (r *VersionRecord) validate(n int) error {
	b32 := func(s string) bool { b, err := UnB64(s); return err == nil && len(b) == 32 && B64(b) == s }
	ok := n <= MaxRecordLen && r.V == 1 && isID(r.Node) && isID(r.By) && isHex40(r.FP) &&
		r.Seq >= 1 && r.Seq <= maxSafeInt && r.At > 0 && r.At <= maxSafeInt && b32(r.Container) &&
		(r.Kind == KindSave || r.Kind == KindRestore) &&
		((r.Seq == 1 && r.Prev == "") || (r.Seq > 1 && b32(r.Prev)))
	if !ok {
		return historyErr("malformed version record")
	}
	return nil
}

func isHex40(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Hash returns the record's hash, which the next record names as prev.
func (r *SignedRecord) Hash() []byte { return sum(r.Raw) }

// Verify checks the record's signature against signer, who must be the
// user (and key) the record names.
func (r *SignedRecord) Verify(signer *PublicUser) error {
	if signer.ID != r.By || signer.Finger != r.FP {
		return historyErr("the record names a different signer")
	}
	if verify(signer.Sig, recordMsg(r.Raw), r.Sig) != nil {
		return historyErr("a version record's signature does not verify")
	}
	return nil
}

// Follows reports whether r is the record right after prev.
func (r *SignedRecord) Follows(prev *SignedRecord) bool {
	return r.Seq == prev.Seq+1 && r.Prev == B64(prev.Hash())
}

// HistoryEntry is one version of a file, as a client checks it: the
// container prefix (from the version's digest) and its record, if it has
// one (versions stored before records existed do not).
type HistoryEntry struct {
	Prefix *Prefix
	Record *SignedRecord
	// Set by VerifyHistory when the record verifies: who stored the version.
	StoredBy *PublicUser
}

// VerifyHistory checks a file's versions, newest first, against the rules
// of §5c. Each record must verify, be about this node and this container,
// and (for a save) be signed by the container's author; records must come
// first, newest to oldest, each following the next in an unbroken chain;
// unrecorded versions may only be older than every recorded one. It
// returns the newest record (nil if there are none).
//
// Entries whose record verifies get StoredBy set even when the chain as a
// whole fails, so a client can still show what is individually proven.
func VerifyHistory(nodeID string, entries []HistoryEntry, signerFor func(userID string) (*PublicUser, error)) (*SignedRecord, error) {
	var firstErr error
	fail := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	recorded := 0
	for i := range entries {
		e := &entries[i]
		if e.Record == nil {
			continue
		}
		if i != recorded {
			fail(historyErr("a version without a signed record appears among signed ones"))
		}
		recorded++
		r := e.Record
		switch {
		case r.Node != nodeID:
			fail(historyErr("a version record belongs to another file"))
			continue
		case e.Prefix == nil || subtle.ConstantTimeCompare([]byte(r.Container), []byte(B64(e.Prefix.Hash()))) != 1:
			fail(historyErr("a version record is about a different container"))
			continue
		case r.Kind == KindSave && (e.Prefix.Signer.User != r.By || e.Prefix.Signer.FP != r.FP):
			fail(historyErr("a version is recorded as saved by someone other than its author"))
			continue
		}
		signer, err := signerFor(r.By)
		if err != nil {
			fail(fmt.Errorf("%w: cannot look up who stored a version: %v", ErrHistory, err))
			continue
		}
		if err := r.Verify(signer); err != nil {
			fail(err)
			continue
		}
		e.StoredBy = signer
	}
	if recorded == 0 || firstErr != nil {
		return nil, firstErr
	}
	for i := 0; i+1 < recorded; i++ {
		if !entries[i].Record.Follows(entries[i+1].Record) {
			fail(historyErr("versions are missing, reordered or replaced"))
		}
	}
	// The oldest record either starts the chain or follows versions that
	// were deleted as too old; then nothing older can remain.
	if last := entries[recorded-1].Record; last.Seq > 1 && recorded != len(entries) {
		fail(historyErr("versions are missing before the oldest signed one"))
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return entries[0].Record, nil
}

// Seen is what a client remembers about a file's history: the newest
// record it has verified.
type Seen struct {
	Seq  int64  `json:"seq"`
	Hash []byte `json:"hash"`
}

// SeenOf returns what to remember after verifying head.
func SeenOf(head *SignedRecord) Seen { return Seen{Seq: head.Seq, Hash: head.Hash()} }

// CheckFresh compares a verified history (records newest first, from
// VerifyHistory's entries) with what this client saw before. A history
// that ends before the remembered version is a rollback; one whose
// version at the remembered position differs is a fork. If the remembered
// version is older than every version kept, ancestry cannot be checked.
func CheckFresh(seen *Seen, records []*SignedRecord) error {
	if seen == nil {
		return nil
	}
	if len(records) == 0 || records[0].Seq < seen.Seq {
		return ErrRolledBack
	}
	for _, r := range records {
		if r.Seq == seen.Seq {
			if subtle.ConstantTimeCompare(r.Hash(), seen.Hash) != 1 {
				return ErrForked
			}
			return nil
		}
	}
	return nil
}

// CheckFreshHead is the quick check for a single record (a download
// carries only the current version's). decided is false when head is
// more than one version past the remembered one; then the caller must
// check the whole history (VerifyHistory and CheckFresh) to know.
func CheckFreshHead(seen *Seen, head *SignedRecord) (decided bool, err error) {
	switch {
	case seen == nil:
		return true, nil
	case head == nil || head.Seq < seen.Seq:
		return true, ErrRolledBack
	case head.Seq == seen.Seq:
		if subtle.ConstantTimeCompare(head.Hash(), seen.Hash) != 1 {
			return true, ErrForked
		}
		return true, nil
	case head.Seq == seen.Seq+1:
		if head.Prev != B64(seen.Hash) {
			return true, ErrForked
		}
		return true, nil
	}
	return false, nil
}
