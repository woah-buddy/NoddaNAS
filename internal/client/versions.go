package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/woah-buddy/FrontDir/internal/e2ee"
)

// Version history with verified authors (docs/E2EE.md §5b).

// versionDigest is what the server reports so a client can check who signed
// a version without downloading it.
type versionDigest struct {
	Prefix   string `json:"prefix"`
	BodyHash string `json:"bodyHash"`
	Trailer  string `json:"trailer"`
}

// ErrNoDigest means the server has not (yet) reported what is needed to
// verify a version's author.
var ErrNoDigest = errors.New("the version's author cannot be checked yet")

// open parses the prefix and checks its key commitment against nk.
func (d *versionDigest) open(nk *e2ee.NodeKey) (*e2ee.Prefix, *e2ee.FileKeys, error) {
	raw, err := e2ee.UnB64(d.Prefix)
	if err != nil {
		return nil, nil, e2ee.ErrMalformed
	}
	p, err := e2ee.ParsePrefix(bytes.NewReader(raw))
	if err != nil {
		return nil, nil, err
	}
	if p.BodyOffset() != int64(len(raw)) {
		return nil, nil, e2ee.ErrMalformed
	}
	k, err := p.Keys(nk)
	if err != nil {
		return nil, nil, err
	}
	return p, k, nil
}

// verifyAuthor returns the user who signed the version p is the header of,
// after checking their signature over it. p must have passed Keys.
func (c *Client) verifyAuthor(ctx context.Context, p *e2ee.Prefix, d *versionDigest) (*e2ee.PublicUser, error) {
	if d.BodyHash == "" || d.Trailer == "" {
		return nil, ErrNoDigest
	}
	bh, err1 := e2ee.UnB64(d.BodyHash)
	tr, err2 := e2ee.UnB64(d.Trailer)
	if err1 != nil || err2 != nil {
		return nil, e2ee.ErrMalformed
	}
	signer, err := c.UserKeys(ctx, p.Signer.User)
	if err != nil {
		return nil, err
	}
	if err := p.VerifyDigest(signer, bh, tr); err != nil {
		return nil, err
	}
	return signer, nil
}

// Version is one stored version of a file.
type Version struct {
	ID         string
	Size       int64     // encrypted size
	CreatedAt  time.Time // the server's clock
	UploadedBy string    // the server's word for who stored it
	// Author is who wrote and signed this version, verified; nil if that
	// could not be checked, and AuthorErr says why.
	Author    *e2ee.PublicUser
	AuthorErr error
	// From the version's signed record (§5c), when it has one that
	// verifies: its position, whether it was saved or restored, when (by
	// the storer's clock) and who stored it.
	Seq      int64
	Kind     string
	SavedAt  time.Time
	StoredBy *e2ee.PublicUser

	prefix *e2ee.Prefix
	record *e2ee.SignedRecord
}

// History is a file's versions, newest first, checked as a whole.
type History struct {
	Versions []Version
	// Err is nil if the signed history checks out and is not older than,
	// or different from, what this client saw before. Otherwise it wraps
	// e2ee.ErrHistory, e2ee.ErrRolledBack or e2ee.ErrForked.
	Err  error
	head *e2ee.SignedRecord
}

type versionJSON struct {
	ID        string    `json:"id"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"createdAt"`
	CreatedBy string    `json:"createdBy"`
	Record    string    `json:"record"`
	RecordSig string    `json:"recordSig"`
	versionDigest
}

// Versions lists a file's versions, newest first, verifies who wrote and
// who stored each one, checks the signed history, and compares it with
// what this client saw before (remembering it if it is newer).
func (c *Client) Versions(ctx context.Context, nodeID string) (*History, error) {
	return c.history(ctx, nodeID, false)
}

// history fetches and checks a file's history. With accept, a history
// that is internally sound is remembered even if it is older than, or
// different from, what was seen before (the user accepts it).
func (c *Client) history(ctx context.Context, nodeID string, accept bool) (*History, error) {
	acct, err := c.requireUnlocked()
	if err != nil {
		return nil, err
	}
	nk, err := c.cachedKey(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Versions []versionJSON `json:"versions"`
	}
	if err := c.json(ctx, "GET", "/api/v1/nodes/"+url.PathEscape(nodeID)+"/versions", nil, &resp); err != nil {
		return nil, err
	}
	h := &History{Versions: make([]Version, len(resp.Versions))}
	entries := make([]e2ee.HistoryEntry, len(resp.Versions))
	for i, v := range resp.Versions {
		out := &h.Versions[i]
		*out = Version{ID: v.ID, Size: v.Size, CreatedAt: v.CreatedAt, UploadedBy: v.CreatedBy, AuthorErr: ErrNoDigest}
		if v.Prefix != "" {
			if p, _, err := v.open(nk); err != nil {
				out.AuthorErr = err
			} else {
				out.prefix = p
				out.Author, out.AuthorErr = c.verifyAuthor(ctx, p, &v.versionDigest)
			}
		}
		if v.Record != "" {
			raw, err1 := e2ee.UnB64(v.Record)
			sig, err2 := e2ee.UnB64(v.RecordSig)
			r, err := e2ee.ParseRecord(raw, sig)
			if err1 != nil || err2 != nil || err != nil {
				h.Err = fmt.Errorf("%w: malformed version record", e2ee.ErrHistory)
			}
			out.record = r
		}
		entries[i] = e2ee.HistoryEntry{Prefix: out.prefix, Record: out.record}
	}
	if h.Err != nil {
		return h, nil
	}
	head, err := e2ee.VerifyHistory(nodeID, entries, func(id string) (*e2ee.PublicUser, error) { return c.UserKeys(ctx, id) })
	for i := range entries {
		if r := entries[i].Record; r != nil && entries[i].StoredBy != nil {
			v := &h.Versions[i]
			v.Seq, v.Kind, v.SavedAt, v.StoredBy = r.Seq, r.Kind, time.UnixMilli(r.At), entries[i].StoredBy
		}
	}
	if err != nil {
		h.Err = err
		return h, nil
	}
	h.head = head
	if !accept {
		var recs []*e2ee.SignedRecord
		for _, e := range entries {
			if e.Record != nil {
				recs = append(recs, e.Record)
			}
		}
		if h.Err = e2ee.CheckFresh(c.seenFor(acct, nodeID), recs); h.Err != nil {
			return h, nil
		}
	}
	if head != nil {
		c.remember(acct, nodeID, head, accept)
	}
	return h, nil
}

// AcceptCurrent accepts the history the server shows for a file as it is,
// after a rollback or fork warning (for example after the server was
// restored from a backup). The history must still check out on its own.
func (c *Client) AcceptCurrent(ctx context.Context, nodeID string) error {
	h, err := c.history(ctx, nodeID, true)
	if err != nil {
		return err
	}
	if h.Err != nil {
		return h.Err
	}
	if h.head == nil {
		acct, _ := c.requireUnlocked()
		c.seen.Forget(acct.UserID, nodeID)
	}
	return nil
}

// nextRecord signs the record for a new version of nodeID with the
// container whose prefix is p, after checking the file's history: a
// client must not build on a history that is broken, rolled back or
// forked. For a new file, pass newFile.
func (c *Client) nextRecord(ctx context.Context, nodeID string, p *e2ee.Prefix, kind string, newFile bool) (*e2ee.SignedRecord, error) {
	acct, err := c.requireUnlocked()
	if err != nil {
		return nil, err
	}
	rec := e2ee.VersionRecord{Node: nodeID, Seq: 1, Container: e2ee.B64(p.Hash()), Kind: kind, At: time.Now().UnixMilli()}
	if !newFile {
		h, err := c.history(ctx, nodeID, false)
		if err != nil {
			return nil, err
		}
		if h.Err != nil {
			return nil, fmt.Errorf("not saving on top of this file's history: %w", h.Err)
		}
		if h.head != nil {
			rec.Seq, rec.Prev = h.head.Seq+1, e2ee.B64(h.head.Hash())
		}
	}
	return e2ee.SignRecord(acct, rec)
}

// recordHeaders carries a record with an upload.
func recordHeaders(r *e2ee.SignedRecord, h map[string]string) map[string]string {
	if h == nil {
		h = map[string]string{}
	}
	h["X-FrontDir-Record"] = e2ee.B64(r.Raw)
	h["X-FrontDir-Record-Sig"] = e2ee.B64(r.Sig)
	return h
}

// checkServedRecord checks the record the server sent with a file's
// content against the content's prefix and against what this client saw
// before. Content without a record is fine only for files whose history
// this client has never seen signed.
func (c *Client) checkServedRecord(ctx context.Context, nodeID string, p *e2ee.Prefix, recB64, sigB64 string) error {
	acct, err := c.requireUnlocked()
	if err != nil {
		return err
	}
	seen := c.seenFor(acct, nodeID)
	if recB64 == "" {
		if seen != nil {
			return e2ee.ErrRolledBack // the server dropped a history this client saw
		}
		return nil
	}
	raw, err1 := e2ee.UnB64(recB64)
	sig, err2 := e2ee.UnB64(sigB64)
	if err1 != nil || err2 != nil {
		return fmt.Errorf("%w: malformed version record", e2ee.ErrHistory)
	}
	r, err := e2ee.ParseRecord(raw, sig)
	if err != nil {
		return err
	}
	// Checked alone, a record is a history of one (its predecessors look
	// deleted, which is allowed): this verifies its signature, file,
	// container and, for a save, that its signer wrote the container.
	if _, err := e2ee.VerifyHistory(nodeID, []e2ee.HistoryEntry{{Prefix: p, Record: r}},
		func(id string) (*e2ee.PublicUser, error) { return c.UserKeys(ctx, id) }); err != nil {
		return err
	}
	decided, err := e2ee.CheckFreshHead(seen, r)
	if err != nil {
		return err
	}
	if !decided { // more than one version newer: check the chain in between
		h, err := c.history(ctx, nodeID, false)
		if err != nil {
			return err
		}
		return h.Err
	}
	c.remember(acct, nodeID, r, false)
	return nil
}

// RestoreVersion makes an earlier version current again. The server copies
// it as a new version; it keeps its author (the signature is the original
// one), and the caller signs a record saying they restored it.
func (c *Client) RestoreVersion(ctx context.Context, nodeID, versionID string) (*Node, error) {
	h, err := c.history(ctx, nodeID, false)
	if err != nil {
		return nil, err
	}
	if h.Err != nil {
		return nil, fmt.Errorf("not restoring on top of this file's history: %w", h.Err)
	}
	var src *Version
	for i := range h.Versions {
		if h.Versions[i].ID == versionID {
			src = &h.Versions[i]
		}
	}
	if src == nil || src.prefix == nil {
		return nil, errors.New("no such version, or it cannot be checked")
	}
	acct, _ := c.requireUnlocked()
	rec := e2ee.VersionRecord{Node: nodeID, Seq: 1, Container: e2ee.B64(src.prefix.Hash()), Kind: e2ee.KindRestore, At: time.Now().UnixMilli()}
	if h.head != nil {
		rec.Seq, rec.Prev = h.head.Seq+1, e2ee.B64(h.head.Hash())
	}
	r, err := e2ee.SignRecord(acct, rec)
	if err != nil {
		return nil, err
	}
	var n Node
	err = c.json(ctx, "POST", "/api/v1/nodes/"+url.PathEscape(nodeID)+"/versions/"+url.PathEscape(versionID)+"/restore",
		map[string]string{"record": e2ee.B64(r.Raw), "recordSig": e2ee.B64(r.Sig)}, &n)
	if err != nil {
		return nil, err
	}
	c.remember(acct, nodeID, r, false)
	return &n, nil
}
