package client

import (
	"bytes"
	"context"
	"errors"
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
	Size       int64 // encrypted size
	CreatedAt  time.Time
	UploadedBy string // who stored it; a restore stores someone else's version
	// Author is who wrote and signed this version, verified; nil if that
	// could not be checked, and AuthorErr says why.
	Author    *e2ee.PublicUser
	AuthorErr error
}

// Versions lists a file's versions, newest first, and verifies who wrote
// each one.
func (c *Client) Versions(ctx context.Context, nodeID string) ([]Version, error) {
	if _, err := c.requireUnlocked(); err != nil {
		return nil, err
	}
	nk, err := c.cachedKey(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Versions []struct {
			ID        string    `json:"id"`
			Size      int64     `json:"size"`
			CreatedAt time.Time `json:"createdAt"`
			CreatedBy string    `json:"createdBy"`
			versionDigest
		} `json:"versions"`
	}
	if err := c.json(ctx, "GET", "/api/v1/nodes/"+url.PathEscape(nodeID)+"/versions", nil, &resp); err != nil {
		return nil, err
	}
	out := make([]Version, len(resp.Versions))
	for i, v := range resp.Versions {
		out[i] = Version{ID: v.ID, Size: v.Size, CreatedAt: v.CreatedAt, UploadedBy: v.CreatedBy}
		if v.Prefix == "" {
			out[i].AuthorErr = ErrNoDigest
			continue
		}
		p, _, err := v.open(nk)
		if err == nil {
			out[i].Author, err = c.verifyAuthor(ctx, p, &v.versionDigest)
		}
		out[i].AuthorErr = err
	}
	return out, nil
}

// RestoreVersion makes an earlier version current again. The server copies
// it as a new version; it keeps its author (the signature is the original
// one) and records the caller as the one who stored it.
func (c *Client) RestoreVersion(ctx context.Context, nodeID, versionID string) (*Node, error) {
	var n Node
	err := c.json(ctx, "POST", "/api/v1/nodes/"+url.PathEscape(nodeID)+"/versions/"+url.PathEscape(versionID)+"/restore", nil, &n)
	if err != nil {
		return nil, err
	}
	return &n, nil
}
