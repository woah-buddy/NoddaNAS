package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"

	"github.com/woah-buddy/FrontDir/internal/e2ee"
)

// Thumbnails (docs/E2EE.md §5a).

// currentPrefix fetches just the header of a file's current version.
func (c *Client) currentPrefix(ctx context.Context, nodeID string) (string, *e2ee.Prefix, error) {
	resp, err := c.do(ctx, "GET", "/api/v1/nodes/"+url.PathEscape(nodeID)+"/content", nil,
		map[string]string{"Range": fmt.Sprintf("bytes=0-%d", 12+e2ee.MaxHeaderLen-1)}, nil)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	p, err := e2ee.ParsePrefix(io.LimitReader(resp.Body, 12+e2ee.MaxHeaderLen))
	if err != nil {
		return "", nil, err
	}
	return resp.Header.Get("X-FrontDir-Version"), p, nil
}

// AttachThumbnail encrypts, signs and attaches a thumbnail (WebP or JPEG)
// to a file's current version.
func (c *Client) AttachThumbnail(ctx context.Context, nodeID string, img []byte, typ string, w, h int) error {
	acct, err := c.requireUnlocked()
	if err != nil {
		return err
	}
	nk, err := c.cachedKey(ctx, nodeID)
	if err != nil {
		return err
	}
	version, p, err := c.currentPrefix(ctx, nodeID)
	if err != nil {
		return err
	}
	k, err := p.Keys(nk)
	if err != nil {
		return err
	}
	enc, sig, err := e2ee.SealThumb(acct, nodeID, p, k, img, typ, w, h)
	if err != nil {
		return err
	}
	return c.json(ctx, "PUT", "/api/v1/nodes/"+url.PathEscape(nodeID)+"/thumbnail",
		map[string]string{"versionId": version, "enc": enc, "sig": sig}, nil)
}

// ErrNoThumbnail means a file has no thumbnail this user may be shown.
var ErrNoThumbnail = errors.New("no thumbnail")

// Thumbnail returns a file's thumbnail, applying the display rule: made by
// the current version's author, or by this user, and verified.
func (c *Client) Thumbnail(ctx context.Context, nodeID string) (*e2ee.Thumb, []byte, error) {
	acct, err := c.requireUnlocked()
	if err != nil {
		return nil, nil, err
	}
	nk, err := c.cachedKey(ctx, nodeID)
	if err != nil {
		return nil, nil, err
	}
	var resp struct {
		Prefix     string `json:"prefix"`
		Thumbnails []struct {
			Maker string `json:"maker"`
			Enc   string `json:"enc"`
			Sig   string `json:"sig"`
		} `json:"thumbnails"`
	}
	if err := c.json(ctx, "GET", "/api/v1/nodes/"+url.PathEscape(nodeID)+"/thumbnail", nil, &resp); err != nil {
		var ae *APIError
		if errors.As(err, &ae) && ae.Status == 404 {
			return nil, nil, ErrNoThumbnail
		}
		return nil, nil, err
	}
	raw, err := e2ee.UnB64(resp.Prefix)
	if err != nil {
		return nil, nil, e2ee.ErrMalformed
	}
	p, err := e2ee.ParsePrefix(bytes.NewReader(raw))
	if err != nil {
		return nil, nil, err
	}
	k, err := p.Keys(nk) // the header that names the author belongs to this node
	if err != nil {
		return nil, nil, err
	}
	// The author's thumbnail first, then the viewer's own.
	for _, want := range []string{p.Signer.User, acct.UserID} {
		for _, t := range resp.Thumbnails {
			if t.Maker != want {
				continue
			}
			maker, err := c.UserKeys(ctx, t.Maker)
			if err != nil || !e2ee.ThumbAuthorOK(p, maker, acct.UserID) {
				continue
			}
			if th, img, err := e2ee.OpenThumb(maker, nodeID, p, k, t.Enc, t.Sig); err == nil {
				return th, img, nil
			}
		}
	}
	return nil, nil, ErrNoThumbnail
}
