package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/woah-buddy/FrontDir/internal/e2ee"
	"github.com/woah-buddy/FrontDir/internal/secure"
)

// File mailboxes (docs/E2EE.md §6a): links anyone can drop files into, and
// nobody can read through. The link is <server>/m#<token>.<public key>;
// the fragment never reaches the server, so the server never learns the
// key that drops are encrypted to.

// MailboxOptions configures a new mailbox.
type MailboxOptions struct {
	Title     string
	Password  string
	ExpiresAt time.Time
	MaxBytes  int64 // required
	MaxFiles  int64 // 0: the server's default
	AutoFile  bool
}

// Mailbox is a mailbox as its manager sees it.
type Mailbox struct {
	ID           string     `json:"id"`
	NodeID       string     `json:"nodeId"`
	SpaceID      string     `json:"spaceId"`
	BoxKey       string     `json:"boxKey"`
	Info         string     `json:"info"`
	ExpiresAt    time.Time  `json:"expiresAt"`
	ClosedAt     *time.Time `json:"closedAt"`
	Accepting    bool       `json:"accepting"`
	AutoFile     bool       `json:"autoFile"`
	PendingFiles int64      `json:"pendingFiles"`
}

// CreateMailbox opens a mailbox on a folder and returns its link.
func (c *Client) CreateMailbox(ctx context.Context, folderID string, o MailboxOptions) (link string, m *Mailbox, err error) {
	nk, err := c.cachedKey(ctx, folderID)
	if err != nil {
		return "", nil, err
	}
	me, err := c.Me(ctx)
	if err != nil {
		return "", nil, err
	}
	id := secure.NewID()
	box, err := e2ee.NewMailbox(id)
	if err != nil {
		return "", nil, err
	}
	info, err := e2ee.SealMailboxInfo(id, box.Public(), e2ee.MailboxInfo{Title: o.Title, Owner: me.User.DisplayName})
	if err != nil {
		return "", nil, err
	}
	var resp struct {
		Mailbox Mailbox `json:"mailbox"`
		Token   string  `json:"token"`
	}
	err = c.json(ctx, "POST", "/api/v1/nodes/"+url.PathEscape(folderID)+"/mailboxes", map[string]any{
		"id": id, "boxKey": box.Wrap(nk), "info": info, "password": o.Password, "expiresAt": o.ExpiresAt,
		"maxBytes": o.MaxBytes, "maxFiles": o.MaxFiles, "autoFile": o.AutoFile}, &resp)
	if err != nil {
		return "", nil, err
	}
	return MailboxLink(c.base, resp.Token, box.Public()), &resp.Mailbox, nil
}

// MailboxLink builds a mailbox's link.
func MailboxLink(base, token string, pub []byte) string {
	return strings.TrimRight(base, "/") + "/m#" + token + "." + e2ee.B64(pub)
}

// ParseMailboxLink splits a mailbox link into server, token and public key.
func ParseMailboxLink(link string) (base, token string, pub []byte, err error) {
	u, err := url.Parse(link)
	if err != nil || u.Path != "/m" || u.Fragment == "" {
		return "", "", nil, errors.New("not a FrontDir mailbox link")
	}
	token, key, ok := strings.Cut(u.Fragment, ".")
	pub, kerr := e2ee.UnB64(key)
	if !ok || kerr != nil || len(pub) != 32 || !secure.ValidToken(token) {
		return "", "", nil, errors.New("this mailbox link is incomplete; copy all of it")
	}
	u.Path, u.Fragment, u.RawQuery = "", "", ""
	return u.String(), token, pub, nil
}

// MailboxForSender is what a sender sees before dropping.
type MailboxForSender struct {
	ID             string
	Title, Owner   string
	ExpiresAt      time.Time
	MaxFileSize    int64
	RemainingBytes int64
	FilesLeft      int64
}

// OpenMailboxLink fetches and decrypts a mailbox's description, as a
// sender. Anyone holding the link can; no account is needed.
func (c *Client) OpenMailboxLink(ctx context.Context, link, password string) (*MailboxForSender, error) {
	_, token, pub, err := ParseMailboxLink(link)
	if err != nil {
		return nil, err
	}
	var resp struct {
		ID             string    `json:"id"`
		Info           string    `json:"info"`
		ExpiresAt      time.Time `json:"expiresAt"`
		MaxFileSize    int64     `json:"maxFileSize"`
		RemainingBytes int64     `json:"remainingBytes"`
		FilesLeft      int64     `json:"filesLeft"`
	}
	if err := c.json(ctx, "POST", "/api/v1/public/mailbox", map[string]string{"token": token, "password": password}, &resp); err != nil {
		return nil, err
	}
	info, err := e2ee.OpenMailboxInfo(resp.ID, pub, resp.Info)
	if err != nil {
		return nil, fmt.Errorf("the mailbox's description does not match its link: %w", err)
	}
	return &MailboxForSender{ID: resp.ID, Title: info.Title, Owner: info.Owner, ExpiresAt: resp.ExpiresAt,
		MaxFileSize: resp.MaxFileSize, RemainingBytes: resp.RemainingBytes, FilesLeft: resp.FilesLeft}, nil
}

// DropFile encrypts r (exactly size bytes) to the mailbox in link and
// uploads it. The sender cannot read it back, or anything else there.
func (c *Client) DropFile(ctx context.Context, link, password, name string, r io.Reader, size int64, note *e2ee.DropNote) error {
	mb, err := c.OpenMailboxLink(ctx, link, password)
	if err != nil {
		return err
	}
	_, token, pub, _ := ParseMailboxLink(link)
	h, body, bodySize, err := e2ee.NewDrop(r, mb.ID, secure.NewID(), pub, size, e2ee.Meta{Name: name, MTime: time.Now().UnixMilli()}, note)
	if err != nil {
		return err
	}
	hdr, _ := json.Marshal(h)
	return c.upload(ctx, "POST", "/api/v1/public/mailbox/drop", body, bodySize, map[string]string{
		"X-FrontDir-Mailbox": token, "X-FrontDir-Mailbox-Password": password, "X-FrontDir-Drop": string(hdr)}, nil)
}

// PendingDrop is a drop waiting in an inbox, decrypted for its manager.
type PendingDrop struct {
	ID        string
	Name      string
	Type      string
	Size      int64 // plaintext
	Note      *e2ee.DropNote
	CreatedAt time.Time // the server's clock
	opened    *e2ee.OpenedDrop
	bodyHash  []byte
}

// Inbox is a mailbox with its pending drops.
type Inbox struct {
	Mailbox Mailbox
	Title   string
	Drops   []PendingDrop
	box     *e2ee.Mailbox
}

// OpenInbox lists a mailbox's pending drops, decrypting each with the
// mailbox key (unwrapped with the folder's key).
func (c *Client) OpenInbox(ctx context.Context, mailboxID string) (*Inbox, error) {
	var resp struct {
		Mailbox Mailbox `json:"mailbox"`
		Drops   []struct {
			ID        string          `json:"id"`
			Header    json.RawMessage `json:"header"`
			BodyHash  string          `json:"bodyHash"`
			CreatedAt time.Time       `json:"createdAt"`
		} `json:"drops"`
	}
	if err := c.json(ctx, "GET", "/api/v1/mailboxes/"+url.PathEscape(mailboxID), nil, &resp); err != nil {
		return nil, err
	}
	nk, err := c.cachedKey(ctx, resp.Mailbox.NodeID)
	if err != nil {
		return nil, err
	}
	box, err := e2ee.OpenMailbox(resp.Mailbox.ID, nk, resp.Mailbox.BoxKey)
	if err != nil {
		return nil, err
	}
	in := &Inbox{Mailbox: resp.Mailbox, box: box}
	if info, err := e2ee.OpenMailboxInfo(box.ID, box.Public(), resp.Mailbox.Info); err == nil {
		in.Title = info.Title
	}
	for _, d := range resp.Drops {
		h, err := e2ee.ParseDropHeader(d.Header)
		if err != nil || h.ID != d.ID {
			return nil, errors.New("a drop's header is malformed")
		}
		od, err := box.OpenDrop(h)
		if err != nil {
			return nil, fmt.Errorf("a drop does not open with this mailbox's key: %w", err)
		}
		bh, err := e2ee.UnB64(d.BodyHash)
		if err != nil {
			return nil, e2ee.ErrMalformed
		}
		in.Drops = append(in.Drops, PendingDrop{ID: d.ID, Name: od.Meta.Name, Type: od.Meta.Type, Size: h.Size, Note: od.Note,
			CreatedAt: d.CreatedAt, opened: od, bodyHash: bh})
	}
	return in, nil
}

// ReadDrop decrypts a pending drop into w, for review before filing. Each
// chunk is authenticated; a drop has no signature (its sender is anonymous).
func (c *Client) ReadDrop(ctx context.Context, in *Inbox, d *PendingDrop, w io.Writer) error {
	resp, err := c.do(ctx, "GET", "/api/v1/mailboxes/"+url.PathEscape(in.Mailbox.ID)+"/drops/"+url.PathEscape(d.ID)+"/content", nil, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, e2ee.BodySize(d.Size)+1))
	if err != nil {
		return err
	}
	if int64(len(body)) != e2ee.BodySize(d.Size) {
		return e2ee.ErrMalformed
	}
	_, err = io.Copy(w, d.opened.Body(bytes.NewReader(body)))
	return err
}

// FileDrop files a pending drop into the mailbox's folder: the drop's key
// is wrapped under the folder, and a container header signed by this user
// goes around the unchanged body (no re-upload). If the name is taken, a
// number is added.
func (c *Client) FileDrop(ctx context.Context, in *Inbox, d *PendingDrop) (*Node, error) {
	acct, err := c.requireUnlocked()
	if err != nil {
		return nil, err
	}
	folder := in.Mailbox.NodeID
	sp, err := c.spaceOf(ctx, folder)
	if err != nil {
		return nil, err
	}
	pub, err := c.spacePub(ctx, sp)
	if err != nil {
		return nil, err
	}
	prefix, err := d.opened.FilePrefix(sp.ID, pub, acct)
	if err != nil {
		return nil, err
	}
	p, err := e2ee.ParsePrefix(bytes.NewReader(prefix))
	if err != nil {
		return nil, err
	}
	trailer := e2ee.FileTrailer(acct, prefix, d.bodyHash)
	name := d.Name
	for attempt := 2; ; attempt++ {
		id := secure.NewID()
		e, err := c.entry(ctx, folder, id, name, d.opened.NK)
		if err != nil {
			return nil, err
		}
		rec, err := c.nextRecord(ctx, id, p, e2ee.KindDrop, true)
		if err != nil {
			return nil, err
		}
		var n Node
		err = c.json(ctx, "POST", "/api/v1/mailboxes/"+url.PathEscape(in.Mailbox.ID)+"/drops/"+url.PathEscape(d.ID)+"/file", map[string]string{
			"id": id, "nameEnc": e["nameEnc"], "nameHash": e["nameHash"], "wrappedKey": e["wrappedKey"],
			"prefix": e2ee.B64(prefix), "trailer": e2ee.B64(trailer), "record": e2ee.B64(rec.Raw), "recordSig": e2ee.B64(rec.Sig)}, &n)
		var exists *ErrExists
		if errors.As(err, &exists) && attempt < 100 {
			name = numbered(d.Name, attempt)
			continue
		}
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		c.keys[id] = d.opened.NK
		c.mu.Unlock()
		c.remember(acct, id, rec, false)
		n.Name = name
		return &n, nil
	}
}

// numbered turns "report.pdf" into "report (2).pdf".
func numbered(name string, n int) string {
	ext := ""
	if i := strings.LastIndex(name, "."); i > 0 {
		name, ext = name[:i], name[i:]
	}
	return fmt.Sprintf("%s (%d)%s", name, n, ext)
}

// DiscardDrop deletes a pending drop.
func (c *Client) DiscardDrop(ctx context.Context, mailboxID, dropID string) error {
	return c.json(ctx, "DELETE", "/api/v1/mailboxes/"+url.PathEscape(mailboxID)+"/drops/"+url.PathEscape(dropID), nil, nil)
}

// CloseMailbox stops a mailbox accepting drops.
func (c *Client) CloseMailbox(ctx context.Context, mailboxID string) error {
	return c.json(ctx, "POST", "/api/v1/mailboxes/"+url.PathEscape(mailboxID)+"/close", nil, nil)
}

// RevokeMyLinks is the kill switch: it revokes every public link this user
// created and closes every mailbox they opened.
func (c *Client) RevokeMyLinks(ctx context.Context) error {
	return c.json(ctx, "POST", "/api/v1/links/revoke-all", nil, nil)
}
