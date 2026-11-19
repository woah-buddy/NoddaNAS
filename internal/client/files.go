package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/woah-buddy/NoddaNAS/internal/e2ee"
	"github.com/woah-buddy/NoddaNAS/internal/secure"
)

// Resolve finds a node by a slash-separated path of real (decrypted)
// names, relative to the personal space root ("" for the root itself).
func (c *Client) Resolve(ctx context.Context, path string) (*Node, error) {
	me, err := c.Me(ctx)
	if err != nil {
		return nil, err
	}
	cur := &Node{ID: me.PersonalSpace.RootID, Kind: "folder", SpaceID: me.PersonalSpace.ID}
	for _, seg := range strings.Split(strings.Trim(path, "/"), "/") {
		if seg == "" {
			continue
		}
		kids, err := c.List(ctx, cur.ID)
		if err != nil {
			return nil, err
		}
		var next *Node
		for _, k := range kids {
			if strings.EqualFold(k.Name, seg) {
				next = k
				break
			}
		}
		if next == nil {
			return nil, fmt.Errorf("%q not found", seg)
		}
		cur = next
	}
	return cur, nil
}

// openContainer downloads a container (current version unless versionID).
func (c *Client) openContainer(ctx context.Context, nodeID, versionID string) (io.ReadCloser, error) {
	path := "/api/v1/nodes/" + nodeID + "/content"
	if versionID != "" {
		path += "?version=" + versionID
	}
	resp, err := c.do(ctx, "GET", path, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// DownloadContainer writes a file's encrypted container to w unchanged:
// an independently restorable backup of that file.
func (c *Client) DownloadContainer(ctx context.Context, nodeID string, w io.Writer) error {
	body, err := c.openContainer(ctx, nodeID, "")
	if err != nil {
		return err
	}
	defer body.Close()
	_, err = io.Copy(w, body)
	return err
}

// Download decrypts a file into w and verifies its signature. On error the
// caller must discard whatever was written.
func (c *Client) Download(ctx context.Context, nodeID string, w io.Writer) (*e2ee.Meta, error) {
	nk, err := c.cachedKey(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	body, err := c.openContainer(ctx, nodeID, "")
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return c.decrypt(ctx, body, nk, w)
}

func (c *Client) decrypt(ctx context.Context, r io.Reader, nk *e2ee.NodeKey, w io.Writer) (*e2ee.Meta, error) {
	p, err := e2ee.ParsePrefix(r)
	if err != nil {
		return nil, err
	}
	k, err := p.Keys(nk) // key commitment: the container belongs to this node
	if err != nil {
		return nil, err
	}
	meta, err := p.DecryptMeta(k)
	if err != nil {
		return nil, err
	}
	signer, err := c.UserKeys(ctx, p.Signer.User)
	if err != nil {
		return nil, err
	}
	return meta, e2ee.DecryptVerify(r, w, p, k, signer)
}

// RestoreContainer restores one backed-up container into a folder. The
// node key comes from the container's own owner seal, opened with the
// space's keys; the container is stored byte-for-byte unchanged.
func (c *Client) RestoreContainer(ctx context.Context, parentID string, container []byte) (*Node, error) {
	p, err := e2ee.ParsePrefix(bytes.NewReader(container))
	if err != nil {
		return nil, err
	}
	sp, err := c.spaceOf(ctx, parentID)
	if err != nil {
		return nil, err
	}
	if p.Owner.Space != sp.ID {
		return nil, fmt.Errorf("this backup belongs to space %s; restore it into a folder of that space", p.Owner.Space)
	}
	s, err := c.openSpace(ctx, sp)
	if err != nil {
		return nil, err
	}
	nk, err := p.OwnerNodeKey(s)
	if err != nil {
		return nil, err
	}
	meta, err := c.decrypt(ctx, bytes.NewReader(container), nk, io.Discard) // full verification first
	if err != nil {
		return nil, fmt.Errorf("backup does not verify: %w", err)
	}
	id := secure.NewID()
	e, err := c.entry(ctx, parentID, id, meta.Name, nk)
	if err != nil {
		return nil, err
	}
	e["id"] = id
	hdr, _ := json.Marshal(e)
	var n Node
	if err := c.upload(ctx, "POST", "/api/v1/nodes/"+parentID+"/files", bytes.NewReader(container), int64(len(container)),
		map[string]string{"X-NoddaNAS-Entry": string(hdr)}, &n); err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.keys[id] = nk
	c.mu.Unlock()
	n.Name = meta.Name
	return &n, nil
}

// Rename renames a node in place.
func (c *Client) Rename(ctx context.Context, n *Node, newName string) error {
	nk, err := c.cachedKey(ctx, n.ID)
	if err != nil {
		return err
	}
	e, err := c.entry(ctx, n.ParentID, n.ID, newName, nk)
	if err != nil {
		return err
	}
	delete(e, "wrappedKey")
	e2 := map[string]any{"nameEnc": e["nameEnc"], "nameHash": e["nameHash"], "revision": n.Revision}
	return c.json(ctx, "PATCH", "/api/v1/nodes/"+n.ID, e2, nil)
}

// Move moves a node into another folder of the same space.
func (c *Client) Move(ctx context.Context, n *Node, destID string) error {
	nk, err := c.cachedKey(ctx, n.ID)
	if err != nil {
		return err
	}
	e, err := c.entry(ctx, destID, n.ID, n.Name, nk)
	if err != nil {
		return err
	}
	return c.json(ctx, "PATCH", "/api/v1/nodes/"+n.ID, map[string]any{"parentId": destID, "nameEnc": e["nameEnc"],
		"nameHash": e["nameHash"], "wrappedKey": e["wrappedKey"], "revision": n.Revision}, nil)
}

// Trash moves a node to its space's trash, sealing its key so the space
// owner can restore it later.
func (c *Client) Trash(ctx context.Context, n *Node) error {
	acct, err := c.requireUnlocked()
	if err != nil {
		return err
	}
	nk, sp, err := c.NodeKey(ctx, n.ID)
	if err != nil {
		return err
	}
	pub, err := c.spacePub(ctx, sp)
	if err != nil {
		return err
	}
	rk, sig, err := e2ee.TrashKey(acct, pub, n.ID, n.Name, n.Kind, nk)
	if err != nil {
		return err
	}
	return c.json(ctx, "POST", "/api/v1/nodes/"+n.ID+"/trash", map[string]any{"restoreKey": rk, "restoreSig": sig, "revision": n.Revision}, nil)
}

// TrashItems lists a space's trash with names recovered from restore keys.
func (c *Client) TrashItems(ctx context.Context, spaceID string) ([]*Node, error) {
	var resp struct {
		Items []*Node `json:"items"`
	}
	if err := c.json(ctx, "GET", "/api/v1/spaces/"+spaceID+"/trash", nil, &resp); err != nil {
		return nil, err
	}
	c.mu.Lock()
	s := c.spaces[spaceID]
	c.mu.Unlock()
	if s == nil {
		return nil, errors.New("open the space first")
	}
	for _, n := range resp.Items {
		trasher, err := c.UserKeys(ctx, n.TrashedBy)
		if err != nil {
			continue
		}
		nk, kn, err := e2ee.OpenTrashKey(s, trasher, n.ID, n.RestoreKey, n.RestoreSig)
		if err != nil {
			n.Name = "(unverifiable item)"
			continue
		}
		n.Name = kn.Name
		c.mu.Lock()
		c.keys[n.ID] = nk
		c.mu.Unlock()
	}
	return resp.Items, nil
}

// RestoreTrash restores a trashed node into a folder of its space.
func (c *Client) RestoreTrash(ctx context.Context, n *Node, parentID string) error {
	nk, err := c.cachedKey(ctx, n.ID)
	if err != nil {
		return err
	}
	e, err := c.entry(ctx, parentID, n.ID, n.Name, nk)
	if err != nil {
		return err
	}
	return c.json(ctx, "POST", "/api/v1/trash/"+n.ID+"/restore", map[string]any{"parentId": parentID,
		"nameEnc": e["nameEnc"], "nameHash": e["nameHash"], "wrappedKey": e["wrappedKey"]}, nil)
}

// ShareWithUser shares a node with another user by email.
func (c *Client) ShareWithUser(ctx context.Context, n *Node, email, perm string) error {
	acct, err := c.requireUnlocked()
	if err != nil {
		return err
	}
	recipient, err := c.LookupUser(ctx, email)
	if err != nil {
		return err
	}
	nk, err := c.cachedKey(ctx, n.ID)
	if err != nil {
		return err
	}
	shareID := secure.NewID()
	sealed, sig, err := e2ee.ShareNode(acct, recipient, shareID, n.ID, perm, n.Name, nk)
	if err != nil {
		return err
	}
	return c.json(ctx, "POST", "/api/v1/nodes/"+n.ID+"/shares", map[string]any{"type": "user", "shareId": shareID,
		"recipientId": recipient.ID, "permission": perm, "sealedKey": sealed, "sig": sig}, nil)
}

// CreateLink creates a public link and returns its full URL. The link
// secret is generated here and only ever appears in the URL fragment.
func (c *Client) CreateLink(ctx context.Context, n *Node, password string, expires time.Duration, maxDownloads int64) (string, error) {
	nk, err := c.cachedKey(ctx, n.ID)
	if err != nil {
		return "", err
	}
	secret := e2ee.NewLinkSecret()
	shareID := secure.NewID()
	body := map[string]any{"type": "link", "shareId": shareID, "linkKey": e2ee.LinkKey(secret, shareID, n.ID, n.Name, nk),
		"password": password, "maxDownloads": maxDownloads}
	if expires > 0 {
		body["expiresAt"] = time.Now().Add(expires).UTC()
	}
	var resp struct {
		URLPrefix string `json:"urlPrefix"`
	}
	if err := c.json(ctx, "POST", "/api/v1/nodes/"+n.ID+"/shares", body, &resp); err != nil {
		return "", err
	}
	return resp.URLPrefix + "." + e2ee.B64(secret), nil
}

// KeyBackup is everything needed to decrypt backups offline, itself
// encrypted: the key bundle (unlocked by passphrase or recovery code) and
// the user's team-folder grants with their granters' public keys.
type KeyBackup struct {
	Format string       `json:"format"` // "noddanas-keys/v1"
	Bundle *e2ee.Bundle `json:"bundle"`
	Teams  []TeamGrant  `json:"teams,omitempty"`
}

// TeamGrant is a team-folder key grant kept for offline use.
type TeamGrant struct {
	SpaceID     string          `json:"spaceId"`
	Grant       string          `json:"grant"`
	GrantSig    string          `json:"grantSig"`
	GrantedBy   string          `json:"grantedBy"`
	GranterKeys e2ee.PublicKeys `json:"granterKeys"`
	GranterSig  string          `json:"granterSelfSig"`
}

// ExportKeys builds a key backup. It contains no plaintext secrets.
func (c *Client) ExportKeys(ctx context.Context) (*KeyBackup, error) {
	b, err := c.KeyBundle(ctx)
	if err != nil {
		return nil, err
	}
	kb := &KeyBackup{Format: "noddanas-keys/v1", Bundle: b}
	var resp struct {
		Spaces []*Space `json:"spaces"`
	}
	if err := c.json(ctx, "GET", "/api/v1/spaces", nil, &resp); err != nil {
		return nil, err
	}
	for _, sp := range resp.Spaces {
		if sp.Kind != "team" || sp.MyGrant == nil {
			continue
		}
		var u User
		if err := c.json(ctx, "GET", "/api/v1/users/"+sp.MyGrant.GrantedBy+"/keys", nil, &u); err != nil || u.Keys == nil {
			continue
		}
		kb.Teams = append(kb.Teams, TeamGrant{SpaceID: sp.ID, Grant: sp.MyGrant.Grant, GrantSig: sp.MyGrant.GrantSig,
			GrantedBy: sp.MyGrant.GrantedBy, GranterKeys: e2ee.PublicKeys{Enc: u.Keys.Enc, Sig: u.Keys.Sig}, GranterSig: u.Keys.SelfSig})
	}
	return kb, nil
}
