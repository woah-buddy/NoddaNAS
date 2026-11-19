// Package client is a Go client for the NoddaNAS HTTP API that performs all
// end-to-end encryption locally (docs/E2EE.md). It backs the noddanas-cli
// tool and the HTTP end-to-end tests. Nothing it sends to the server is
// plaintext: names, keys and content are encrypted before they leave.
package client

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/woah-buddy/NoddaNAS/internal/e2ee"
	"github.com/woah-buddy/NoddaNAS/internal/secure"
)

// Client talks to one NoddaNAS server as one user.
type Client struct {
	base  string
	http  *http.Client
	token string // app password; empty when the http.Client carries a session cookie

	mu     sync.Mutex
	acct   *e2ee.Account
	me     *Me
	keys   map[string]*e2ee.NodeKey   // node ID -> key
	spaces map[string]*e2ee.Space     // space ID -> unlocked space
	pubs   map[string]*ecdh.PublicKey // space ID -> verified space public key
	dir    map[string]*e2ee.PublicUser
}

// New returns a client. token is an app password (ndn_...); pass "" if hc
// already authenticates (e.g. a cookie jar holding a browser session).
func New(baseURL string, hc *http.Client, token string) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 0}
	}
	return &Client{base: strings.TrimRight(baseURL, "/"), http: hc, token: token,
		keys: map[string]*e2ee.NodeKey{}, spaces: map[string]*e2ee.Space{}, pubs: map[string]*ecdh.PublicKey{},
		dir: map[string]*e2ee.PublicUser{}}
}

// APIError is an error returned by the server.
type APIError struct {
	Status  int
	Code    string
	Message string
	Detail  map[string]string
}

func (e *APIError) Error() string { return fmt.Sprintf("%s (%d %s)", e.Message, e.Status, e.Code) }

// ErrExists is returned when a name is taken; ExistingID names the holder.
type ErrExists struct{ ExistingID, Kind string }

func (e *ErrExists) Error() string { return "an item with that name already exists" }

func (c *Client) do(ctx context.Context, method, path string, body io.Reader, hdr map[string]string, out any) (*http.Response, error) {
	return c.doSized(ctx, method, path, body, -1, hdr, out)
}

func (c *Client) doSized(ctx context.Context, method, path string, body io.Reader, size int64, hdr map[string]string, out any) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	if size >= 0 {
		req.ContentLength = size
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	} else {
		req.Header.Set("Sec-Fetch-Site", "same-origin") // what a same-origin browser page sends
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		var eb struct {
			Error struct {
				Code    string            `json:"code"`
				Message string            `json:"message"`
				Detail  map[string]string `json:"detail"`
			} `json:"error"`
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		_ = json.Unmarshal(raw, &eb)
		if eb.Error.Message == "" {
			eb.Error.Message = strings.TrimSpace(string(raw))
		}
		ae := &APIError{Status: resp.StatusCode, Code: eb.Error.Code, Message: eb.Error.Message, Detail: eb.Error.Detail}
		if resp.StatusCode == http.StatusConflict && ae.Detail["existingId"] != "" {
			return nil, &ErrExists{ExistingID: ae.Detail["existingId"], Kind: ae.Detail["existingKind"]}
		}
		return nil, ae
	}
	if out != nil {
		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return nil, fmt.Errorf("decoding %s %s: %w", method, path, err)
		}
	}
	return resp, nil
}

func (c *Client) json(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	hdr := map[string]string{}
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body, hdr["Content-Type"] = bytes.NewReader(raw), "application/json"
	}
	resp, err := c.do(ctx, method, path, body, hdr, out)
	if err == nil && out == nil {
		resp.Body.Close()
	}
	return err
}

// ---- account -----------------------------------------------------------------

// Keys are a user's published public keys.
type Keys struct {
	Enc     string `json:"enc"`
	Sig     string `json:"sig"`
	SelfSig string `json:"selfSig"`
}

// User is a directory entry.
type User struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	Admin       bool   `json:"admin"`
	Keys        *Keys  `json:"keys"`
}

// Space is a personal space or team folder.
type Space struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	RootID     string `json:"rootId"`
	NameEnc    string `json:"nameEnc"`
	PublicKey  string `json:"publicKey"`
	KeySig     string `json:"keySig"`
	KeySigner  string `json:"keySigner"`
	RootKey    string `json:"rootKey"`
	QuotaBytes int64  `json:"quotaBytes"`
	UsedBytes  int64  `json:"usedBytes"`
	Role       string `json:"role"`
	MyGrant    *struct {
		Grant     string `json:"grant"`
		GrantSig  string `json:"grantSig"`
		GrantedBy string `json:"grantedBy"`
	} `json:"myGrant"`
	Name string `json:"-"` // decrypted (team folders)
}

// Me is the signed-in account.
type Me struct {
	User          User  `json:"user"`
	PersonalSpace Space `json:"personalSpace"`
	ReadOnly      bool  `json:"readOnly"`
}

// Me fetches (and caches) the signed-in account.
func (c *Client) Me(ctx context.Context) (*Me, error) {
	var me Me
	if err := c.json(ctx, "GET", "/api/v1/me", nil, &me); err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.me = &me
	c.mu.Unlock()
	return &me, nil
}

// SetupKeys creates the user's keys (browser session only) and returns the
// recovery code, which the user must store offline.
func (c *Client) SetupKeys(ctx context.Context, passphrase string) (string, error) {
	me, err := c.Me(ctx)
	if err != nil {
		return "", err
	}
	acct, bundle, code, err := e2ee.NewAccount(me.User.ID, passphrase)
	if err != nil {
		return "", err
	}
	sp := acct.PersonalSpace(me.PersonalSpace.ID)
	root := e2ee.NewNodeKey()
	raw, _ := json.Marshal(bundle)
	err = c.json(ctx, "POST", "/api/v1/keys", map[string]any{"bundle": string(raw), "personalSpace": map[string]string{
		"publicKey": e2ee.B64(sp.PublicKey()), "keySig": e2ee.SignSpaceKey(acct, sp.ID, sp.PublicKey()),
		"rootKey": sp.WrapRoot(me.PersonalSpace.RootID, root)}}, nil)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	c.acct, c.spaces[sp.ID], c.keys[me.PersonalSpace.RootID] = acct, sp, root
	c.pubs[sp.ID] = sp.Priv.PublicKey()
	c.mu.Unlock()
	return code, nil
}

// KeyBundle downloads the user's encrypted key bundle (also the key backup).
func (c *Client) KeyBundle(ctx context.Context) (*e2ee.Bundle, error) {
	var resp struct {
		Bundle string `json:"bundle"`
	}
	if err := c.json(ctx, "GET", "/api/v1/keys", nil, &resp); err != nil {
		return nil, err
	}
	var b e2ee.Bundle
	if err := json.Unmarshal([]byte(resp.Bundle), &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// Unlock opens the user's keys with a passphrase or (if recovery is true)
// the recovery code.
func (c *Client) Unlock(ctx context.Context, secret string, recovery bool) error {
	me, err := c.Me(ctx)
	if err != nil {
		return err
	}
	b, err := c.KeyBundle(ctx)
	if err != nil {
		return err
	}
	if b.UserID != me.User.ID {
		return errors.New("key bundle belongs to a different user")
	}
	var acct *e2ee.Account
	if recovery {
		acct, err = e2ee.UnlockWithRecoveryCode(b, secret)
	} else {
		acct, err = e2ee.Unlock(b, secret)
	}
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.acct = acct
	c.dir[acct.UserID] = acct.Public()
	c.mu.Unlock()
	return nil
}

// Account returns the unlocked account (nil if locked).
func (c *Client) Account() *e2ee.Account {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.acct
}

// UserKeys fetches and verifies a user's public keys (cached).
func (c *Client) UserKeys(ctx context.Context, userID string) (*e2ee.PublicUser, error) {
	c.mu.Lock()
	if u, ok := c.dir[userID]; ok {
		c.mu.Unlock()
		return u, nil
	}
	c.mu.Unlock()
	var u User
	if err := c.json(ctx, "GET", "/api/v1/users/"+url.PathEscape(userID)+"/keys", nil, &u); err != nil {
		return nil, err
	}
	return c.verifyUser(u)
}

func (c *Client) verifyUser(u User) (*e2ee.PublicUser, error) {
	if u.Keys == nil {
		return nil, fmt.Errorf("user %s has not set up encryption", u.ID)
	}
	pu, err := e2ee.VerifyPublicKeys(u.ID, e2ee.PublicKeys{Enc: u.Keys.Enc, Sig: u.Keys.Sig}, u.Keys.SelfSig)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.dir[u.ID] = pu
	c.mu.Unlock()
	return pu, nil
}

// LookupUser finds a user by email and verifies their keys.
func (c *Client) LookupUser(ctx context.Context, email string) (*e2ee.PublicUser, error) {
	var u User
	if err := c.json(ctx, "GET", "/api/v1/users/lookup?email="+url.QueryEscape(email), nil, &u); err != nil {
		return nil, err
	}
	return c.verifyUser(u)
}

// ---- spaces --------------------------------------------------------------------

func (c *Client) requireUnlocked() (*e2ee.Account, error) {
	a := c.Account()
	if a == nil {
		return nil, errors.New("keys are locked: unlock with your passphrase first")
	}
	return a, nil
}

// openSpace derives a space's keys and root key, checking every signature.
func (c *Client) openSpace(ctx context.Context, sp *Space) (*e2ee.Space, error) {
	acct, err := c.requireUnlocked()
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if s, ok := c.spaces[sp.ID]; ok {
		c.mu.Unlock()
		return s, nil
	}
	c.mu.Unlock()
	var s *e2ee.Space
	switch {
	case sp.Kind == "personal":
		s = acct.PersonalSpace(sp.ID)
	case sp.MyGrant != nil:
		granter, err := c.UserKeys(ctx, sp.MyGrant.GrantedBy)
		if err != nil {
			return nil, err
		}
		if s, err = e2ee.OpenGrant(acct, granter, sp.ID, sp.MyGrant.Grant, sp.MyGrant.GrantSig); err != nil {
			return nil, fmt.Errorf("team key grant does not verify: %w", err)
		}
	default:
		return nil, errors.New("you have not been granted this team folder's key yet; ask a manager to open it")
	}
	if e2ee.B64(s.PublicKey()) != sp.PublicKey {
		return nil, errors.New("space public key does not match its secret")
	}
	root, err := s.UnwrapRoot(sp.RootID, sp.RootKey)
	if err != nil {
		return nil, err
	}
	if sp.Kind == "team" {
		sp.Name, _ = s.DecryptName(sp.NameEnc)
	}
	c.mu.Lock()
	c.spaces[sp.ID], c.keys[sp.RootID], c.pubs[sp.ID] = s, root, s.Priv.PublicKey()
	c.mu.Unlock()
	return s, nil
}

// spacePub returns a space's public key, verified against its creator.
func (c *Client) spacePub(ctx context.Context, sp *Space) (*ecdh.PublicKey, error) {
	c.mu.Lock()
	if p, ok := c.pubs[sp.ID]; ok {
		c.mu.Unlock()
		return p, nil
	}
	c.mu.Unlock()
	creator, err := c.UserKeys(ctx, sp.KeySigner)
	if err != nil {
		return nil, err
	}
	p, err := e2ee.VerifySpaceKey(creator, sp.ID, sp.PublicKey, sp.KeySig)
	if err != nil {
		return nil, fmt.Errorf("space key does not verify: %w", err)
	}
	c.mu.Lock()
	c.pubs[sp.ID] = p
	c.mu.Unlock()
	return p, nil
}

// Spaces lists the user's spaces, decrypting team names where possible.
func (c *Client) Spaces(ctx context.Context) ([]*Space, error) {
	var resp struct {
		Spaces []*Space `json:"spaces"`
	}
	if err := c.json(ctx, "GET", "/api/v1/spaces", nil, &resp); err != nil {
		return nil, err
	}
	for _, sp := range resp.Spaces {
		if _, err := c.openSpace(ctx, sp); err != nil && sp.Kind == "team" {
			sp.Name = "(locked team folder " + sp.ID[:8] + ")"
		}
	}
	return resp.Spaces, nil
}

// CreateTeam creates a team folder with the caller as manager.
func (c *Client) CreateTeam(ctx context.Context, name string) (*Space, error) {
	acct, err := c.requireUnlocked()
	if err != nil {
		return nil, err
	}
	id, rootID := secure.NewID(), secure.NewID()
	s := e2ee.OpenSpace(id, e2ee.NewTeamSecret())
	root := e2ee.NewNodeKey()
	grant, gsig, err := s.Grant(acct, acct.Public())
	if err != nil {
		return nil, err
	}
	var sp Space
	err = c.json(ctx, "POST", "/api/v1/spaces", map[string]any{"id": id, "rootId": rootID, "nameEnc": s.EncryptName(name),
		"keys": map[string]string{"publicKey": e2ee.B64(s.PublicKey()), "keySig": e2ee.SignSpaceKey(acct, id, s.PublicKey()),
			"rootKey": s.WrapRoot(rootID, root)}, "grant": grant, "grantSig": gsig}, &sp)
	if err != nil {
		return nil, err
	}
	sp.Name = name
	c.mu.Lock()
	c.spaces[id], c.keys[rootID], c.pubs[id] = s, root, s.Priv.PublicKey()
	c.mu.Unlock()
	return &sp, nil
}

// Member is a team folder member.
type Member struct {
	UserID      string   `json:"userId"`
	DisplayName string   `json:"displayName"`
	Email       string   `json:"email"`
	Keys        *Keys    `json:"keys"`
	DirectRole  string   `json:"directRole"`
	GroupRoles  []string `json:"groupRoles"`
	Role        string   `json:"role"`
	HasGrant    bool     `json:"hasGrant"`
}

// Members lists a team folder's members.
func (c *Client) Members(ctx context.Context, spaceID string) ([]Member, error) {
	var resp struct {
		Members []Member `json:"members"`
	}
	err := c.json(ctx, "GET", "/api/v1/spaces/"+spaceID+"/members", nil, &resp)
	return resp.Members, err
}

// AddMember adds a user to a team folder with a role and grants them the key.
func (c *Client) AddMember(ctx context.Context, spaceID, userID, role string) error {
	if err := c.json(ctx, "PUT", "/api/v1/spaces/"+spaceID+"/members/"+userID, map[string]any{"role": role}, nil); err != nil {
		return err
	}
	return c.GrantKey(ctx, spaceID, userID)
}

// GrantKey gives a member the team folder's key (managers only).
func (c *Client) GrantKey(ctx context.Context, spaceID, userID string) error {
	acct, err := c.requireUnlocked()
	if err != nil {
		return err
	}
	c.mu.Lock()
	s := c.spaces[spaceID]
	c.mu.Unlock()
	if s == nil {
		return errors.New("open the team folder first")
	}
	member, err := c.UserKeys(ctx, userID)
	if err != nil {
		return err
	}
	grant, sig, err := s.Grant(acct, member)
	if err != nil {
		return err
	}
	return c.json(ctx, "PUT", "/api/v1/spaces/"+spaceID+"/members/"+userID, map[string]any{"grant": grant, "grantSig": sig}, nil)
}

// GrantPending grants the key to every member who has access but no key
// yet (e.g. arrived through an IdP group). Returns how many were granted.
func (c *Client) GrantPending(ctx context.Context, spaceID string) (int, error) {
	members, err := c.Members(ctx, spaceID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, m := range members {
		if m.HasGrant || m.Keys == nil {
			continue
		}
		if err := c.GrantKey(ctx, spaceID, m.UserID); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// ---- nodes ------------------------------------------------------------------------

// Node is a file or folder as returned by the server.
type Node struct {
	ID         string    `json:"id"`
	ParentID   string    `json:"parentId"`
	SpaceID    string    `json:"spaceId"`
	Kind       string    `json:"kind"`
	NameEnc    string    `json:"nameEnc"`
	NameHash   string    `json:"nameHash"`
	WrappedKey string    `json:"wrappedKey"`
	Size       int64     `json:"size"`
	SHA256     string    `json:"sha256"`
	ModifiedAt time.Time `json:"modifiedAt"`
	CreatedBy  string    `json:"createdBy"`
	Revision   int64     `json:"revision"`
	Permission string    `json:"permission"`
	TrashedBy  string    `json:"trashedBy"`
	RestoreKey string    `json:"restoreKey"`
	RestoreSig string    `json:"restoreSig"`
	Name       string    `json:"-"` // decrypted
}

type pathResp struct {
	Space Space  `json:"space"`
	Nodes []Node `json:"nodes"`
	Share *struct {
		ID         string `json:"id"`
		NodeID     string `json:"nodeId"`
		Permission string `json:"permission"`
		CreatedBy  string `json:"createdBy"`
		SealedKey  string `json:"sealedKey"`
		Sig        string `json:"sig"`
	} `json:"share"`
}

// NodeKey derives (and caches) a node's key by walking from an entry point
// the caller holds a key for.
func (c *Client) NodeKey(ctx context.Context, nodeID string) (*e2ee.NodeKey, *Space, error) {
	acct, err := c.requireUnlocked()
	if err != nil {
		return nil, nil, err
	}
	var p pathResp
	if err := c.json(ctx, "GET", "/api/v1/nodes/"+nodeID+"/path", nil, &p); err != nil {
		return nil, nil, err
	}
	var k *e2ee.NodeKey
	if p.Share != nil {
		sharer, err := c.UserKeys(ctx, p.Share.CreatedBy)
		if err != nil {
			return nil, nil, err
		}
		if k, _, err = e2ee.OpenShare(acct, sharer, p.Share.ID, p.Share.NodeID, p.Share.Permission, p.Share.SealedKey, p.Share.Sig); err != nil {
			return nil, nil, fmt.Errorf("share does not verify: %w", err)
		}
	} else {
		if _, err := c.openSpace(ctx, &p.Space); err != nil {
			return nil, nil, err
		}
		c.mu.Lock()
		k = c.keys[p.Space.RootID]
		c.mu.Unlock()
	}
	for i, n := range p.Nodes {
		if i > 0 {
			if k, err = k.UnwrapChild(n.ID, n.WrappedKey); err != nil {
				return nil, nil, err
			}
		}
		c.mu.Lock()
		c.keys[n.ID] = k
		c.mu.Unlock()
	}
	return k, &p.Space, nil
}

func (c *Client) cachedKey(ctx context.Context, id string) (*e2ee.NodeKey, error) {
	c.mu.Lock()
	k := c.keys[id]
	c.mu.Unlock()
	if k != nil {
		return k, nil
	}
	k, _, err := c.NodeKey(ctx, id)
	return k, err
}

// List returns a folder's children with decrypted names, sorted.
func (c *Client) List(ctx context.Context, folderID string) ([]*Node, error) {
	pk, err := c.cachedKey(ctx, folderID)
	if err != nil {
		return nil, err
	}
	var out []*Node
	cursor := ""
	for {
		var resp struct {
			Children   []*Node `json:"children"`
			NextCursor string  `json:"nextCursor"`
		}
		if err := c.json(ctx, "GET", "/api/v1/nodes/"+folderID+"/children?limit=1000&cursor="+cursor, nil, &resp); err != nil {
			return nil, err
		}
		for _, n := range resp.Children {
			if n.Name, err = pk.DecryptName(n.ID, n.NameEnc); err != nil {
				return nil, fmt.Errorf("child %s: %w", n.ID, err)
			}
			if k, err := pk.UnwrapChild(n.ID, n.WrappedKey); err == nil {
				c.mu.Lock()
				c.keys[n.ID] = k
				c.mu.Unlock()
			}
			out = append(out, n)
		}
		if resp.NextCursor == "" {
			break
		}
		cursor = resp.NextCursor
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind == "folder"
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}

func (c *Client) entry(ctx context.Context, parentID, id, name string, nk *e2ee.NodeKey) (map[string]string, error) {
	if err := e2ee.ValidateName(name); err != nil {
		return nil, err
	}
	pk, err := c.cachedKey(ctx, parentID)
	if err != nil {
		return nil, err
	}
	return map[string]string{"nameEnc": pk.EncryptName(id, name), "nameHash": pk.NameHash(name), "wrappedKey": pk.WrapChild(id, nk)}, nil
}

// Mkdir creates a folder and returns its ID.
func (c *Client) Mkdir(ctx context.Context, parentID, name string) (string, error) {
	id, nk := secure.NewID(), e2ee.NewNodeKey()
	e, err := c.entry(ctx, parentID, id, name, nk)
	if err != nil {
		return "", err
	}
	e["id"] = id
	if err := c.json(ctx, "POST", "/api/v1/nodes/"+parentID+"/folders", e, nil); err != nil {
		return "", err
	}
	c.mu.Lock()
	c.keys[id] = nk
	c.mu.Unlock()
	return id, nil
}

// spaceOf returns the space a node belongs to (for sealing to its owner).
func (c *Client) spaceOf(ctx context.Context, nodeID string) (*Space, error) {
	var p pathResp
	if err := c.json(ctx, "GET", "/api/v1/nodes/"+nodeID+"/path", nil, &p); err != nil {
		return nil, err
	}
	return &p.Space, nil
}

func (c *Client) container(ctx context.Context, sp *Space, nk *e2ee.NodeKey, r io.Reader, size int64, meta e2ee.Meta) (io.Reader, int64, error) {
	acct, err := c.requireUnlocked()
	if err != nil {
		return nil, 0, err
	}
	pub, err := c.spacePub(ctx, sp)
	if err != nil {
		return nil, 0, err
	}
	return e2ee.NewWriter(r, e2ee.WriteParams{Size: size, NodeKey: nk, SpaceID: sp.ID, SpacePub: pub, Meta: meta, Signer: acct})
}

// Upload encrypts r (exactly size bytes) as a new file. If the name is
// taken it returns *ErrExists.
func (c *Client) Upload(ctx context.Context, parentID, name string, r io.Reader, size int64, mtime time.Time) (*Node, error) {
	sp, err := c.spaceOf(ctx, parentID)
	if err != nil {
		return nil, err
	}
	id, nk := secure.NewID(), e2ee.NewNodeKey()
	e, err := c.entry(ctx, parentID, id, name, nk)
	if err != nil {
		return nil, err
	}
	e["id"] = id
	hdr, _ := json.Marshal(e)
	body, total, err := c.container(ctx, sp, nk, r, size, e2ee.Meta{Name: name, MTime: mtime.UnixMilli()})
	if err != nil {
		return nil, err
	}
	var n Node
	if err := c.upload(ctx, "POST", "/api/v1/nodes/"+parentID+"/files", body, total, map[string]string{"X-NoddaNAS-Entry": string(hdr)}, &n); err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.keys[id] = nk
	c.mu.Unlock()
	n.Name = name
	return &n, nil
}

// UploadVersion encrypts r as a new version of an existing file.
func (c *Client) UploadVersion(ctx context.Context, nodeID, name string, r io.Reader, size int64, mtime time.Time) (*Node, error) {
	nk, sp, err := c.NodeKey(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	body, total, err := c.container(ctx, sp, nk, r, size, e2ee.Meta{Name: name, MTime: mtime.UnixMilli()})
	if err != nil {
		return nil, err
	}
	var n Node
	err = c.upload(ctx, "PUT", "/api/v1/nodes/"+nodeID+"/content", body, total, nil, &n)
	return &n, err
}

func (c *Client) upload(ctx context.Context, method, path string, body io.Reader, size int64, hdr map[string]string, out any) error {
	h := map[string]string{"Content-Type": "application/octet-stream"}
	for k, v := range hdr {
		h[k] = v
	}
	resp, err := c.doSized(ctx, method, path, body, size, h, out)
	if err == nil && out == nil {
		resp.Body.Close()
	}
	return err
}
