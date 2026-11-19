package service_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/woah-buddy/NoddaNAS/internal/blob/fsblob"
	"github.com/woah-buddy/NoddaNAS/internal/domain"
	"github.com/woah-buddy/NoddaNAS/internal/e2ee"
	"github.com/woah-buddy/NoddaNAS/internal/secure"
	"github.com/woah-buddy/NoddaNAS/internal/service"
	"github.com/woah-buddy/NoddaNAS/internal/testutil"
)

// These tests drive the service exactly as an E2EE client would: every
// name, key and file they send is encrypted with internal/e2ee, and every
// read is decrypted and verified. The server only ever sees ciphertext.
// They run against a real PostgreSQL (NODDANAS_TEST_DATABASE_URL).

const pass = "correct horse battery staple"

type env struct {
	t        *testing.T
	svc      *service.Service
	blobRoot string
	ctx      context.Context
	users    map[string]*e2ee.PublicUser // directory, as clients would fetch it
}

func newEnv(t *testing.T, mutate ...func(*service.Config)) *env {
	t.Helper()
	st := testutil.Postgres(t)
	root := t.TempDir()
	blobs, err := fsblob.New(root)
	if err != nil {
		t.Fatal(err)
	}
	cfg := service.DefaultConfig()
	cfg.DefaultQuota = 1 << 20
	cfg.AdminGroups = []string{"nas-admins"}
	for _, m := range mutate {
		m(&cfg)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &env{t: t, svc: service.New(st, blobs, cfg, log), blobRoot: root, ctx: context.Background(),
		users: map[string]*e2ee.PublicUser{}}
}

// client is a test E2EE client for one user.
type client struct {
	e       *env
	t       *testing.T
	p       service.Principal
	acct    *e2ee.Account
	u       *domain.User
	home    string // personal space ID
	root    string // personal root folder ID
	keys    map[string]*e2ee.NodeKey
	spaces  map[string]*e2ee.Space
	pubs    map[string][]byte // space ID -> space public key
	spaceOf map[string]string
}

func ecdhPub(raw []byte) (*ecdh.PublicKey, error) { return ecdh.X25519().NewPublicKey(raw) }

func (e *env) login(name string, groups ...string) *client {
	e.t.Helper()
	u, err := e.svc.LoginUser(e.ctx, service.Identity{Issuer: "https://idp.test", Subject: "sub-" + name,
		Email: name + "@example.test", EmailVerified: true, Name: name, Groups: groups})
	if err != nil {
		e.t.Fatal(err)
	}
	return &client{e: e, t: e.t, p: service.Principal{UserID: u.ID}, u: u, home: u.PersonalSpaceID,
		keys: map[string]*e2ee.NodeKey{}, spaces: map[string]*e2ee.Space{}, pubs: map[string][]byte{},
		spaceOf: map[string]string{}}
}

// user signs in and sets up encryption.
func (e *env) user(name string, groups ...string) *client {
	e.t.Helper()
	c := e.login(name, groups...)
	acct, bundle, _, err := e2ee.NewAccount(c.u.ID, pass)
	if err != nil {
		c.t.Fatal(err)
	}
	c.acct = acct
	_, sp, _ := e.svc.Me(e.ctx, c.p)
	c.root = sp.RootID
	space := acct.PersonalSpace(c.home)
	rootKey := e2ee.NewNodeKey()
	raw, _ := json.Marshal(bundle)
	if err := e.svc.SetupKeys(e.ctx, c.p, string(raw), service.SpaceKeys{
		PublicKey: e2ee.B64(space.PublicKey()), KeySig: e2ee.SignSpaceKey(acct, c.home, space.PublicKey()),
		RootKey: space.WrapRoot(c.root, rootKey)}); err != nil {
		c.t.Fatal(err)
	}
	c.keys[c.root], c.spaces[c.home], c.pubs[c.home], c.spaceOf[c.root] = rootKey, space, space.PublicKey(), c.home
	e.users[c.u.ID] = acct.Public()
	return c
}

func (c *client) entry(parentID, id, name string, nk *e2ee.NodeKey) service.EntryFields {
	pk := c.keys[parentID]
	if pk == nil {
		c.t.Fatalf("client has no key for %s", parentID)
	}
	return service.EntryFields{NameEnc: pk.EncryptName(id, name), NameHash: pk.NameHash(name), WrappedKey: pk.WrapChild(id, nk)}
}

func (c *client) mkdir(parentID, name string) string {
	c.t.Helper()
	id, nk := secure.NewID(), e2ee.NewNodeKey()
	if _, err := c.e.svc.CreateFolder(c.e.ctx, c.p, parentID, id, c.entry(parentID, id, name, nk)); err != nil {
		c.t.Fatal(err)
	}
	c.keys[id], c.spaceOf[id] = nk, c.spaceOf[parentID]
	return id
}

func (c *client) container(spaceID string, nk *e2ee.NodeKey, name, body string) []byte {
	c.t.Helper()
	pub, err := ecdhPub(c.pubs[spaceID])
	if err != nil {
		c.t.Fatal(err)
	}
	r, _, err := e2ee.NewWriter(strings.NewReader(body), e2ee.WriteParams{Size: int64(len(body)), NodeKey: nk,
		SpaceID: spaceID, SpacePub: pub, Meta: e2ee.Meta{Name: name, Type: "text/plain", MTime: 1}, Signer: c.acct})
	if err != nil {
		c.t.Fatal(err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		c.t.Fatal(err)
	}
	return b
}

func (c *client) put(parentID, name, body string) (*domain.Node, error) {
	id, nk := secure.NewID(), e2ee.NewNodeKey()
	ct := c.container(c.spaceOf[parentID], nk, name, body)
	n, err := c.e.svc.Upload(c.e.ctx, c.p, service.UploadRequest{ParentID: parentID, NewID: id,
		Entry: c.entry(parentID, id, name, nk), Size: int64(len(ct))}, bytes.NewReader(ct))
	if err == nil {
		c.keys[id], c.spaceOf[id] = nk, c.spaceOf[parentID]
	}
	return n, err
}

func (c *client) putVersion(id, name, body string) (*domain.Node, error) {
	ct := c.container(c.spaceOf[id], c.keys[id], name, body)
	return c.e.svc.Upload(c.e.ctx, c.p, service.UploadRequest{NodeID: id, Size: int64(len(ct))}, bytes.NewReader(ct))
}

// read downloads, decrypts and verifies a file's current content.
func (c *client) read(id string) (string, error) {
	content, err := c.e.svc.OpenContent(c.e.ctx, c.p, id, "")
	if err != nil {
		return "", err
	}
	defer content.Close()
	p, err := e2ee.ParsePrefix(content)
	if err != nil {
		return "", err
	}
	k, err := p.Keys(c.keys[id])
	if err != nil {
		return "", err
	}
	var out bytes.Buffer
	if err := e2ee.DecryptVerify(content, &out, p, k, c.e.users[p.Signer.User]); err != nil {
		return "", err
	}
	return out.String(), nil
}

func (c *client) mustRead(id, want string) {
	c.t.Helper()
	got, err := c.read(id)
	if err != nil || got != want {
		c.t.Fatalf("read %s = %q, %v; want %q", id, got, err, want)
	}
}

func (c *client) trash(id, name, kind string) error {
	n, err := c.e.svc.GetNode(c.e.ctx, c.p, id)
	if err != nil {
		return err
	}
	pub, _ := ecdhPub(c.pubs[n.Node.SpaceID])
	rk, sig, _ := e2ee.TrashKey(c.acct, pub, id, name, kind, c.keys[id])
	return c.e.svc.Trash(c.e.ctx, c.p, id, service.TrashRequest{RestoreKey: rk, RestoreSig: sig})
}

func wantCode(t *testing.T, err error, code domain.Code) {
	t.Helper()
	if got := domain.CodeOf(err); got != code {
		t.Fatalf("got error %v (code %q), want %q", err, got, code)
	}
}

func must[T any](t *testing.T) func(T, error) T {
	return func(v T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

func (e *env) blobFiles() []string {
	var files []string
	filepath.WalkDir(filepath.Join(e.blobRoot, "blobs"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files = append(files, p)
		}
		return nil
	})
	return files
}

// ---------------------------------------------------------------------------

func TestProvisioningAndKeys(t *testing.T) {
	e := newEnv(t)
	a := e.user("alice", "nas-admins")
	if !a.u.Admin {
		t.Fatal("admin group did not make alice an administrator")
	}
	u, err := e.svc.LoginUser(e.ctx, service.Identity{Issuer: "https://idp.test", Subject: "mallory",
		Email: "bob@example.test", EmailVerified: false})
	if err != nil || u.Email != "" {
		t.Fatalf("unverified email recorded: %q %v", u.Email, err)
	}
	// Keys can be set up once; a second attempt (e.g. a hijacked session
	// trying to swap keys) is refused.
	acct2, bundle2, _, _ := e2ee.NewAccount(a.u.ID, pass)
	raw, _ := json.Marshal(bundle2)
	sp := acct2.PersonalSpace(a.home)
	err = e.svc.SetupKeys(e.ctx, a.p, string(raw), service.SpaceKeys{PublicKey: e2ee.B64(sp.PublicKey()),
		KeySig: e2ee.SignSpaceKey(acct2, a.home, sp.PublicKey()), RootKey: sp.WrapRoot(a.root, e2ee.NewNodeKey())})
	wantCode(t, err, domain.CodeConflict)
	// Bundle updates may change unlockers but never the public keys.
	wantCode(t, e.svc.UpdateKeyBundle(e.ctx, a.p, string(raw)), domain.CodeInvalid)
	stored := must[string](t)(e.svc.KeyBundle(e.ctx, a.p))
	var b e2ee.Bundle
	json.Unmarshal([]byte(stored), &b)
	if err := a.acct.ChangePassphrase(&b, "a different passphrase"); err != nil {
		t.Fatal(err)
	}
	nb, _ := json.Marshal(b)
	if err := e.svc.UpdateKeyBundle(e.ctx, a.p, string(nb)); err != nil {
		t.Fatal(err)
	}
	// A bundle made for another user is refused.
	other := e.login("carol")
	wantCode(t, e.svc.SetupKeys(e.ctx, other.p, string(raw), service.SpaceKeys{}), domain.CodeInvalid)
}

func TestE2EEFileLifecycle(t *testing.T) {
	e := newEnv(t)
	a := e.user("alice")
	docs := a.mkdir(a.root, "Docs")
	f := must[*domain.Node](t)(a.put(docs, "notes.txt", "hello v1"))
	a.mustRead(f.ID, "hello v1")

	// The server never sees plaintext: not the name, not the content.
	for _, p := range e.blobFiles() {
		raw, _ := os.ReadFile(p)
		if bytes.Contains(raw, []byte("hello")) || bytes.Contains(raw, []byte("notes.txt")) {
			t.Fatal("plaintext found in blob storage")
		}
	}

	// Case-insensitive duplicate detection works on keyed hashes alone.
	_, err := a.put(docs, "NOTES.TXT", "x")
	wantCode(t, err, domain.CodeConflict)
	var de *domain.Error
	if !errors.As(err, &de) || de.Detail["existingId"] != f.ID {
		t.Fatalf("conflict should identify the existing file: %v", err)
	}

	must[*domain.Node](t)(a.putVersion(f.ID, "notes.txt", "hello v2"))
	a.mustRead(f.ID, "hello v2")
	vs := must[[]*domain.Version](t)(e.svc.ListVersions(e.ctx, a.p, f.ID))
	if len(vs) != 2 {
		t.Fatalf("versions = %d", len(vs))
	}
	must[*domain.Node](t)(e.svc.RestoreVersion(e.ctx, a.p, f.ID, vs[1].ID))
	a.mustRead(f.ID, "hello v1")

	// Rename = new encrypted name and hash; move = also a re-wrapped key.
	archive := a.mkdir(a.root, "Archive")
	n := must[*domain.Node](t)(e.svc.Update(e.ctx, a.p, f.ID, service.UpdateRequest{
		ParentID: &archive, Entry: a.entry(archive, f.ID, "old-notes.txt", a.keys[f.ID])}))
	if name, err := a.keys[archive].DecryptName(f.ID, n.NameEnc); err != nil || name != "old-notes.txt" {
		t.Fatalf("moved name: %q %v", name, err)
	}
	// A move without a re-wrapped key is refused.
	_, err = e.svc.Update(e.ctx, a.p, f.ID, service.UpdateRequest{ParentID: &docs,
		Entry: service.EntryFields{NameEnc: n.NameEnc, NameHash: n.NameHash}})
	wantCode(t, err, domain.CodeInvalid)
	a.mustRead(f.ID, "hello v1")
}

// The headline property: a single stored container, copied out of storage
// as a backup, can be restored with only the owner's keys, still encrypted.
func TestIndependentBackupAndRestore(t *testing.T) {
	e := newEnv(t)
	a := e.user("alice")
	f := must[*domain.Node](t)(a.put(a.root, "taxes-2026.pdf", "very private"))
	backup, err := os.ReadFile(e.blobFiles()[0]) // e.g. from a volume backup or an API download
	if err != nil {
		t.Fatal(err)
	}

	// The file is deleted and purged: no node, no key, no database trace.
	if err := a.trash(f.ID, "taxes-2026.pdf", "file"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeletePermanently(e.ctx, a.p, f.ID); err != nil {
		t.Fatal(err)
	}
	must[int](t)(e.svc.RunMaintenance(e.ctx, 10))
	if len(e.blobFiles()) != 0 {
		t.Fatal("blob not purged")
	}

	// Restore: open the owner seal with the space keys (derived from the
	// passphrase or recovery code), read the name from the encrypted
	// metadata, and re-link the unchanged container.
	p, err := e2ee.ParsePrefix(bytes.NewReader(backup))
	if err != nil {
		t.Fatal(err)
	}
	nk, err := p.OwnerNodeKey(a.spaces[a.home])
	if err != nil {
		t.Fatal(err)
	}
	k, _ := p.Keys(nk)
	meta := must[*e2ee.Meta](t)(p.DecryptMeta(k))
	if meta.Name != "taxes-2026.pdf" {
		t.Fatalf("meta name %q", meta.Name)
	}
	if err := e2ee.DecryptVerify(bytes.NewReader(backup[p.BodyOffset():]), io.Discard, p, k, a.acct.Public()); err != nil {
		t.Fatalf("backup does not verify: %v", err)
	}
	id := secure.NewID()
	restored, err := e.svc.Upload(e.ctx, a.p, service.UploadRequest{ParentID: a.root, NewID: id,
		Entry: a.entry(a.root, id, meta.Name, nk), Size: int64(len(backup))}, bytes.NewReader(backup))
	if err != nil {
		t.Fatal(err)
	}
	a.keys[id] = nk
	a.mustRead(restored.ID, "very private")
	stored, _ := os.ReadFile(e.blobFiles()[0])
	if !bytes.Equal(stored, backup) {
		t.Fatal("restored container should be byte-identical to the backup")
	}

	// Someone else's container (sealed to their space) is refused.
	b := e.user("bob")
	foreign := b.container(b.home, e2ee.NewNodeKey(), "x", "x")
	id2 := secure.NewID()
	_, err = e.svc.Upload(e.ctx, a.p, service.UploadRequest{ParentID: a.root, NewID: id2,
		Entry: a.entry(a.root, id2, "x", e2ee.NewNodeKey()), Size: int64(len(foreign))}, bytes.NewReader(foreign))
	wantCode(t, err, domain.CodeInvalid)
}

func TestTenantIsolation(t *testing.T) {
	e := newEnv(t)
	a, b := e.user("alice"), e.user("bob")
	private := a.mkdir(a.root, "Private")
	f := must[*domain.Node](t)(a.put(private, "diary.txt", "dear diary"))
	_, err := e.svc.GetNode(e.ctx, b.p, f.ID)
	wantCode(t, err, domain.CodeNotFound)
	_, _, _, err = e.svc.ListChildren(e.ctx, b.p, private, "", 0)
	wantCode(t, err, domain.CodeNotFound)
	_, err = e.svc.OpenContent(e.ctx, b.p, f.ID, "")
	wantCode(t, err, domain.CodeNotFound)
	_, err = e.svc.NodePath(e.ctx, b.p, f.ID)
	wantCode(t, err, domain.CodeNotFound)
	_, err = e.svc.ListTrash(e.ctx, b.p, a.home)
	wantCode(t, err, domain.CodeNotFound)
	_, err = e.svc.GetNode(e.ctx, b.p, "../../etc/passwd")
	wantCode(t, err, domain.CodeNotFound)
	// Moving one's own item into someone else's folder is refused.
	bf := must[*domain.Node](t)(b.put(b.root, "mine.txt", "b"))
	_, err = e.svc.Update(e.ctx, b.p, bf.ID, service.UpdateRequest{ParentID: &private, Entry: b.entry(b.root, bf.ID, "x", b.keys[bf.ID])})
	wantCode(t, err, domain.CodeNotFound)
}

func TestUserShares(t *testing.T) {
	e := newEnv(t)
	a, b := e.user("alice"), e.user("bob")
	photos := a.mkdir(a.root, "Photos")
	pic := must[*domain.Node](t)(a.put(photos, "beach.jpg", "jpegdata"))

	recipient := must[*service.PublicUser](t)(e.svc.LookupUser(e.ctx, a.p, "bob@example.test"))
	rpub, err := e2ee.VerifyPublicKeys(recipient.ID, e2ee.PublicKeys{Enc: recipient.Keys.Enc, Sig: recipient.Keys.Sig}, recipient.Keys.SelfSig)
	if err != nil {
		t.Fatal(err)
	}
	shareID := secure.NewID()
	sealed, sig, _ := e2ee.ShareNode(a.acct, rpub, shareID, photos, "write", "Photos", a.keys[photos])
	sh := must[*domain.Share](t)(e.svc.ShareWithUser(e.ctx, a.p, photos, service.NewUserShare{
		ShareID: shareID, RecipientID: b.u.ID, Permission: domain.PermWrite, SealedKey: sealed, Sig: sig}))

	// Bob discovers the share, verifies Alice's signature, and gets the key.
	items := must[[]service.SharedItem](t)(e.svc.SharedWithMe(e.ctx, b.p))
	if len(items) != 1 {
		t.Fatalf("shared-with-me = %d", len(items))
	}
	it := items[0].Share
	nk, name, err := e2ee.OpenShare(b.acct, e.users[it.CreatedBy], it.ID, it.NodeID, string(it.Permission), it.SealedKey, it.ShareSig)
	if err != nil || name != "Photos" {
		t.Fatalf("open share: %q %v", name, err)
	}
	b.keys[photos], b.spaceOf[photos], b.pubs[a.home] = nk, a.home, a.spaces[a.home].PublicKey()

	// Bob's key path starts at the share, not at Alice's root.
	path := must[*service.Path](t)(e.svc.NodePath(e.ctx, b.p, pic.ID))
	if path.Share == nil || path.Nodes[0].ID != photos || path.Space.Role != domain.RoleNone {
		t.Fatalf("path entry = %+v", path)
	}
	b.keys[pic.ID] = must[*e2ee.NodeKey](t)(nk.UnwrapChild(pic.ID, path.Nodes[1].WrappedKey))
	b.mustRead(pic.ID, "jpegdata")

	// Bob writes into the share; Alice's space pays and Alice can read it.
	up := must[*domain.Node](t)(b.put(photos, "sunset.jpg", "by bob"))
	if up.SpaceID != a.home {
		t.Fatal("content written into a share belongs to the sharer's space")
	}
	a.keys[up.ID] = must[*e2ee.NodeKey](t)(a.keys[photos].UnwrapChild(up.ID, up.WrappedKey))
	a.mustRead(up.ID, "by bob")
	// Bob cannot trash the shared folder itself, nor re-share it.
	wantCode(t, b.trash(photos, "Photos", "folder"), domain.CodeForbidden)
	_, err = e.svc.ShareWithUser(e.ctx, b.p, photos, service.NewUserShare{ShareID: secure.NewID(),
		RecipientID: a.u.ID, Permission: domain.PermRead, SealedKey: sealed, Sig: sig})
	wantCode(t, err, domain.CodeForbidden)

	if err := e.svc.DeleteShare(e.ctx, a.p, sh.ID); err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.OpenContent(e.ctx, b.p, pic.ID, "")
	wantCode(t, err, domain.CodeNotFound)
}

func TestTeamFolders(t *testing.T) {
	e := newEnv(t)
	admin := e.user("admin", "nas-admins")
	bob := e.user("bob")
	carol := e.user("carol")
	dave := e.login("dave", "engineering") // in the group, no keys yet

	// Bob (any user) creates a team folder.
	teamID, rootID := secure.NewID(), secure.NewID()
	team := e2ee.OpenSpace(teamID, e2ee.NewTeamSecret())
	rootKey := e2ee.NewNodeKey()
	grant, gsig, _ := team.Grant(bob.acct, bob.acct.Public())
	sp := must[*domain.Space](t)(e.svc.CreateTeam(e.ctx, bob.p, service.NewTeam{ID: teamID, RootID: rootID,
		NameEnc: team.EncryptName("Launch Plan"), Grant: grant, GrantSig: gsig,
		Keys: service.SpaceKeys{PublicKey: e2ee.B64(team.PublicKey()), KeySig: e2ee.SignSpaceKey(bob.acct, teamID, team.PublicKey()),
			RootKey: team.WrapRoot(rootID, rootKey)}}))
	if sp.QuotaBytes != service.DefaultConfig().DefaultTeamQuota {
		t.Fatal("team folders have their own quota")
	}
	bob.keys[rootID], bob.spaces[teamID], bob.pubs[teamID], bob.spaceOf[rootID] = rootKey, team, team.PublicKey(), teamID
	plan := must[*domain.Node](t)(bob.put(rootID, "plan.md", "ship it"))

	// Item 2: Bob adds Carol directly. She is authorized at once, but holds
	// no key until a manager's client grants it.
	write := domain.RoleWrite
	if err := e.svc.UpdateMember(e.ctx, bob.p, teamID, carol.u.ID, service.MemberUpdate{Role: &write}); err != nil {
		t.Fatal(err)
	}
	info := must[*service.SpaceInfo](t)(e.svc.GetSpace(e.ctx, carol.p, teamID))
	if info.Role != domain.RoleWrite || info.Membership.Grant != "" {
		t.Fatalf("carol membership = %+v", info.Membership)
	}
	cg, cs, _ := team.Grant(bob.acct, e.users[carol.u.ID])
	if err := e.svc.UpdateMember(e.ctx, bob.p, teamID, carol.u.ID, service.MemberUpdate{Grant: cg, GrantSig: cs}); err != nil {
		t.Fatal(err)
	}
	info = must[*service.SpaceInfo](t)(e.svc.GetSpace(e.ctx, carol.p, teamID))
	m := info.Membership
	cTeam, err := e2ee.OpenGrant(carol.acct, e.users[m.GrantedBy], teamID, m.Grant, m.GrantSig)
	if err != nil {
		t.Fatal(err)
	}
	if name, _ := cTeam.DecryptName(info.Space.NameEnc); name != "Launch Plan" {
		t.Fatalf("team name %q", name)
	}
	rk := must[*e2ee.NodeKey](t)(cTeam.UnwrapRoot(rootID, info.Space.RootKey))
	carol.keys[rootID], carol.spaceOf[rootID], carol.pubs[teamID] = rk, teamID, team.PublicKey()
	carol.keys[plan.ID] = must[*e2ee.NodeKey](t)(rk.UnwrapChild(plan.ID, plan.WrappedKey))
	carol.mustRead(plan.ID, "ship it")
	must[*domain.Node](t)(carol.put(rootID, "notes.md", "from carol"))

	// Item 3: only administrators map IdP groups to team folders.
	wantCode(t, e.svc.SetGroupMapping(e.ctx, bob.p, teamID, "engineering", domain.RoleRead), domain.CodeForbidden)
	if err := e.svc.SetGroupMapping(e.ctx, admin.p, teamID, "engineering", domain.RoleRead); err != nil {
		t.Fatal(err)
	}
	// Dave arrives through the group: authorized, and listed as awaiting a key.
	if _, err := e.svc.GetNode(e.ctx, dave.p, plan.ID); err != nil {
		t.Fatalf("group member not authorized: %v", err)
	}
	pending := 0
	for _, mb := range must[[]*domain.Member](t)(e.svc.ListMembers(e.ctx, bob.p, teamID)) {
		if mb.Grant == "" {
			pending++
		}
	}
	if pending != 1 {
		t.Fatalf("pending grants = %d, want 1 (dave)", pending)
	}
	wantCode(t, e.svc.UpdateMember(e.ctx, bob.p, teamID, dave.u.ID, service.MemberUpdate{Grant: cg, GrantSig: cs}),
		domain.CodePrecondition) // dave has not set up keys
	// The group's role is read: Dave cannot write.
	id := secure.NewID()
	_, err = e.svc.Upload(e.ctx, dave.p, service.UploadRequest{ParentID: rootID, NewID: id,
		Entry: bob.entry(rootID, id, "x", e2ee.NewNodeKey())}, strings.NewReader(""))
	wantCode(t, err, domain.CodeForbidden)

	// Removing the mapping revokes group access immediately.
	if err := e.svc.DeleteGroupMapping(e.ctx, admin.p, teamID, "engineering"); err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.GetNode(e.ctx, dave.p, plan.ID)
	wantCode(t, err, domain.CodeNotFound)
	carol.mustRead(plan.ID, "ship it") // still a direct member

	// The last key-holding manager cannot leave; others can.
	wantCode(t, e.svc.RemoveMember(e.ctx, bob.p, teamID, bob.u.ID), domain.CodeConflict)
	if err := e.svc.RemoveMember(e.ctx, carol.p, teamID, carol.u.ID); err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.GetNode(e.ctx, carol.p, plan.ID)
	wantCode(t, err, domain.CodeNotFound)

	// Deleting the team folder purges its content.
	before := len(e.blobFiles())
	if err := e.svc.DeleteTeam(e.ctx, bob.p, teamID); err != nil {
		t.Fatal(err)
	}
	must[int](t)(e.svc.RunMaintenance(e.ctx, 10))
	if after := len(e.blobFiles()); after != before-2 {
		t.Fatalf("blobs %d -> %d", before, after)
	}
	_, err = e.svc.GetSpace(e.ctx, bob.p, teamID)
	wantCode(t, err, domain.CodeNotFound)
}

func TestTrashRestoreAndPurge(t *testing.T) {
	e := newEnv(t)
	a := e.user("alice")
	dir := a.mkdir(a.root, "Old")
	f := must[*domain.Node](t)(a.put(dir, "f.txt", "12345"))
	g := must[*domain.Node](t)(a.put(dir, "g.txt", "678"))
	if err := a.trash(g.ID, "g.txt", "file"); err != nil {
		t.Fatal(err)
	}
	if err := a.trash(dir, "Old", "folder"); err != nil {
		t.Fatal(err)
	}
	_, err := e.svc.GetNode(e.ctx, a.p, f.ID)
	wantCode(t, err, domain.CodeNotFound)

	// Purge the folder; g (trashed separately) survives and stays restorable
	// even though the folder whose key wrapped it is gone.
	if err := e.svc.DeletePermanently(e.ctx, a.p, dir); err != nil {
		t.Fatal(err)
	}
	if n, _ := e.svc.RunMaintenance(e.ctx, 10); n != 1 {
		t.Fatal("folder not purged")
	}
	_, sp, _ := e.svc.Me(e.ctx, a.p)
	if sp.UsedBytes != g.Size {
		t.Fatalf("used = %d, want %d", sp.UsedBytes, g.Size)
	}
	entries := must[[]service.TrashEntry](t)(e.svc.ListTrash(e.ctx, a.p, a.home))
	if len(entries) != 1 || entries[0].Node.ID != g.ID {
		t.Fatalf("trash = %+v", entries)
	}
	tn := entries[0].Node
	nk, kn, err := e2ee.OpenTrashKey(a.spaces[a.home], e.users[tn.TrashedBy], tn.ID, tn.RestoreKey, tn.RestoreSig)
	if err != nil || kn.Name != "g.txt" {
		t.Fatalf("open trash key: %v", err)
	}
	a.keys[g.ID] = nk
	must[*domain.Node](t)(e.svc.Restore(e.ctx, a.p, g.ID, service.RestoreRequest{ParentID: a.root,
		Entry: a.entry(a.root, g.ID, kn.Name, nk)}))
	a.mustRead(g.ID, "678")
}

func TestQuotaIsAtomic(t *testing.T) {
	e := newEnv(t)
	a := e.user("alice")
	one := len(a.container(a.home, e2ee.NewNodeKey(), "f00", strings.Repeat("y", 100)))
	if err := e.svc.SetQuota(e.ctx, a.home, int64(one*10+one/2)); err != nil {
		t.Fatal(err)
	}
	// Encrypt everything first (the test client is single-threaded), then
	// race 20 uploads against a quota that fits exactly 10.
	reqs := make([]service.UploadRequest, 20)
	bodies := make([][]byte, 20)
	for i := range reqs {
		id, nk, name := secure.NewID(), e2ee.NewNodeKey(), fmt.Sprintf("f%02d", i)
		bodies[i] = a.container(a.home, nk, name, strings.Repeat("y", 100))
		reqs[i] = service.UploadRequest{ParentID: a.root, NewID: id, Entry: a.entry(a.root, id, name, nk), Size: int64(len(bodies[i]))}
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := range reqs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.svc.Upload(e.ctx, a.p, reqs[i], bytes.NewReader(bodies[i])); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	_, sp, _ := e.svc.Me(e.ctx, a.p)
	if ok != 10 || sp.UsedBytes != int64(10*one) {
		t.Fatalf("succeeded %d, used %d", ok, sp.UsedBytes)
	}
	if n := len(e.blobFiles()); n != 10 {
		t.Fatalf("rejected uploads left %d extra blobs", n-10)
	}
}

func TestUploadValidation(t *testing.T) {
	e := newEnv(t)
	a := e.user("alice")
	nk := e2ee.NewNodeKey()
	good := a.container(a.home, nk, "a", "hello")
	up := func(body []byte, size int64, mutate func(*service.UploadRequest)) error {
		id := secure.NewID()
		req := service.UploadRequest{ParentID: a.root, NewID: id, Entry: a.entry(a.root, id, "a", nk), Size: size}
		if mutate != nil {
			mutate(&req)
		}
		_, err := e.svc.Upload(e.ctx, a.p, req, bytes.NewReader(body))
		return err
	}
	cases := map[string]error{
		"not a container":  up([]byte("plain text"), -1, nil),
		"truncated":        up(good[:len(good)-10], -1, nil),
		"trailing bytes":   up(append(bytes.Clone(good), 1, 2, 3), -1, nil),
		"length mismatch":  up(good, int64(len(good)+1), nil),
		"bad wrapped key":  up(good, -1, func(r *service.UploadRequest) { r.Entry.WrappedKey = "AAAA" }),
		"bad name hash":    up(good, -1, func(r *service.UploadRequest) { r.Entry.NameHash = "NOTHEX" }),
		"bad name":         up(good, -1, func(r *service.UploadRequest) { r.Entry.NameEnc = "!!" }),
		"client-chosen ID": up(good, -1, func(r *service.UploadRequest) { r.NewID = "../../x" }),
	}
	for name, err := range cases {
		if domain.CodeOf(err) != domain.CodeInvalid {
			t.Errorf("%s: got %v, want invalid", name, err)
		}
	}
	if n := len(e.blobFiles()); n != 0 {
		t.Fatalf("rejected uploads left %d blobs", n)
	}
	if err := up(good, int64(len(good)), nil); err != nil {
		t.Fatal(err)
	}
}

func TestReadOnlyAndCycles(t *testing.T) {
	e := newEnv(t)
	a := e.user("alice")
	x := a.mkdir(a.root, "x")
	y := a.mkdir(x, "y")
	_, err := e.svc.Update(e.ctx, a.p, x, service.UpdateRequest{ParentID: &y, Entry: a.entry(y, x, "x", a.keys[x])})
	wantCode(t, err, domain.CodeInvalid)
	ro := service.Principal{UserID: a.p.UserID, ReadOnly: true}
	id := secure.NewID()
	_, err = e.svc.CreateFolder(e.ctx, ro, a.root, id, a.entry(a.root, id, "z", e2ee.NewNodeKey()))
	wantCode(t, err, domain.CodeForbidden)
	_, _, err = e.svc.CreateLink(e.ctx, ro, x, service.LinkOptions{ShareID: secure.NewID(), LinkKey: e2ee.B64(make([]byte, 64))})
	wantCode(t, err, domain.CodeForbidden)
}

func TestPublicLinks(t *testing.T) {
	e := newEnv(t, func(c *service.Config) { c.LinkMaxFailures = 3 })
	a := e.user("alice")
	pub := a.mkdir(a.root, "Public")
	f := must[*domain.Node](t)(a.put(pub, "flyer.pdf", "pdfdata"))
	secret := must[*domain.Node](t)(a.put(a.root, "secret.txt", "nope"))

	linkSecret := e2ee.NewLinkSecret()
	shareID := secure.NewID()
	_, token, err := e.svc.CreateLink(e.ctx, a.p, pub, service.LinkOptions{ShareID: shareID,
		LinkKey: e2ee.LinkKey(linkSecret, shareID, pub, "Public", a.keys[pub])})
	if err != nil {
		t.Fatal(err)
	}
	cred := service.LinkCredential{Token: token}
	// A visitor derives keys from the link secret plus the returned path.
	view := must[*service.LinkView](t)(e.svc.LinkNode(e.ctx, cred, f.ID))
	nk, name, err := e2ee.OpenLinkKey(linkSecret, view.Share.ID, view.Share.NodeID, view.Share.LinkKey)
	if err != nil || name != "Public" {
		t.Fatalf("link key: %v", err)
	}
	fk := must[*e2ee.NodeKey](t)(nk.UnwrapChild(f.ID, view.Path[1].WrappedKey))
	c := must[*service.Content](t)(e.svc.LinkOpen(e.ctx, cred, f.ID))
	p, _ := e2ee.ParsePrefix(c)
	k, err := p.Keys(fk)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := e2ee.DecryptVerify(c, &out, p, k, a.acct.Public()); err != nil || out.String() != "pdfdata" {
		t.Fatalf("visitor decrypt: %q %v", out.String(), err)
	}
	c.Close()
	_, err = e.svc.LinkOpen(e.ctx, cred, secret.ID)
	wantCode(t, err, domain.CodeNotFound)
	_, err = e.svc.LinkNode(e.ctx, service.LinkCredential{Token: secure.NewToken()}, "")
	wantCode(t, err, domain.CodeNotFound)

	sid := secure.NewID()
	_, ptoken, _ := e.svc.CreateLink(e.ctx, a.p, f.ID, service.LinkOptions{ShareID: sid, Password: "correct horse battery",
		LinkKey: e2ee.LinkKey(linkSecret, sid, f.ID, "flyer.pdf", a.keys[f.ID])})
	for range 3 {
		_, err = e.svc.LinkNode(e.ctx, service.LinkCredential{Token: ptoken, Password: "wrong guess!"}, "")
		wantCode(t, err, domain.CodeUnauthorized)
	}
	_, err = e.svc.LinkNode(e.ctx, service.LinkCredential{Token: ptoken, Password: "correct horse battery"}, "")
	wantCode(t, err, domain.CodeRateLimited)
	past := time.Now().Add(-time.Hour)
	_, _, err = e.svc.CreateLink(e.ctx, a.p, f.ID, service.LinkOptions{ShareID: secure.NewID(), LinkKey: view.Share.LinkKey, ExpiresAt: &past})
	wantCode(t, err, domain.CodeInvalid)
}

// link creates a public link for c on node id and returns its credential.
func (c *client) link(id, name string, opts service.LinkOptions) service.LinkCredential {
	c.t.Helper()
	opts.ShareID = secure.NewID()
	opts.LinkKey = e2ee.LinkKey(e2ee.NewLinkSecret(), opts.ShareID, id, name, c.keys[id])
	_, token, err := c.e.svc.CreateLink(c.e.ctx, c.p, id, opts)
	if err != nil {
		c.t.Fatal(err)
	}
	return service.LinkCredential{Token: token}
}

func TestSharedByMeAndLinkKillSwitches(t *testing.T) {
	e := newEnv(t)
	a, b, admin := e.user("alice"), e.user("bob"), e.user("root", "nas-admins")
	docs := a.mkdir(a.root, "Docs")
	f := must[*domain.Node](t)(a.put(docs, "report.pdf", "pdf"))
	l1 := a.link(docs, "Docs", service.LinkOptions{})
	l2 := a.link(f.ID, "report.pdf", service.LinkOptions{MaxDownloads: 1, Password: "a long link password"})
	bobFile := must[*domain.Node](t)(b.put(b.root, "b.txt", "bee"))
	lb := b.link(bobFile.ID, "b.txt", service.LinkOptions{})

	// Alice also shares Docs with Bob directly; the kill switch must leave that alone.
	rpub := e.users[b.u.ID]
	shareID := secure.NewID()
	sealed, sig, _ := e2ee.ShareNode(a.acct, rpub, shareID, docs, "read", "Docs", a.keys[docs])
	must[*domain.Share](t)(e.svc.ShareWithUser(e.ctx, a.p, docs, service.NewUserShare{
		ShareID: shareID, RecipientID: b.u.ID, Permission: domain.PermRead, SealedKey: sealed, Sig: sig}))

	// Use up l2's single download: its status becomes "exhausted".
	l2.Password = "a long link password"
	if c, err := e.svc.LinkOpen(e.ctx, l2, f.ID); err != nil {
		t.Fatal(err)
	} else {
		c.Close()
	}

	// Shared by me: Alice sees her three shares (and not Bob's), newest first, with status.
	items, truncated, err := e.svc.SharedByMe(e.ctx, a.p)
	if err != nil || truncated || len(items) != 3 {
		t.Fatalf("shared-by-me: %d items, truncated=%v, %v", len(items), truncated, err)
	}
	kinds := map[domain.ShareKind]int{}
	for _, it := range items {
		kinds[it.Share.Kind]++
		if it.Share.CreatedBy != a.u.ID || it.Node == nil {
			t.Fatalf("unexpected item %+v", it)
		}
		if it.Share.NodeID == f.ID && it.Share.Status(time.Now()) != "exhausted" {
			t.Fatalf("status = %s", it.Share.Status(time.Now()))
		}
	}
	if kinds[domain.ShareLink] != 2 || kinds[domain.ShareUser] != 1 {
		t.Fatalf("kinds = %v", kinds)
	}

	// A read-only credential cannot pull the switch.
	_, err = e.svc.RevokeMyLinks(e.ctx, service.Principal{UserID: a.u.ID, ReadOnly: true})
	wantCode(t, err, domain.CodeForbidden)

	// Alice's switch: both her links die at once; Bob's link and her user share survive.
	if n, err := e.svc.RevokeMyLinks(e.ctx, a.p); err != nil || n != 2 {
		t.Fatalf("revoke mine = %d, %v", n, err)
	}
	for _, cred := range []service.LinkCredential{l1, l2} {
		_, err := e.svc.LinkNode(e.ctx, cred, "")
		wantCode(t, err, domain.CodeNotFound)
	}
	must[*service.LinkView](t)(e.svc.LinkNode(e.ctx, lb, ""))
	if got := must[[]service.SharedItem](t)(e.svc.SharedWithMe(e.ctx, b.p)); len(got) != 1 {
		t.Fatal("user share was revoked by the link kill switch")
	}
	if n, _ := e.svc.RevokeMyLinks(e.ctx, a.p); n != 0 {
		t.Fatal("second revoke found links")
	}

	// The global switch is for administrators only.
	_, err = e.svc.AdminRevokeAllLinks(e.ctx, a.p)
	wantCode(t, err, domain.CodeForbidden)
	_, err = e.svc.AdminRevokeAllLinks(e.ctx, service.Principal{UserID: admin.u.ID, ReadOnly: true})
	wantCode(t, err, domain.CodeForbidden)
	if n, err := e.svc.AdminRevokeAllLinks(e.ctx, admin.p); err != nil || n != 1 {
		t.Fatalf("admin revoke = %d, %v", n, err)
	}
	_, err = e.svc.LinkNode(e.ctx, lb, "")
	wantCode(t, err, domain.CodeNotFound)

	// Operator break-glass: per user needs a real email; there is no "empty means everyone".
	b.link(bobFile.ID, "b.txt", service.LinkOptions{})
	a.link(f.ID, "report.pdf", service.LinkOptions{})
	_, err = e.svc.OperatorRevokeLinks(e.ctx, "")
	wantCode(t, err, domain.CodeInvalid)
	_, err = e.svc.OperatorFindUser(e.ctx, "not an email")
	wantCode(t, err, domain.CodeInvalid)
	byEmail := must[*domain.User](t)(e.svc.OperatorFindUser(e.ctx, "bob@example.test"))
	byID := must[*domain.User](t)(e.svc.OperatorFindUser(e.ctx, b.u.ID))
	if byEmail.ID != b.u.ID || byID.ID != b.u.ID {
		t.Fatal("operator user lookup")
	}
	if n, err := e.svc.OperatorRevokeLinks(e.ctx, byEmail.ID); err != nil || n != 1 {
		t.Fatalf("operator revoke bob = %d, %v", n, err)
	}
	if n, err := e.svc.OperatorRevokeAllLinks(e.ctx); err != nil || n != 1 {
		t.Fatalf("operator revoke all = %d, %v", n, err)
	}

	// An item the creator can no longer see (here: trashed) stays listed so
	// its link can still be found and revoked, but without node details.
	g := must[*domain.Node](t)(a.put(a.root, "gone.txt", "x"))
	a.link(g.ID, "gone.txt", service.LinkOptions{})
	if err := a.trash(g.ID, "gone.txt", "file"); err != nil {
		t.Fatal(err)
	}
	items, _, _ = e.svc.SharedByMe(e.ctx, a.p)
	var hidden int
	for _, it := range items {
		if it.Share.NodeID == g.ID && it.Node == nil {
			hidden++
		}
	}
	if hidden != 1 {
		t.Fatal("link on an item the creator cannot see should be listed without node details")
	}
	if n, _ := e.svc.RevokeMyLinks(e.ctx, a.p); n != 1 {
		t.Fatalf("revoking the hidden link: %d", n)
	}
}

// Every key bundle the server stores (and so every backup of it) must meet
// the full passphrase work factor, whatever client produced it.
func TestWeakKeyBundlesRefused(t *testing.T) {
	e := newEnv(t)
	a := e.user("alice")
	stored := must[string](t)(e.svc.KeyBundle(e.ctx, a.p))
	mutate := func(f func(*e2ee.Bundle)) string {
		var b e2ee.Bundle
		if err := json.Unmarshal([]byte(stored), &b); err != nil {
			t.Fatal(err)
		}
		f(&b)
		raw, _ := json.Marshal(b)
		return string(raw)
	}
	passIdx := func(b *e2ee.Bundle, typ string) int {
		for i, u := range b.Unlock {
			if u.Type == typ {
				return i
			}
		}
		t.Fatalf("no %s unlocker", typ)
		return -1
	}
	for name, f := range map[string]func(*e2ee.Bundle){
		"low PBKDF2 work factor": func(b *e2ee.Bundle) { b.Unlock[passIdx(b, "passphrase")].Iter = 1000 },
		"other KDF":              func(b *e2ee.Bundle) { b.Unlock[passIdx(b, "passphrase")].KDF = "sha256" },
		"absurd work factor":     func(b *e2ee.Bundle) { b.Unlock[passIdx(b, "passphrase")].Iter = 1 << 30 },
		"short salt":             func(b *e2ee.Bundle) { b.Unlock[passIdx(b, "passphrase")].Salt = e2ee.B64(make([]byte, 4)) },
		"truncated wrapped key":  func(b *e2ee.Bundle) { b.Unlock[passIdx(b, "recovery")].MK = e2ee.B64(make([]byte, 20)) },
		"recovery with a KDF":    func(b *e2ee.Bundle) { b.Unlock[passIdx(b, "recovery")].Iter = 1 },
		"unknown unlocker":       func(b *e2ee.Bundle) { b.Unlock = append(b.Unlock, e2ee.Unlocker{Type: "pin"}) },
	} {
		if err := e.svc.UpdateKeyBundle(e.ctx, a.p, mutate(f)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The genuine bundle is still accepted.
	if err := e.svc.UpdateKeyBundle(e.ctx, a.p, stored); err != nil {
		t.Fatal(err)
	}
}

// The administrator can prove storage is complete and intact without any
// keys: sizes and SHA-256 are of the ciphertext.
func TestVerifyStorage(t *testing.T) {
	e := newEnv(t)
	a := e.user("alice")
	f1 := must[*domain.Node](t)(a.put(a.root, "one.txt", "first file"))
	must[*domain.Node](t)(a.putVersion(f1.ID, "one.txt", "first file, second version"))
	must[*domain.Node](t)(a.put(a.root, "two.txt", "second file"))
	must[*domain.Node](t)(a.put(a.root, "three.txt", "third file"))

	r := must[*service.StorageReport](t)(e.svc.OperatorVerifyStorage(e.ctx, true))
	if !r.OK() || r.Versions != 4 || r.Orphans != 0 || r.Bytes == 0 {
		t.Fatalf("clean storage: %+v", r)
	}
	files := e.blobFiles()
	if len(files) != 4 {
		t.Fatalf("%d blob files", len(files))
	}
	// Damage three containers in three ways, and plant a stray file.
	os.Remove(files[0])
	raw, _ := os.ReadFile(files[1])
	os.WriteFile(files[1], raw[:len(raw)-1], 0o600) // truncated
	raw, _ = os.ReadFile(files[2])
	raw[len(raw)/2] ^= 0x01 // one flipped bit, same size
	os.WriteFile(files[2], raw, 0o600)
	stray := filepath.Join(filepath.Dir(files[3]), "ffffffffffffffffffffffffffffffff")
	os.WriteFile(stray, []byte("x"), 0o600)

	quick := must[*service.StorageReport](t)(e.svc.OperatorVerifyStorage(e.ctx, false))
	if quick.OK() || len(quick.Missing) != 1 || len(quick.WrongSize) != 1 || len(quick.WrongHash) != 0 || quick.Orphans != 1 {
		t.Fatalf("size check: %+v", quick)
	}
	full := must[*service.StorageReport](t)(e.svc.OperatorVerifyStorage(e.ctx, true))
	if len(full.Missing) != 1 || len(full.WrongSize) != 1 || len(full.WrongHash) != 1 {
		t.Fatalf("hash check: %+v", full)
	}
}
