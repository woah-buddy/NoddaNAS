package service_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/woah-buddy/NoddaNAS/internal/blobcrypt"
	"github.com/woah-buddy/NoddaNAS/internal/domain"
	"github.com/woah-buddy/NoddaNAS/internal/secure"
	"github.com/woah-buddy/NoddaNAS/internal/service"
	"github.com/woah-buddy/NoddaNAS/internal/testutil"
)

// These tests run against a real PostgreSQL so the SQL that enforces
// quotas, uniqueness and concurrency is exercised, not mocked. Set
// NODDANAS_TEST_DATABASE_URL to run them; each test gets its own schema.

type env struct {
	svc      *service.Service
	blobRoot string
	ctx      context.Context
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
	for _, m := range mutate {
		m(&cfg)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &env{svc: service.New(st, blobs, testutil.Keyring(t), cfg, log), blobRoot: root, ctx: context.Background()}
}

type user struct {
	p    service.Principal
	root string
}

func (e *env) user(t *testing.T, name string) user {
	t.Helper()
	u, err := e.svc.LoginUser(e.ctx, service.Identity{
		Issuer: "https://idp.test", Subject: "sub-" + name, Email: name + "@example.test", EmailVerified: true, Name: name,
	})
	if err != nil {
		t.Fatal(err)
	}
	return user{p: service.Principal{UserID: u.ID}, root: u.RootID}
}

func (e *env) mkdir(t *testing.T, u user, parent, name string) string {
	t.Helper()
	n, err := e.svc.CreateFolder(e.ctx, u.p, parent, name)
	if err != nil {
		t.Fatal(err)
	}
	return n.ID
}

func (e *env) put(t *testing.T, p service.Principal, parent, name, body string) (*domain.Node, error) {
	t.Helper()
	return e.svc.Upload(e.ctx, p, service.UploadRequest{
		ParentID: parent, Name: name, Size: int64(len(body)), SHA256: sum(body),
	}, strings.NewReader(body))
}

func (e *env) read(t *testing.T, p service.Principal, id string) string {
	t.Helper()
	c, err := e.svc.OpenContent(e.ctx, p, id, "")
	if err != nil {
		t.Fatalf("open %s: %v", id, err)
	}
	defer c.Close()
	b, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func wantCode(t *testing.T, err error, code domain.Code) {
	t.Helper()
	if got := domain.CodeOf(err); got != code {
		t.Fatalf("got error %v (code %q), want code %q", err, got, code)
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

func (e *env) blobFiles(t *testing.T) []string {
	t.Helper()
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

func TestProvisioning(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "alice")
	again := e.user(t, "alice")
	if a.p.UserID != again.p.UserID || a.root != again.root {
		t.Fatal("same identity must map to the same account")
	}
	// An unverified email is never recorded, so it cannot attract shares.
	u, err := e.svc.LoginUser(e.ctx, service.Identity{Issuer: "https://idp.test", Subject: "mallory",
		Email: "bob@example.test", EmailVerified: false})
	if err != nil || u.Email != "" {
		t.Fatalf("unverified email recorded: %q %v", u.Email, err)
	}
	// A verified email already held by another account is not duplicated.
	u2, err := e.svc.LoginUser(e.ctx, service.Identity{Issuer: "https://other-idp.test", Subject: "alice",
		Email: "alice@example.test", EmailVerified: true})
	if err != nil || u2.Email != "" {
		t.Fatalf("second account captured an existing email: %q %v", u2.Email, err)
	}
}

func TestOwnerFileLifecycle(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "alice")
	docs := e.mkdir(t, a, a.root, "Docs")

	f := must[*domain.Node](t)(e.put(t, a.p, docs, "notes.txt", "hello v1"))
	if got := e.read(t, a.p, f.ID); got != "hello v1" {
		t.Fatalf("read %q", got)
	}
	// A second upload with the same name conflicts unless overwrite is set.
	_, err := e.put(t, a.p, docs, "NOTES.TXT", "x")
	wantCode(t, err, domain.CodeConflict)

	v2, err := e.svc.Upload(e.ctx, a.p, service.UploadRequest{ParentID: docs, Name: "notes.txt", Overwrite: true, Size: -1},
		strings.NewReader("hello v2"))
	if err != nil || v2.ID != f.ID {
		t.Fatalf("overwrite: %v", err)
	}
	vs := must[[]*domain.Version](t)(e.svc.ListVersions(e.ctx, a.p, f.ID))
	if len(vs) != 2 {
		t.Fatalf("versions = %d", len(vs))
	}
	restored := must[*domain.Node](t)(e.svc.RestoreVersion(e.ctx, a.p, f.ID, vs[1].ID))
	if got := e.read(t, a.p, restored.ID); got != "hello v1" {
		t.Fatalf("after restore %q", got)
	}

	// Stale revisions are rejected (optimistic concurrency).
	name := "renamed.txt"
	_, err = e.svc.Update(e.ctx, a.p, f.ID, service.UpdateRequest{Name: &name, Revision: 1})
	wantCode(t, err, domain.CodePrecondition)
	must[*domain.Node](t)(e.svc.Update(e.ctx, a.p, f.ID, service.UpdateRequest{Name: &name}))

	me := must[*domain.User](t)(e.svc.Me(e.ctx, a.p))
	if want := int64(len("hello v1")*2 + len("hello v2")); me.UsedBytes != want {
		t.Fatalf("used = %d, want %d (all versions count)", me.UsedBytes, want)
	}
}

func TestContentIsEncryptedAtRest(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "alice")
	secret := strings.Repeat("TOP-SECRET-PLAINTEXT ", 1000)
	must[*domain.Node](t)(e.put(t, a.p, a.root, "s.txt", secret))
	files := e.blobFiles(t)
	if len(files) != 1 {
		t.Fatalf("blob files = %d", len(files))
	}
	raw, _ := os.ReadFile(files[0])
	if bytes.Contains(raw, []byte("TOP-SECRET")) {
		t.Fatal("plaintext found in blob storage")
	}
}

func TestTenantIsolation(t *testing.T) {
	e := newEnv(t)
	a, b := e.user(t, "alice"), e.user(t, "bob")
	private := e.mkdir(t, a, a.root, "Private")
	f := must[*domain.Node](t)(e.put(t, a.p, private, "diary.txt", "dear diary"))

	// Every operation on someone else's data looks exactly like "no such item".
	_, err := e.svc.GetNode(e.ctx, b.p, f.ID)
	wantCode(t, err, domain.CodeNotFound)
	_, _, _, err = e.svc.ListChildren(e.ctx, b.p, private, "", 0)
	wantCode(t, err, domain.CodeNotFound)
	_, err = e.svc.OpenContent(e.ctx, b.p, f.ID, "")
	wantCode(t, err, domain.CodeNotFound)
	_, err = e.put(t, b.p, private, "planted.txt", "x")
	wantCode(t, err, domain.CodeNotFound)
	wantCode(t, e.svc.Trash(e.ctx, b.p, f.ID, 0), domain.CodeNotFound)
	_, _, err = e.svc.CreateLink(e.ctx, b.p, f.ID, service.LinkOptions{})
	wantCode(t, err, domain.CodeNotFound)
	_, err = e.svc.Update(e.ctx, b.p, f.ID, service.UpdateRequest{ParentID: &b.root})
	wantCode(t, err, domain.CodeNotFound)
	// Bob cannot pull Alice's file into his tree, nor push his into hers.
	bf := must[*domain.Node](t)(e.put(t, b.p, b.root, "mine.txt", "b"))
	_, err = e.svc.Update(e.ctx, b.p, bf.ID, service.UpdateRequest{ParentID: &private})
	wantCode(t, err, domain.CodeNotFound)
	// Malformed IDs are rejected without reaching storage.
	_, err = e.svc.GetNode(e.ctx, b.p, "../../etc/passwd")
	wantCode(t, err, domain.CodeNotFound)
}

func TestReadShare(t *testing.T) {
	e := newEnv(t)
	a, b := e.user(t, "alice"), e.user(t, "bob")
	photos := e.mkdir(t, a, a.root, "Photos")
	trip := e.mkdir(t, a, photos, "Trip")
	pic := must[*domain.Node](t)(e.put(t, a.p, trip, "beach.jpg", "jpegdata"))
	must[*domain.Share](t)(e.svc.ShareWithUser(e.ctx, a.p, photos, "bob@example.test", domain.PermRead))

	if got := e.read(t, b.p, pic.ID); got != "jpegdata" {
		t.Fatal("grantee cannot read inside the share")
	}
	items := must[[]service.SharedItem](t)(e.svc.SharedWithMe(e.ctx, b.p))
	if len(items) != 1 || items[0].Node.Node.ID != photos {
		t.Fatalf("shared-with-me = %+v", items)
	}
	// Visible, so denials are "forbidden" rather than "not found".
	_, err := e.put(t, b.p, trip, "x.jpg", "x")
	wantCode(t, err, domain.CodeForbidden)
	wantCode(t, e.svc.Trash(e.ctx, b.p, pic.ID, 0), domain.CodeForbidden)
	_, err = e.svc.ShareWithUser(e.ctx, b.p, trip, "alice@example.test", domain.PermRead)
	wantCode(t, err, domain.CodeForbidden) // no re-sharing
	_, _, err = e.svc.CreateLink(e.ctx, b.p, trip, service.LinkOptions{})
	wantCode(t, err, domain.CodeForbidden)
	// Alice's root, above the share, stays invisible.
	_, err = e.svc.GetNode(e.ctx, b.p, a.root)
	wantCode(t, err, domain.CodeNotFound)
}

func TestWriteShare(t *testing.T) {
	e := newEnv(t)
	a, b := e.user(t, "alice"), e.user(t, "bob")
	team := e.mkdir(t, a, a.root, "Team")
	sh := must[*domain.Share](t)(e.svc.ShareWithUser(e.ctx, a.p, team, "bob@example.test", domain.PermWrite))

	f := must[*domain.Node](t)(e.put(t, b.p, team, "report.txt", "by bob"))
	if f.OwnerID != a.p.UserID {
		t.Fatal("content written into a share must belong to (and be charged to) the owner")
	}
	if me := must[*domain.User](t)(e.svc.Me(e.ctx, a.p)); me.UsedBytes != int64(len("by bob")) {
		t.Fatalf("owner usage = %d", me.UsedBytes)
	}
	name := "final.txt"
	must[*domain.Node](t)(e.svc.Update(e.ctx, b.p, f.ID, service.UpdateRequest{Name: &name}))

	// Changing the share root itself needs write on *its* parent, which Bob lacks.
	wantCode(t, e.svc.Trash(e.ctx, b.p, team, 0), domain.CodeForbidden)
	_, err := e.svc.Update(e.ctx, b.p, team, service.UpdateRequest{Name: &name})
	wantCode(t, err, domain.CodeForbidden)
	// Moving content out of the share into Bob's own storage is refused.
	_, err = e.svc.Update(e.ctx, b.p, f.ID, service.UpdateRequest{ParentID: &b.root})
	wantCode(t, err, domain.CodeInvalid)

	// Revocation takes effect immediately.
	if err := e.svc.DeleteShare(e.ctx, a.p, sh.ID); err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.GetNode(e.ctx, b.p, f.ID)
	wantCode(t, err, domain.CodeNotFound)
}

func TestReadOnlyCredential(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "alice")
	f := must[*domain.Node](t)(e.put(t, a.p, a.root, "a.txt", "a"))
	ro := service.Principal{UserID: a.p.UserID, ReadOnly: true}
	if got := e.read(t, ro, f.ID); got != "a" {
		t.Fatal("read-only credential cannot read")
	}
	_, err := e.put(t, ro, a.root, "b.txt", "b")
	wantCode(t, err, domain.CodeForbidden)
	wantCode(t, e.svc.Trash(e.ctx, ro, f.ID, 0), domain.CodeForbidden)
	_, _, err = e.svc.CreateLink(e.ctx, ro, f.ID, service.LinkOptions{})
	wantCode(t, err, domain.CodeForbidden)
}

func TestTrashRestoreAndPurge(t *testing.T) {
	e := newEnv(t)
	a, b := e.user(t, "alice"), e.user(t, "bob")
	dir := e.mkdir(t, a, a.root, "Old")
	inner := e.mkdir(t, a, dir, "Inner")
	f := must[*domain.Node](t)(e.put(t, a.p, inner, "f.txt", "12345"))
	g := must[*domain.Node](t)(e.put(t, a.p, dir, "g.txt", "678"))
	must[*domain.Share](t)(e.svc.ShareWithUser(e.ctx, a.p, dir, "bob@example.test", domain.PermRead))

	// g is trashed on its own first; then the whole folder.
	if err := e.svc.Trash(e.ctx, a.p, g.ID, 0); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Trash(e.ctx, a.p, dir, 0); err != nil {
		t.Fatal(err)
	}
	// Everything inside a trashed folder disappears, for owner and grantee alike.
	for _, p := range []service.Principal{a.p, b.p} {
		_, err := e.svc.GetNode(e.ctx, p, f.ID)
		wantCode(t, err, domain.CodeNotFound)
	}
	// The name is free again while the folder sits in the trash.
	clash := e.mkdir(t, a, a.root, "Old")
	_, err := e.svc.Restore(e.ctx, a.p, dir, nil)
	wantCode(t, err, domain.CodeConflict)
	newName := "Old (restored)"
	must[*domain.Node](t)(e.svc.Restore(e.ctx, a.p, dir, &newName))
	if got := e.read(t, b.p, f.ID); got != "12345" {
		t.Fatal("restored content not readable by grantee")
	}
	_ = clash

	// Permanently delete the folder: content and quota go away, but g (trashed
	// separately) survives in the trash and can still be restored.
	if err := e.svc.Trash(e.ctx, a.p, dir, 0); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeletePermanently(e.ctx, a.p, dir); err != nil {
		t.Fatal(err)
	}
	if n, err := e.svc.RunMaintenance(e.ctx, 10); err != nil || n != 1 {
		t.Fatalf("purged %d, %v", n, err)
	}
	if me := must[*domain.User](t)(e.svc.Me(e.ctx, a.p)); me.UsedBytes != 3 {
		t.Fatalf("used = %d, want 3 (only g remains)", me.UsedBytes)
	}
	if files := e.blobFiles(t); len(files) != 1 {
		t.Fatalf("blob files = %d, want 1", len(files))
	}
	restored := must[*domain.Node](t)(e.svc.Restore(e.ctx, a.p, g.ID, nil))
	if restored.ParentID != a.root {
		t.Fatal("orphaned trash item should restore into the root folder")
	}
	if got := e.read(t, a.p, g.ID); got != "678" {
		t.Fatal("g lost")
	}
	// Only the owner can see or act on their trash.
	wantCode(t, e.svc.DeletePermanently(e.ctx, b.p, g.ID), domain.CodeNotFound)
}

func TestTrashExpiry(t *testing.T) {
	e := newEnv(t, func(c *service.Config) { c.TrashRetention = -time.Second })
	a := e.user(t, "alice")
	f := must[*domain.Node](t)(e.put(t, a.p, a.root, "f.txt", "data"))
	if err := e.svc.Trash(e.ctx, a.p, f.ID, 0); err != nil {
		t.Fatal(err)
	}
	if n, err := e.svc.RunMaintenance(e.ctx, 10); err != nil || n != 1 {
		t.Fatalf("purged %d, %v", n, err)
	}
	if me := must[*domain.User](t)(e.svc.Me(e.ctx, a.p)); me.UsedBytes != 0 {
		t.Fatalf("used = %d", me.UsedBytes)
	}
}

func TestQuotaIsAtomic(t *testing.T) {
	e := newEnv(t, func(c *service.Config) { c.DefaultQuota = 1000 })
	a := e.user(t, "alice")
	_, err := e.put(t, a.p, a.root, "big", strings.Repeat("x", 1001))
	wantCode(t, err, domain.CodeQuota)
	// Unknown-size uploads are cut off at the remaining quota.
	_, err = e.svc.Upload(e.ctx, a.p, service.UploadRequest{ParentID: a.root, Name: "stream", Size: -1},
		strings.NewReader(strings.Repeat("x", 1001)))
	wantCode(t, err, domain.CodeQuota)

	// 20 concurrent 100-byte uploads against a 1000-byte quota: exactly 10 win.
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.put(t, a.p, a.root, fmt.Sprintf("f%d", i), strings.Repeat("y", 100)); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	me := must[*domain.User](t)(e.svc.Me(e.ctx, a.p))
	if ok != 10 || me.UsedBytes != 1000 {
		t.Fatalf("succeeded %d, used %d", ok, me.UsedBytes)
	}
	if files := e.blobFiles(t); len(files) != 10 {
		t.Fatalf("rejected uploads left %d blobs behind", len(files)-10)
	}
}

func TestUploadIntegrity(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "alice")
	_, err := e.svc.Upload(e.ctx, a.p, service.UploadRequest{ParentID: a.root, Name: "a", Size: 10}, strings.NewReader("short"))
	wantCode(t, err, domain.CodeInvalid)
	_, err = e.svc.Upload(e.ctx, a.p, service.UploadRequest{ParentID: a.root, Name: "a", Size: 2}, strings.NewReader("too long"))
	wantCode(t, err, domain.CodeInvalid)
	_, err = e.svc.Upload(e.ctx, a.p, service.UploadRequest{ParentID: a.root, Name: "a", Size: 3, SHA256: sum("abd")},
		strings.NewReader("abc"))
	wantCode(t, err, domain.CodeInvalid)
	for _, bad := range []string{"", ".", "..", "a/b", "a\\b", "x\x00y", "evil‮fdp.exe", " lead"} {
		_, err = e.put(t, a.p, a.root, bad, "x")
		wantCode(t, err, domain.CodeInvalid)
	}
	if files := e.blobFiles(t); len(files) != 0 {
		t.Fatalf("rejected uploads left %d blobs behind", len(files))
	}
	if me := must[*domain.User](t)(e.svc.Me(e.ctx, a.p)); me.UsedBytes != 0 {
		t.Fatalf("rejected uploads charged quota: %d", me.UsedBytes)
	}
}

func TestMoveCannotCreateCycle(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "alice")
	x := e.mkdir(t, a, a.root, "x")
	y := e.mkdir(t, a, x, "y")
	_, err := e.svc.Update(e.ctx, a.p, x, service.UpdateRequest{ParentID: &y})
	wantCode(t, err, domain.CodeInvalid)
	_, err = e.svc.Update(e.ctx, a.p, x, service.UpdateRequest{ParentID: &x})
	wantCode(t, err, domain.CodeInvalid)
	wantCode(t, e.svc.Trash(e.ctx, a.p, a.root, 0), domain.CodeForbidden)
}

func TestPublicLinks(t *testing.T) {
	e := newEnv(t, func(c *service.Config) { c.LinkMaxFailures = 3 })
	a := e.user(t, "alice")
	pub := e.mkdir(t, a, a.root, "Public")
	f := must[*domain.Node](t)(e.put(t, a.p, pub, "flyer.pdf", "pdfdata"))
	secret := must[*domain.Node](t)(e.put(t, a.p, a.root, "secret.txt", "nope"))

	_, token, err := e.svc.CreateLink(e.ctx, a.p, pub, service.LinkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cred := service.LinkCredential{Token: token}
	_, kids, _, err := e.svc.LinkChildren(e.ctx, cred, "", "", 0)
	if err != nil || len(kids) != 1 {
		t.Fatalf("list via link: %v", err)
	}
	c, err := e.svc.LinkOpen(e.ctx, cred, f.ID)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	// A link never reaches outside its own subtree.
	_, err = e.svc.LinkOpen(e.ctx, cred, secret.ID)
	wantCode(t, err, domain.CodeNotFound)
	_, _, err = e.svc.LinkNode(e.ctx, cred, a.root)
	wantCode(t, err, domain.CodeNotFound)
	// Wrong or malformed tokens look like nothing at all.
	_, _, err = e.svc.LinkNode(e.ctx, service.LinkCredential{Token: secure.NewToken()}, "")
	wantCode(t, err, domain.CodeNotFound)
	_, _, err = e.svc.LinkNode(e.ctx, service.LinkCredential{Token: "x"}, "")
	wantCode(t, err, domain.CodeNotFound)

	// Password-protected link with lockout.
	_, ptoken, _ := e.svc.CreateLink(e.ctx, a.p, f.ID, service.LinkOptions{Password: "correct horse battery"})
	_, _, err = e.svc.LinkNode(e.ctx, service.LinkCredential{Token: ptoken}, "")
	wantCode(t, err, domain.CodeUnauthorized)
	for range 3 {
		_, _, err = e.svc.LinkNode(e.ctx, service.LinkCredential{Token: ptoken, Password: "wrong guess!"}, "")
		wantCode(t, err, domain.CodeUnauthorized)
	}
	_, _, err = e.svc.LinkNode(e.ctx, service.LinkCredential{Token: ptoken, Password: "correct horse battery"}, "")
	wantCode(t, err, domain.CodeRateLimited) // locked, even with the right password

	// Download limits.
	_, ltoken, _ := e.svc.CreateLink(e.ctx, a.p, f.ID, service.LinkOptions{MaxDownloads: 1})
	c, err = e.svc.LinkOpen(e.ctx, service.LinkCredential{Token: ltoken}, "")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	_, err = e.svc.LinkOpen(e.ctx, service.LinkCredential{Token: ltoken}, "")
	wantCode(t, err, domain.CodeGone)

	// Expiry bounds are enforced and links die with the trash.
	past := time.Now().Add(-time.Hour)
	_, _, err = e.svc.CreateLink(e.ctx, a.p, f.ID, service.LinkOptions{ExpiresAt: &past})
	wantCode(t, err, domain.CodeInvalid)
	if err := e.svc.Trash(e.ctx, a.p, pub, 0); err != nil {
		t.Fatal(err)
	}
	_, _, err = e.svc.LinkNode(e.ctx, cred, "")
	wantCode(t, err, domain.CodeNotFound)
}

func TestCorruptBlobIsDetected(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "alice")
	f := must[*domain.Node](t)(e.put(t, a.p, a.root, "f.txt", strings.Repeat("z", 5000)))
	path := e.blobFiles(t)[0]
	raw, _ := os.ReadFile(path)
	raw[100] ^= 0xff
	os.WriteFile(path, raw, 0o600)
	c, err := e.svc.OpenContent(e.ctx, a.p, f.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := io.ReadAll(c); !errors.Is(err, blobcrypt.ErrCorrupt) {
		t.Fatalf("tampered blob read without error: %v", err)
	}
}
