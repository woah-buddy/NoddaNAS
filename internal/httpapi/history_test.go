package httpapi_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/woah-buddy/FrontDir/internal/client"
	"github.com/woah-buddy/FrontDir/internal/e2ee"
	"github.com/woah-buddy/FrontDir/internal/testutil"
)

// Signed version history end to end (docs/E2EE.md §5c), played against a
// server whose database is tampered with: who stored a version and when
// cannot be relabelled, versions cannot be reordered or dropped, and a
// client that has seen a newer or different history notices a rollback or
// a fork, also after a restart.
func TestSignedHistory(t *testing.T) {
	store, schema := testutil.PostgresSchema(t)
	h := newHarnessWith(t, harnessOpts{store: store})
	ctx := context.Background()
	login := func(name string) *client.Client {
		return client.New(h.base, h.loginOIDC(idpUser{sub: name, email: name + "@example.test", groups: []string{"nas-users"}}), "")
	}
	user := func(name string) *client.Client {
		c := login(name)
		must[string](t)(c.SetupKeys(ctx, pass))
		return c
	}
	sql := func(q string, args ...any) int64 { t.Helper(); return testutil.Exec(t, schema, q, args...) }
	seenFile := filepath.Join(t.TempDir(), "seen.json")
	alice, bob, carol := user("alice"), user("bob"), user("carol")
	alice.SetSeenStore(must[*client.FileSeen](t)(client.OpenFileSeen(seenFile)))
	ids := map[string]string{}
	for name, c := range map[string]*client.Client{"alice": alice, "bob": bob, "carol": carol} {
		ids[name] = must[*client.Me](t)(c.Me(ctx)).User.ID
	}
	me := must[*client.Me](t)(alice.Me(ctx))
	docs := must[string](t)(alice.Mkdir(ctx, me.PersonalSpace.RootID, "Docs"))
	for _, who := range []string{"bob", "carol"} {
		if err := alice.ShareWithUser(ctx, &client.Node{ID: docs, Name: "Docs", Kind: "folder"}, who+"@example.test", "write"); err != nil {
			t.Fatal(err)
		}
	}
	f := must[*client.Node](t)(alice.Upload(ctx, docs, "plan.txt", strings.NewReader("one"), 3, time.Now()))
	save := func(c *client.Client, text string) error {
		_, err := c.UploadVersion(ctx, f.ID, "plan.txt", strings.NewReader(text), int64(len(text)), time.Now())
		return err
	}
	history := func(c *client.Client) *client.History {
		t.Helper()
		return must[*client.History](t)(c.Versions(ctx, f.ID))
	}
	read := func(c *client.Client) (string, error) {
		var b bytes.Buffer
		_, err := c.Download(ctx, f.ID, &b)
		return b.String(), err
	}
	if err := save(bob, "two"); err != nil {
		t.Fatal(err)
	}
	if err := save(alice, "three"); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.RestoreVersion(ctx, f.ID, history(bob).Versions[2].ID); err != nil { // bob brings back "one"
		t.Fatal(err)
	}

	hs := history(alice)
	if hs.Err != nil {
		t.Fatalf("genuine history: %v", hs.Err)
	}
	type want struct {
		seq              int64
		kind, by, author string
	}
	for i, w := range []want{{4, "restore", "bob", "alice"}, {3, "save", "alice", "alice"}, {2, "save", "bob", "bob"}, {1, "save", "alice", "alice"}} {
		v := hs.Versions[i]
		if v.Seq != w.seq || v.Kind != w.kind || v.StoredBy == nil || v.StoredBy.ID != ids[w.by] || v.Author == nil ||
			v.Author.ID != ids[w.author] || time.Since(v.SavedAt) > time.Minute {
			t.Fatalf("version %d: seq %d kind %s stored by %v author %v at %v", i, v.Seq, v.Kind, v.StoredBy, v.Author, v.SavedAt)
		}
	}
	ver := func(i int) string { return hs.Versions[i].ID }
	if got, err := read(alice); err != nil || got != "one" {
		t.Fatalf("read %q: %v", got, err)
	}

	// Snapshot the genuine rows; each tampering below is undone from it.
	sql(`CREATE TABLE genuine AS SELECT * FROM versions`)
	sql(`CREATE TABLE genuine_node AS SELECT id, version_id FROM nodes`)
	reset := func() {
		t.Helper()
		sql(`DELETE FROM versions WHERE node_id = $1`, f.ID)
		sql(`INSERT INTO versions SELECT * FROM genuine WHERE node_id = $1`, f.ID)
		sql(`UPDATE nodes n SET version_id = g.version_id FROM genuine_node g WHERE n.id = g.id`)
		if err := history(alice).Err; err != nil {
			t.Fatalf("reset: %v", err)
		}
	}

	// Who stored a version is signed: the server's own column can say
	// anything, the client shows the signed name.
	sql(`UPDATE versions SET created_by = $1 WHERE id = $2`, ids["carol"], ver(0))
	if v := history(alice).Versions[0]; v.StoredBy.ID != ids["bob"] || v.UploadedBy != ids["carol"] {
		t.Fatal("restorer relabelled")
	}
	reset()

	for name, tamper := range map[string]func(){
		// The signed time: one digit of "at" changed.
		"signed time": func() {
			sql(`UPDATE versions SET record = overlay(record placing '9'::bytea from position('"at":1'::bytea in record) + 6 for 1) WHERE id = $1`, ver(1))
		},
		// Order: the server sorts by its own timestamps; swap two.
		"reordered": func() {
			sql(`UPDATE versions SET created_at = CASE id WHEN $1 THEN (SELECT created_at FROM genuine WHERE id = $2)
				ELSE (SELECT created_at FROM genuine WHERE id = $1) END WHERE id IN ($1, $2)`, ver(1), ver(2))
		},
		"middle version dropped": func() { sql(`DELETE FROM versions WHERE id = $1`, ver(2)) },
		"record moved to another version": func() {
			sql(`UPDATE versions SET record = (SELECT record FROM genuine WHERE id = $2), record_sig = (SELECT record_sig FROM genuine WHERE id = $2) WHERE id = $1`, ver(1), ver(3))
		},
		"records stripped from one version": func() {
			sql(`UPDATE versions SET record = NULL, record_sig = NULL, seq = NULL, record_hash = NULL WHERE id = $1`, ver(1))
		},
	} {
		tamper()
		if err := history(alice).Err; !errors.Is(err, e2ee.ErrHistory) {
			t.Errorf("%s: %v", name, err)
		}
		if err := save(alice, "on top"); !errors.Is(err, e2ee.ErrHistory) {
			t.Errorf("%s: saved on top of a broken history: %v", name, err)
		}
		reset()
	}

	// Rollback: the server cuts the newest version off and serves the one
	// before as current. Alice has seen version 4, so all her paths notice;
	// so does a restarted client on the same device. Carol never looked at
	// this file, so she cannot tell: that is the documented limit.
	rollback := func() {
		sql(`DELETE FROM versions WHERE id = $1`, ver(0))
		sql(`UPDATE nodes SET version_id = $1 WHERE id = $2`, ver(1), f.ID)
	}
	rollback()
	if err := history(alice).Err; !errors.Is(err, e2ee.ErrRolledBack) {
		t.Fatalf("rollback not noticed in the history: %v", err)
	}
	if _, err := read(alice); !errors.Is(err, e2ee.ErrRolledBack) {
		t.Fatalf("rollback not noticed on download: %v", err)
	}
	if _, err := alice.OpenRemote(ctx, f.ID); !errors.Is(err, e2ee.ErrRolledBack) {
		t.Fatalf("rollback not noticed by the drive: %v", err)
	}
	if err := save(alice, "on top"); !errors.Is(err, e2ee.ErrRolledBack) {
		t.Fatalf("saved on top of a rolled-back history: %v", err)
	}
	restarted := login("alice")
	if err := restarted.Unlock(ctx, pass, false); err != nil {
		t.Fatal(err)
	}
	restarted.SetSeenStore(must[*client.FileSeen](t)(client.OpenFileSeen(seenFile)))
	if _, err := read(restarted); !errors.Is(err, e2ee.ErrRolledBack) {
		t.Fatalf("restarted client did not remember: %v", err)
	}
	if got, err := read(carol); err != nil || got != "three" {
		t.Fatalf("carol, who never saw this file, reads %q: %v", got, err)
	}
	// Alice can accept the older state (after a server restore from backup,
	// say); then she works normally again.
	if err := alice.AcceptCurrent(ctx, f.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := read(alice); err != nil || got != "three" {
		t.Fatalf("after accepting: %q %v", got, err)
	}
	reset()

	// Fork: alice has seen version 4 (bob's restore). The server hides it
	// from carol, who saves her own version 4 on top of version 3. When
	// alice is shown that history, version 4 is not the one she saw.
	if got, err := read(alice); err != nil || got != "one" {
		t.Fatalf("read after reset: %q %v", got, err)
	}
	rollback()
	if err := save(carol, "carol's four"); err != nil {
		t.Fatal(err)
	}
	if err := history(alice).Err; !errors.Is(err, e2ee.ErrForked) {
		t.Fatalf("fork not noticed: %v", err)
	}
	if _, err := read(alice); !errors.Is(err, e2ee.ErrForked) {
		t.Fatalf("fork not noticed on download: %v", err)
	}
	// A server that also drops the whole signed history of a file alice
	// has seen signed is caught too.
	sql(`UPDATE versions SET record = NULL, record_sig = NULL, seq = NULL, record_hash = NULL WHERE node_id = $1`, f.ID)
	if _, err := read(alice); !errors.Is(err, e2ee.ErrRolledBack) {
		t.Fatalf("stripped history not noticed: %v", err)
	}
}
