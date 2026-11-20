package httpapi_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/woah-buddy/FrontDir/internal/client"
	"github.com/woah-buddy/FrontDir/internal/testutil"
)

// Version attribution end to end (docs/E2EE.md §5b): every version names
// who wrote it, verified from the header without downloading the file, and
// a server cannot attribute a version to someone else.
func TestVersionAuthors(t *testing.T) {
	store, schema := testutil.PostgresSchema(t)
	h := newHarnessWith(t, harnessOpts{store: store})
	ctx := context.Background()
	user := func(name string) *client.Client {
		c := client.New(h.base, h.loginOIDC(idpUser{sub: name, email: name + "@example.test", groups: []string{"nas-users"}}), "")
		must[string](t)(c.SetupKeys(ctx, pass))
		return c
	}
	alice, bob := user("alice"), user("bob")
	aliceID := must[*client.Me](t)(alice.Me(ctx)).User.ID
	bobID := must[*client.Me](t)(bob.Me(ctx)).User.ID
	me := must[*client.Me](t)(alice.Me(ctx))
	docs := must[string](t)(alice.Mkdir(ctx, me.PersonalSpace.RootID, "Docs"))
	if err := alice.ShareWithUser(ctx, &client.Node{ID: docs, Name: "Docs", Kind: "folder"}, "bob@example.test", "write"); err != nil {
		t.Fatal(err)
	}
	f := must[*client.Node](t)(alice.Upload(ctx, docs, "plan.txt", strings.NewReader("alice's first draft"), 19, time.Now()))
	must[*client.Node](t)(bob.UploadVersion(ctx, f.ID, "plan.txt", strings.NewReader("bob's edit"), 10, time.Now()))
	vs := must[[]client.Version](t)(alice.Versions(ctx, f.ID))
	if len(vs) != 2 {
		t.Fatalf("%d versions", len(vs))
	}
	first := vs[1].ID
	// Bob restores Alice's first draft: he stores it, she still wrote it.
	if _, err := bob.RestoreVersion(ctx, f.ID, first); err != nil {
		t.Fatal(err)
	}

	type want struct{ author, uploader string }
	check := func(c *client.Client, label string, exp []want) []client.Version {
		t.Helper()
		vs := must[[]client.Version](t)(c.Versions(ctx, f.ID))
		if len(vs) != len(exp) {
			t.Fatalf("%s: %d versions, want %d", label, len(vs), len(exp))
		}
		for i, w := range exp {
			got := ""
			if vs[i].Author != nil {
				got = vs[i].Author.ID
			}
			if got != w.author || vs[i].UploadedBy != w.uploader {
				t.Fatalf("%s: version %d: author %q (%v), uploader %q; want %q, %q",
					label, i, got, vs[i].AuthorErr, vs[i].UploadedBy, w.author, w.uploader)
			}
		}
		return vs
	}
	all := []want{{aliceID, bobID}, {bobID, bobID}, {aliceID, aliceID}} // newest first
	check(alice, "alice", all)
	vs = check(bob, "bob", all)
	restored, bobs := vs[0].ID, vs[1].ID

	// A server that edits a digest cannot reassign the version: the check
	// fails and nobody is named.
	for _, tamper := range []string{
		`UPDATE versions SET body_hash = sha256(body_hash) WHERE id = $1`,
		`UPDATE versions SET trailer = set_byte(trailer, 40, get_byte(trailer, 40) # 1) WHERE id = $1`,
	} {
		if testutil.Exec(t, schema, tamper, bobs) != 1 {
			t.Fatal("tamper did not apply")
		}
		vs := must[[]client.Version](t)(alice.Versions(ctx, f.ID))
		if vs[1].Author != nil || vs[1].AuthorErr == nil {
			t.Fatalf("tampered digest still verified (%s)", tamper)
		}
		if vs[0].Author == nil || vs[2].Author == nil {
			t.Fatal("tampering one version affected the others")
		}
		// Undo by recomputing it from the stored ciphertext.
		testutil.Exec(t, schema, `UPDATE versions SET body_hash = NULL WHERE id = $1`, bobs)
		if _, err := h.svc.RunMaintenance(ctx, 10); err != nil {
			t.Fatal(err)
		}
	}
	check(alice, "after recompute", all)

	// Swapping headers between versions does not move authorship either:
	// Alice's header with Bob's body hash verifies for nobody.
	testutil.Exec(t, schema, `UPDATE versions SET header = (SELECT header FROM versions WHERE id = $2) WHERE id = $1`, bobs, restored)
	if vs := must[[]client.Version](t)(alice.Versions(ctx, f.ID)); vs[1].Author != nil {
		t.Fatalf("version attributed to %s through a swapped header", vs[1].Author.ID)
	}
	testutil.Exec(t, schema, `UPDATE versions SET body_hash = NULL WHERE id = $1`, bobs)
	must[int](t)(h.svc.RunMaintenance(ctx, 10))
	check(alice, "after swap repaired", all)

	// Versions stored before digests existed: unverifiable until the
	// maintenance worker computes them from the ciphertext.
	if testutil.Exec(t, schema, `UPDATE versions SET signer_id = NULL, header = NULL, body_hash = NULL, trailer = NULL`) != 3 {
		t.Fatal("expected three versions")
	}
	for _, v := range must[[]client.Version](t)(alice.Versions(ctx, f.ID)) {
		if v.Author != nil || !errors.Is(v.AuthorErr, client.ErrNoDigest) {
			t.Fatalf("legacy version: %v %v", v.Author, v.AuthorErr)
		}
	}
	must[int](t)(h.svc.RunMaintenance(ctx, 10))
	check(alice, "after backfill", all)
	if n := testutil.Exec(t, schema, `UPDATE versions SET body_hash = body_hash WHERE body_hash IS NULL`); n != 0 {
		t.Fatalf("%d versions still without a digest", n)
	}

	// Thumbnails follow the verified author, not the uploader and not the
	// header's bare claim. The current version is Alice's, restored by Bob.
	// Bob attaches a thumbnail to it; he is not its author, so only he sees it.
	img := []byte("\xff\xd8\xff bob's picture")
	if err := bob.AttachThumbnail(ctx, f.ID, img, "image/jpeg", 64, 64); err != nil {
		t.Fatal(err)
	}
	if _, _, err := alice.Thumbnail(ctx, f.ID); !errors.Is(err, client.ErrNoThumbnail) {
		t.Fatalf("alice was shown the restorer's thumbnail: %v", err)
	}
	// Alice attaches hers: everyone sees it, while her signature verifies.
	mine := []byte("\xff\xd8\xff alice's picture")
	if err := alice.AttachThumbnail(ctx, f.ID, mine, "image/jpeg", 64, 64); err != nil {
		t.Fatal(err)
	}
	if _, got, err := bob.Thumbnail(ctx, f.ID); err != nil || !bytes.Equal(got, mine) {
		t.Fatalf("bob does not see the author's thumbnail: %v", err)
	}
	// If the server breaks the digest, the author can no longer be
	// verified, and bob falls back to his own thumbnail.
	testutil.Exec(t, schema, `UPDATE versions SET body_hash = sha256(body_hash) WHERE id = $1`, restored)
	if _, got, err := bob.Thumbnail(ctx, f.ID); err != nil || !bytes.Equal(got, img) {
		t.Fatalf("with an unverifiable author bob should see only his own thumbnail: %v", err)
	}
}
