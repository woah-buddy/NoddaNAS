package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/woah-buddy/FrontDir/internal/client"
	"github.com/woah-buddy/FrontDir/internal/e2ee"
	"github.com/woah-buddy/FrontDir/internal/testutil"
)

// File mailboxes end to end (docs/E2EE.md §6a): anyone with the link can
// drop files; nobody can read anything through it; only folder writers see
// and file drops; limits, passwords, closing, expiry and purges hold.
func TestMailbox(t *testing.T) {
	store, schema := testutil.PostgresSchema(t)
	dataDir := t.TempDir()
	h := newHarnessWith(t, harnessOpts{store: store, dataDir: dataDir})
	ctx := context.Background()
	sql := func(q string, args ...any) int64 { t.Helper(); return testutil.Exec(t, schema, q, args...) }
	user := func(name string) *client.Client {
		c := client.New(h.base, h.loginOIDC(idpUser{sub: name, email: name + "@example.test", groups: []string{"nas-users"}}), "")
		must[string](t)(c.SetupKeys(ctx, pass))
		return c
	}
	alice, bob := user("alice"), user("bob")
	stranger := client.New(h.base, h.srv.Client(), "") // no account, no session
	me := must[*client.Me](t)(alice.Me(ctx))
	inboxFolder := must[string](t)(alice.Mkdir(ctx, me.PersonalSpace.RootID, "Receipts"))
	expires := time.Now().Add(7 * 24 * time.Hour)
	create := func(o client.MailboxOptions) (string, *client.Mailbox) {
		t.Helper()
		if o.ExpiresAt.IsZero() {
			o.ExpiresAt = expires
		}
		link, m, err := alice.CreateMailbox(ctx, inboxFolder, o)
		if err != nil {
			t.Fatal(err)
		}
		return link, m
	}
	link, mb := create(client.MailboxOptions{Title: "Receipts for 2026 ✓",
		ExpiresAt: expires, MaxBytes: 200_000, MaxFiles: 4})
	if !strings.Contains(link, "/m#") || mb.PendingFiles != 0 {
		t.Fatalf("link %q", link)
	}

	// A sender sees the title and whose mailbox it is, decrypted with the
	// key in the link, and nothing else.
	view := must[*client.MailboxForSender](t)(stranger.OpenMailboxLink(ctx, link, ""))
	if view.Title != "Receipts for 2026 ✓" || view.Owner != me.User.DisplayName || view.FilesLeft != 4 {
		t.Fatalf("sender view %+v", view)
	}
	secret := "TOP-SECRET-RECEIPT-CONTENT "
	drop := func(c *client.Client, l, pw, name, text string, note *e2ee.DropNote) error {
		return c.DropFile(ctx, l, pw, name, strings.NewReader(text), int64(len(text)), note)
	}
	taxi := secret + "taxi" + strings.Repeat(".", 60_000) // big enough that charging it twice would show
	if err := drop(stranger, link, "", "taxi.pdf", taxi, &e2ee.DropNote{Name: "Bob Sender", Email: "b@example.test", Message: "for the trip"}); err != nil {
		t.Fatal(err)
	}
	if err := drop(stranger, link, "", "hotel.pdf", secret+"hotel", nil); err != nil {
		t.Fatal(err)
	}

	// One-way: the public endpoint tells nothing about drops, and the token
	// opens nothing else.
	_, token, _, _ := client.ParseMailboxLink(link)
	_, raw := postJSON(t, h.srv.Client(), h.base+"/api/v1/public/mailbox", map[string]string{"token": token})
	var keys map[string]any
	json.Unmarshal(raw, &keys)
	for k := range keys {
		if !map[string]bool{"id": true, "info": true, "expiresAt": true, "maxFileSize": true, "remainingBytes": true, "filesLeft": true}[k] {
			t.Errorf("sender view reveals %q", k)
		}
	}
	for _, path := range []string{"/api/v1/public/node", "/api/v1/public/download"} {
		if code, _ := postJSON(t, h.srv.Client(), h.base+path, map[string]string{"token": token}); code != http.StatusNotFound {
			t.Errorf("mailbox token opened %s: %d", path, code)
		}
	}
	if code := getStatus(t, h, "/api/v1/mailboxes/"+mb.ID); code != http.StatusUnauthorized {
		t.Errorf("anonymous inbox: %d", code)
	}
	// The server stores no plaintext: neither contents nor names.
	filepath.WalkDir(dataDir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if b, _ := os.ReadFile(p); bytes.Contains(b, []byte("TOP-SECRET")) || bytes.Contains(b, []byte("taxi.pdf")) {
				t.Errorf("plaintext stored in %s", p)
			}
		}
		return nil
	})

	// A server that swaps in its own key (by sending a link holder a
	// different description) is caught: the description must decrypt
	// with the key in the link.
	_, _, otherPub, _ := client.ParseMailboxLink(firstOf(create(client.MailboxOptions{
		Title: "other", ExpiresAt: expires, MaxBytes: 1000})))
	swapped := client.MailboxLink(h.base, token, otherPub)
	if err := drop(stranger, swapped, "", "x.pdf", "x", nil); err == nil {
		t.Fatal("drop sent to a mailbox whose description does not match the link's key")
	}

	// Only people who can write to the folder see the inbox: the server
	// itself says it does not exist (checked directly, not via a client
	// that would fail later for want of the folder key).
	bobHTTP := h.loginOIDC(idpUser{sub: "bob", email: "bob@example.test", groups: []string{"nas-users"}})
	bobSees := func() int {
		t.Helper()
		resp, err := bobHTTP.Get(h.base + "/api/v1/mailboxes/" + mb.ID)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := bobSees(); code != http.StatusNotFound {
		t.Fatalf("bob sees alice's inbox: %d", code)
	}
	if err := alice.ShareWithUser(ctx, &client.Node{ID: inboxFolder, Name: "Receipts", Kind: "folder"}, "bob@example.test", "read"); err != nil {
		t.Fatal(err)
	}
	if code := bobSees(); code != http.StatusNotFound {
		t.Fatalf("read access shows the inbox: %d", code)
	}
	if _, err := bob.OpenInbox(ctx, mb.ID); !isStatus(err, http.StatusNotFound) {
		t.Fatalf("read access opens the inbox: %v", err)
	}

	in := must[*client.Inbox](t)(alice.OpenInbox(ctx, mb.ID))
	if in.Title != "Receipts for 2026 ✓" || len(in.Drops) != 2 || in.Drops[0].Name != "taxi.pdf" || in.Drops[0].Note.Message != "for the trip" {
		t.Fatalf("inbox %+v", in)
	}
	var review bytes.Buffer
	if err := alice.ReadDrop(ctx, in, &in.Drops[0], &review); err != nil || review.String() != taxi {
		t.Fatalf("review: %q %v", review.String(), err)
	}
	usedBefore := must[*client.Me](t)(alice.Me(ctx)).PersonalSpace.UsedBytes

	// Filing: a normal file, signed by alice, recorded as a drop, carrying
	// the sender's note; the drop is gone and was not charged twice.
	f := must[*client.Node](t)(alice.FileDrop(ctx, in, &in.Drops[0]))
	var got bytes.Buffer
	meta, err := alice.Download(ctx, f.ID, &got)
	if err != nil || got.String() != taxi || meta.From == nil || meta.From.Name != "Bob Sender" {
		t.Fatalf("filed file: %q %+v %v", got.String(), meta, err)
	}
	hs := must[*client.History](t)(alice.Versions(ctx, f.ID))
	if hs.Err != nil || hs.Versions[0].Kind != e2ee.KindDrop || hs.Versions[0].StoredBy.ID != me.User.ID {
		t.Fatalf("filed history: %+v %v", hs.Versions, hs.Err)
	}
	usedAfter := must[*client.Me](t)(alice.Me(ctx)).PersonalSpace.UsedBytes
	if growth := usedAfter - usedBefore; growth <= 0 || growth > 2000 { // only the new header and trailer
		t.Fatalf("filing changed usage by %d bytes", growth)
	}
	if _, err := alice.FileDrop(ctx, in, &in.Drops[0]); err == nil {
		t.Fatal("a drop was filed twice")
	}
	// Name taken: filed under a numbered name.
	if err := drop(stranger, link, "", "taxi.pdf", "second taxi", nil); err != nil {
		t.Fatal(err)
	}
	in = must[*client.Inbox](t)(alice.OpenInbox(ctx, mb.ID))
	var second *client.PendingDrop
	for i := range in.Drops {
		if in.Drops[i].Name == "taxi.pdf" {
			second = &in.Drops[i]
		}
	}
	if n := must[*client.Node](t)(alice.FileDrop(ctx, in, second)); n.Name != "taxi (2).pdf" {
		t.Fatalf("numbered name %q", n.Name)
	}

	// Limits: 3 of 4 files used; one more fits, then the mailbox is full.
	if err := drop(stranger, link, "", "four.pdf", "4", nil); err != nil {
		t.Fatal(err)
	}
	if err := drop(stranger, link, "", "five.pdf", "5", nil); !isStatus(err, http.StatusInsufficientStorage) {
		t.Fatalf("file cap: %v", err)
	}
	link2, mb2 := create(client.MailboxOptions{Title: "small", ExpiresAt: expires, MaxBytes: 100})
	if err := drop(stranger, link2, "", "big.bin", strings.Repeat("b", 200), nil); !isStatus(err, http.StatusInsufficientStorage) {
		t.Fatalf("size cap: %v", err)
	}

	// Discarding refunds the space.
	in = must[*client.Inbox](t)(alice.OpenInbox(ctx, mb.ID))
	before := must[*client.Me](t)(alice.Me(ctx)).PersonalSpace.UsedBytes
	for _, d := range in.Drops {
		if err := alice.DiscardDrop(ctx, mb.ID, d.ID); err != nil {
			t.Fatal(err)
		}
	}
	if after := must[*client.Me](t)(alice.Me(ctx)).PersonalSpace.UsedBytes; after >= before {
		t.Fatalf("discard did not refund: %d -> %d", before, after)
	}

	// Passwords.
	link3, mb3 := create(client.MailboxOptions{Title: "locked", Password: "correct horse 42",
		ExpiresAt: expires, MaxBytes: 10_000})
	if _, err := stranger.OpenMailboxLink(ctx, link3, ""); !isStatus(err, http.StatusUnauthorized) {
		t.Fatalf("no password: %v", err)
	}
	if err := drop(stranger, link3, "wrong password!", "a", "a", nil); !isStatus(err, http.StatusUnauthorized) {
		t.Fatalf("wrong password: %v", err)
	}
	if err := drop(stranger, link3, "correct horse 42", "a.txt", "a", nil); err != nil {
		t.Fatal(err)
	}

	// Closing stops drops; what is pending can still be filed.
	if err := alice.CloseMailbox(ctx, mb3.ID); err != nil {
		t.Fatal(err)
	}
	if err := drop(stranger, link3, "correct horse 42", "b.txt", "b", nil); !isStatus(err, http.StatusGone) {
		t.Fatalf("closed: %v", err)
	}
	in3 := must[*client.Inbox](t)(alice.OpenInbox(ctx, mb3.ID))
	must[*client.Node](t)(alice.FileDrop(ctx, in3, &in3.Drops[0]))
	// Expiry.
	sql(`UPDATE mailboxes SET expires_at = now() - interval '1 minute' WHERE id = $1`, mb2.ID)
	if err := drop(stranger, link2, "", "late.txt", "x", nil); !isStatus(err, http.StatusGone) {
		t.Fatalf("expired: %v", err)
	}
	// The kill switch closes mailboxes too.
	if err := alice.RevokeMyLinks(ctx); err != nil {
		t.Fatal(err)
	}
	if err := drop(stranger, link, "", "after.txt", "x", nil); !isStatus(err, http.StatusGone) {
		t.Fatalf("after the kill switch: %v", err)
	}

	// Finished mailboxes lose their pending drops after the retention
	// period, refunding the space, and then disappear.
	link4, mb4 := create(client.MailboxOptions{Title: "old", ExpiresAt: expires, MaxBytes: 10_000})
	if err := drop(stranger, link4, "", "stale.txt", "stale", nil); err != nil {
		t.Fatal(err)
	}
	sql(`UPDATE mailboxes SET closed_at = now() - interval '400 days' WHERE id = $1`, mb4.ID)
	must[int](t)(h.svc.RunMaintenance(ctx, 10))
	if _, err := alice.OpenInbox(ctx, mb4.ID); !isStatus(err, http.StatusNotFound) {
		t.Fatalf("finished mailbox kept: %v", err)
	}
	if n := sql(`UPDATE mailbox_drops SET size = size WHERE mailbox_id = $1`, mb4.ID); n != 0 {
		t.Fatal("finished mailbox's drops kept")
	}

	// A mailbox on a trashed folder takes nothing, and deleting the folder
	// for good takes the mailbox and its pending drops with it.
	link5, _ := create(client.MailboxOptions{Title: "doomed", ExpiresAt: expires, MaxBytes: 10_000})
	if err := drop(stranger, link5, "", "pending.txt", "pending", nil); err != nil {
		t.Fatal(err)
	}
	if err := alice.Trash(ctx, &client.Node{ID: inboxFolder, ParentID: me.PersonalSpace.RootID, Name: "Receipts", Kind: "folder"}); err != nil {
		t.Fatal(err)
	}
	if err := drop(stranger, link5, "", "x.txt", "x", nil); !isStatus(err, http.StatusNotFound) {
		t.Fatalf("trashed folder: %v", err)
	}
	sql(`UPDATE nodes SET trashed_at = now() - interval '400 days' WHERE id = $1`, inboxFolder)
	must[int](t)(h.svc.RunMaintenance(ctx, 10))
	if n := sql(`UPDATE mailboxes SET info = info WHERE node_id = $1`, inboxFolder); n != 0 {
		t.Fatal("purged folder kept its mailboxes")
	}
}

func isStatus(err error, status int) bool {
	var ae *client.APIError
	return errors.As(err, &ae) && ae.Status == status
}

func getStatus(t *testing.T, h *harness, path string) int {
	t.Helper()
	resp, err := h.srv.Client().Get(h.base + path)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func firstOf[A, B any](a A, _ B) A { return a }
