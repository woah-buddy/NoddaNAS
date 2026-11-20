package httpapi_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/woah-buddy/FrontDir/internal/client"
)

// Thumbnails end to end (docs/E2EE.md §5a): attached beside a version,
// shown only when made by the version's author or by the viewer.
func TestThumbnails(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	user := func(name string) *client.Client {
		c := client.New(h.base, h.loginOIDC(idpUser{sub: name, email: name + "@example.test", groups: []string{"nas-users"}}), "")
		must[string](t)(c.SetupKeys(ctx, pass))
		return c
	}
	alice, bob, carol := user("alice"), user("bob"), user("carol")
	me := must[*client.Me](t)(alice.Me(ctx))
	docs := must[string](t)(alice.Mkdir(ctx, me.PersonalSpace.RootID, "Photos"))
	f := must[*client.Node](t)(alice.Upload(ctx, docs, "beach.jpg", strings.NewReader("pretend photo"), 13, time.Now()))
	other := must[*client.Node](t)(alice.Upload(ctx, docs, "other.jpg", strings.NewReader("x"), 1, time.Now()))
	d := &client.Node{ID: docs, Name: "Photos", Kind: "folder"}
	if err := alice.ShareWithUser(ctx, d, "bob@example.test", "write"); err != nil {
		t.Fatal(err)
	}
	if err := alice.ShareWithUser(ctx, d, "carol@example.test", "read"); err != nil {
		t.Fatal(err)
	}
	hasThumb := func(c *client.Client, id string) bool {
		t.Helper()
		for _, n := range must[[]*client.Node](t)(c.List(ctx, docs)) {
			if n.ID == id {
				return n.HasThumbnail
			}
		}
		t.Fatalf("%s not listed", id)
		return false
	}

	// No thumbnail yet.
	if _, _, err := carol.Thumbnail(ctx, f.ID); !errors.Is(err, client.ErrNoThumbnail) {
		t.Fatalf("thumbnail before any: %v", err)
	}
	// The author attaches one; everyone with access sees it.
	real := []byte("\xff\xd8\xff real beach")
	if err := alice.AttachThumbnail(ctx, f.ID, real, "image/jpeg", 256, 192); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]*client.Client{"alice": alice, "bob": bob, "carol": carol} {
		if _, img, err := c.Thumbnail(ctx, f.ID); err != nil || !bytes.Equal(img, real) || !hasThumb(c, f.ID) {
			t.Fatalf("%s does not see the author's thumbnail: %v", name, err)
		}
	}

	// A collaborator with write access attaches a misleading one: only he
	// sees it, and the author's stays for everyone else.
	fake := []byte("\xff\xd8\xff something else entirely")
	if err := bob.AttachThumbnail(ctx, other.ID, fake, "image/jpeg", 256, 192); err != nil {
		t.Fatal(err)
	}
	if _, img, err := bob.Thumbnail(ctx, other.ID); err != nil || !bytes.Equal(img, fake) {
		t.Fatalf("bob does not see his own thumbnail: %v", err)
	}
	if _, _, err := carol.Thumbnail(ctx, other.ID); !errors.Is(err, client.ErrNoThumbnail) || hasThumb(carol, other.ID) {
		t.Fatalf("carol was shown bob's thumbnail of alice's file: %v", err)
	}
	if _, _, err := alice.Thumbnail(ctx, other.ID); !errors.Is(err, client.ErrNoThumbnail) {
		t.Fatalf("alice was shown bob's thumbnail of her file: %v", err)
	}
	if err := bob.AttachThumbnail(ctx, f.ID, fake, "image/jpeg", 256, 192); err != nil {
		t.Fatal(err)
	}
	if _, img, _ := carol.Thumbnail(ctx, f.ID); !bytes.Equal(img, real) {
		t.Fatal("bob's thumbnail replaced the author's")
	}
	if _, img, _ := bob.Thumbnail(ctx, f.ID); !bytes.Equal(img, real) {
		t.Fatal("the author's thumbnail should come first")
	}

	// Read access is not enough to attach one.
	err := carol.AttachThumbnail(ctx, f.ID, fake, "image/jpeg", 10, 10)
	if ae, ok := err.(*client.APIError); !ok || ae.Status != http.StatusForbidden {
		t.Fatalf("read share attached a thumbnail: %v", err)
	}

	// A thumbnail belongs to one version: a new version starts without one.
	must[*client.Node](t)(alice.UploadVersion(ctx, f.ID, "beach.jpg", strings.NewReader("new photo"), 9, time.Now()))
	if _, _, err := alice.Thumbnail(ctx, f.ID); !errors.Is(err, client.ErrNoThumbnail) || hasThumb(alice, f.ID) {
		t.Fatalf("old version's thumbnail shown for the new one: %v", err)
	}

	// The server checks the shape and that the version belongs to the file.
	put := func(body string) int {
		req, _ := http.NewRequest("PUT", h.base+"/api/v1/nodes/"+f.ID+"/thumbnail", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		resp, err := h.loginOIDC(idpUser{sub: "alice", email: "alice@example.test", groups: []string{"nas-users"}}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	sig := strings.Repeat("A", 86)
	if c := put(`{"versionId":"` + other.ID + `","enc":"` + strings.Repeat("A", 60) + `","sig":"` + sig + `"}`); c != 404 {
		t.Fatalf("someone else's version: %d", c)
	}
	nodes := must[[]*client.Node](t)(alice.List(ctx, docs))
	var ver string
	for _, n := range nodes {
		if n.ID == f.ID {
			ver = n.VersionID
		}
	}
	if c := put(`{"versionId":"` + ver + `","enc":"` + strings.Repeat("A", 49200) + `","sig":"` + sig + `"}`); c != 400 {
		t.Fatalf("oversized thumbnail: %d", c)
	}
	if c := put(`{"versionId":"` + ver + `","enc":"` + strings.Repeat("A", 60) + `","sig":"short"}`); c != 400 {
		t.Fatalf("malformed signature: %d", c)
	}
}
