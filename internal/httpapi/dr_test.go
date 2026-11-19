package httpapi_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/woah-buddy/FrontDir/internal/client"
	"github.com/woah-buddy/FrontDir/internal/service"
	"github.com/woah-buddy/FrontDir/internal/testutil"
)

// TestDisasterRecovery is the "the building burned down" drill. It runs a
// realistic workload, takes a full backup of the server (every database row,
// every file in the data directory, and the server's own logs), and then:
//
//  1. scans every byte of that backup for any plaintext a user entrusted to
//     the system (file contents, file/folder/team names, passphrases,
//     recovery codes, link secrets and passwords, app password tokens), in
//     raw, hex and base64 form;
//  2. restores it onto a brand-new server and proves users get everything
//     back using only their own secrets (passphrase or recovery code), while
//     a wrong passphrase gets nothing;
//  3. proves the administrator can verify the restore is complete and
//     intact without being able to read it.
func TestDisasterRecovery(t *testing.T) {
	ctx := context.Background()
	store1, schema1 := testutil.PostgresSchema(t)
	data1 := t.TempDir()
	logs := &lockedBuffer{}
	idp := newFakeOIDC(t) // the identity provider survives the fire; FrontDir does not
	h1 := newHarnessWith(t, harnessOpts{store: store1, dataDir: data1, oidc: idp, logs: logs})

	// Everything a user entrusts to the system, each made unique so that a
	// match in the backup cannot be a coincidence.
	uniq := func(s string) string { return s + " " + hex.EncodeToString(randBytes(6)) }
	var (
		alicePass   = uniq("alice's long passphrase")
		bobPass     = uniq("bob's long passphrase")
		folderName  = uniq("Medical Records")
		fileName    = uniq("diagnosis") + ".txt"
		contentV1   = uniq("PLAINTEXT version one of the diagnosis")
		contentV2   = uniq("PLAINTEXT version two of the diagnosis")
		trashName   = uniq("diary") + ".md"
		trashBody   = uniq("PLAINTEXT diary entry")
		teamName    = uniq("Project Nightingale")
		teamFile    = uniq("acquisition plan") + ".pdf"
		teamBody    = uniq("PLAINTEXT acquisition terms")
		linkPass    = uniq("link password")
		secretsSeen []string // filled with generated secrets below
	)

	// ---- before the fire: people use the system -----------------------------
	aliceB := h1.loginOIDC(idpUser{sub: "alice", email: "alice@example.test", groups: []string{"nas-users", "nas-admins"}})
	alice := client.New(h1.base, aliceB, "")
	aliceCode := must[string](t)(alice.SetupKeys(ctx, alicePass))
	bobB := h1.loginOIDC(idpUser{sub: "bob", email: "bob@example.test", groups: []string{"nas-users"}})
	bob := client.New(h1.base, bobB, "")
	bobCode := must[string](t)(bob.SetupKeys(ctx, bobPass))
	aliceMe := must[*client.Me](t)(alice.Me(ctx))
	bobMe := must[*client.Me](t)(bob.Me(ctx))

	put := func(c *client.Client, parent, name, body string) *client.Node {
		return must[*client.Node](t)(c.Upload(ctx, parent, name, strings.NewReader(body), int64(len(body)), time.Now()))
	}
	folderID := must[string](t)(alice.Mkdir(ctx, aliceMe.PersonalSpace.RootID, folderName))
	doc := put(alice, folderID, fileName, contentV1)
	must[*client.Node](t)(alice.UploadVersion(ctx, doc.ID, fileName, strings.NewReader(contentV2), int64(len(contentV2)), time.Now()))
	diary := put(alice, aliceMe.PersonalSpace.RootID, trashName, trashBody)
	if err := alice.Trash(ctx, diary); err != nil {
		t.Fatal(err)
	}
	team := must[*client.Space](t)(alice.CreateTeam(ctx, teamName))
	if err := alice.AddMember(ctx, team.ID, bobMe.User.ID, "write"); err != nil {
		t.Fatal(err)
	}
	if err := alice.GrantKey(ctx, team.ID, bobMe.User.ID); err != nil {
		t.Fatal(err)
	}
	tf := put(bob, team.RootID, teamFile, teamBody)
	folder := must[*client.Node](t)(alice.Resolve(ctx, folderName))
	if err := alice.ShareWithUser(ctx, folder, "bob@example.test", "read"); err != nil {
		t.Fatal(err)
	}
	link := must[string](t)(alice.CreateLink(ctx, doc, linkPass, 0, 0))
	linkToken, linkSecret, _ := strings.Cut(link[strings.Index(link, "#")+1:], ".")
	if code, _ := postJSON(t, h1.srv.Client(), h1.base+"/api/v1/public/node", map[string]string{"token": linkToken, "password": linkPass}); code != 200 {
		t.Fatalf("link before the fire: %d", code)
	}
	var ap struct{ Token string }
	req, _ := http.NewRequest("POST", h1.base+"/api/v1/app-passwords", strings.NewReader(`{"name":"backup job"}`))
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Content-Type", "application/json")
	resp, err := aliceB.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	json.NewDecoder(resp.Body).Decode(&ap)
	resp.Body.Close()
	if ap.Token == "" {
		t.Fatal("no app password")
	}
	secretsSeen = append(secretsSeen, aliceCode, bobCode, strings.ReplaceAll(aliceCode, "-", ""), linkToken, linkSecret, ap.Token)

	// ---- the backup: what an administrator would copy off-site --------------
	store2, dump := testutil.RestoreCopy(t, schema1)
	data2 := t.TempDir()
	copyTree(t, data1, data2)
	var backup [][]byte
	backup = append(backup, []byte(dump), logs.Bytes())
	filepath.WalkDir(data2, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(p)
			backup = append(backup, b)
		}
		return nil
	})

	t.Run("the backup holds no plaintext and no usable secret", func(t *testing.T) {
		plaintext := []string{alicePass, bobPass, folderName, fileName, contentV1, contentV2, trashName, trashBody,
			teamName, teamFile, teamBody, linkPass}
		for _, secret := range append(plaintext, secretsSeen...) {
			for _, form := range encodings(secret) {
				for _, part := range backup {
					if bytes.Contains(part, form) {
						t.Fatalf("backup contains %q (as %q)", secret, form)
					}
				}
			}
		}
		// Sanity check that the scan sees real content: the backup does
		// contain the expected metadata, such as users' email addresses.
		if !strings.Contains(dump, "alice@example.test") || !bytes.Contains(logs.Bytes(), []byte(`"event":"file.upload"`)) || len(backup) < 5 {
			t.Fatal("backup scan looked at nothing")
		}
	})

	// ---- after the fire: a brand-new server on the restored backup ----------
	h2 := newHarnessWith(t, harnessOpts{store: store2, dataDir: data2, oidc: idp})

	t.Run("the administrator can verify the restore without reading it", func(t *testing.T) {
		r := must[*service.StorageReport](t)(h2.svc.OperatorVerifyStorage(ctx, true))
		if !r.OK() || r.Versions != 4 || r.Orphans != 0 {
			t.Fatalf("restored storage: %+v", r)
		}
	})

	t.Run("users get everything back with their own secrets", func(t *testing.T) {
		a2B := h2.loginOIDC(idpUser{sub: "alice", email: "alice@example.test", groups: []string{"nas-users"}})
		a2 := client.New(h2.base, a2B, "")
		if me := must[*client.Me](t)(a2.Me(ctx)); me.User.ID != aliceMe.User.ID {
			t.Fatal("same identity did not map to the same account after restore")
		}
		if err := a2.Unlock(ctx, "not alice's passphrase at all", false); err == nil {
			t.Fatal("a wrong passphrase unlocked the restored keys")
		}
		if err := a2.Unlock(ctx, alicePass, false); err != nil {
			t.Fatal(err)
		}
		n := must[*client.Node](t)(a2.Resolve(ctx, folderName+"/"+fileName))
		var buf bytes.Buffer
		if _, err := a2.Download(ctx, n.ID, &buf); err != nil || buf.String() != contentV2 {
			t.Fatalf("alice's file after restore: %q %v", buf.String(), err)
		}
		// Even the trash survives, still encrypted, and restores.
		items := must[[]*client.Node](t)(a2.TrashItems(ctx, aliceMe.PersonalSpace.ID))
		if len(items) != 1 || items[0].Name != trashName {
			t.Fatalf("trash after restore: %+v", items)
		}
		if err := a2.RestoreTrash(ctx, items[0], aliceMe.PersonalSpace.RootID); err != nil {
			t.Fatal(err)
		}
		buf.Reset()
		if _, err := a2.Download(ctx, diary.ID, &buf); err != nil || buf.String() != trashBody {
			t.Fatalf("restored trash item: %q %v", buf.String(), err)
		}

		// Bob forgot his passphrase in the chaos: his recovery code works.
		b2B := h2.loginOIDC(idpUser{sub: "bob", email: "bob@example.test", groups: []string{"nas-users"}})
		b2 := client.New(h2.base, b2B, "")
		if err := b2.Unlock(ctx, bobCode, true); err != nil {
			t.Fatal(err)
		}
		for id, want := range map[string]string{tf.ID: teamBody, doc.ID: contentV2} { // team file; Alice's share
			buf.Reset()
			if _, err := b2.Download(ctx, id, &buf); err != nil || buf.String() != want {
				t.Fatalf("bob after restore: %q %v", buf.String(), err)
			}
		}
	})

	t.Run("restored links work again, which is why the runbook re-applies revocations", func(t *testing.T) {
		code, _ := postJSON(t, h2.srv.Client(), h2.base+"/api/v1/public/node", map[string]string{"token": linkToken, "password": linkPass})
		if code != 200 {
			t.Fatalf("link after restore: %d", code)
		}
		if n, err := h2.svc.OperatorRevokeAllLinks(ctx); err != nil || n != 1 {
			t.Fatalf("revoke after restore: %d %v", n, err)
		}
		if n, err := h2.am.EndEverySession(ctx); err != nil || n == 0 {
			t.Fatalf("end sessions after restore: %d %v", n, err)
		}
	})
}

// The scanner must catch a secret however it is embedded: a scan that
// cannot fail proves nothing.
func TestLeakScannerCatchesEncodedSecrets(t *testing.T) {
	secret := "PLAINTEXT diagnosis " + hex.EncodeToString(randBytes(6))
	found := func(haystack []byte) bool {
		for _, form := range encodings(secret) {
			if bytes.Contains(haystack, form) {
				return true
			}
		}
		return false
	}
	for pre := 0; pre < 3; pre++ {
		embedded := append(append(randBytes(pre+7), secret...), randBytes(5)...)
		for name, leak := range map[string]string{
			"raw":    string(embedded),
			"lower":  strings.ToLower(string(embedded)),
			"hex":    hex.EncodeToString(embedded),
			"base64": base64.StdEncoding.EncodeToString(embedded),
			"b64url": base64.RawURLEncoding.EncodeToString(embedded),
		} {
			if !found([]byte(`{"x":"` + leak + `"}`)) {
				t.Errorf("missed a %s leak at offset %d", name, pre+7)
			}
		}
	}
	if found([]byte(base64.StdEncoding.EncodeToString(randBytes(200)))) {
		t.Error("false positive on random data")
	}
}

// encodings returns forms in which a secret could leak: as-is, lowercased,
// hex, and base64 (standard and URL alphabets, at each of the three byte
// alignments a substring can have inside a longer encoded value).
func encodings(s string) [][]byte {
	out := [][]byte{[]byte(s), []byte(strings.ToLower(s)), []byte(hex.EncodeToString([]byte(s)))}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawURLEncoding} {
		for pad := 0; pad < 3; pad++ {
			e := enc.EncodeToString(append(make([]byte, pad), s...))
			// Drop characters influenced by the padding or the end.
			out = append(out, []byte(e[4:len(e)-4]))
		}
	}
	return out
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func postJSON(t *testing.T, c *http.Client, url string, body any) (int, []byte) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// lockedBuffer collects the server's logs from concurrent handlers.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) Bytes() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return bytes.Clone(l.b.Bytes())
}
