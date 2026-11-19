package httpapi_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/woah-buddy/FrontDir/internal/client"
	"github.com/woah-buddy/FrontDir/internal/davgw"
)

// The local decrypting WebDAV gateway (frontdir-cli mount), end to end:
// a real server, a real client holding unlocked keys, and WebDAV requests
// as Finder or Explorer would send them.
func TestDecryptingGateway(t *testing.T) {
	dataDir := t.TempDir()
	h := newHarnessWith(t, harnessOpts{dataDir: dataDir})
	ctx := context.Background()
	alice := client.New(h.base, h.loginOIDC(idpUser{sub: "alice", email: "alice@example.test", groups: []string{"nas-users"}}), "")
	must[string](t)(alice.SetupKeys(ctx, pass))

	start := func(readOnly bool) (base string, do func(method, p string, body []byte, hdr ...string) (*http.Response, []byte)) {
		token := strings.Repeat("A", 43)
		g := davgw.New(davgw.Options{Client: alice, ReadOnly: readOnly, TempDir: t.TempDir(), Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
		var handler http.Handler
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
		t.Cleanup(srv.Close)
		handler = davgw.Handler(g, token, strings.TrimPrefix(srv.URL, "http://"), nil)
		base = srv.URL + "/" + token + "/FrontDir"
		do = func(method, p string, body []byte, hdr ...string) (*http.Response, []byte) {
			t.Helper()
			req, _ := http.NewRequest(method, base+p, bytes.NewReader(body))
			for i := 0; i+1 < len(hdr); i += 2 {
				if hdr[i] == "Host" {
					req.Host = hdr[i+1]
				} else {
					req.Header.Set(hdr[i], hdr[i+1])
				}
			}
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return resp, b
		}
		return base, do
	}
	base, do := start(false)
	code := func(resp *http.Response, _ []byte) int { return resp.StatusCode }

	// Only a local WebDAV client that knows the secret path gets in.
	if c := code(do("PROPFIND", "/", nil, "Depth", "0", "Host", "evil.example")); c != http.StatusMisdirectedRequest {
		t.Fatalf("DNS rebinding: %d", c)
	}
	if c := code(do("GET", "/", nil, "Origin", "https://evil.example")); c != 403 {
		t.Fatalf("browser origin: %d", c)
	}
	if c := code(do("GET", "/", nil, "Sec-Fetch-Site", "cross-site")); c != 403 {
		t.Fatalf("cross-site fetch: %d", c)
	}
	wrong, _ := http.NewRequest("PROPFIND", strings.Replace(base, "AAAA", "AAAB", 1)+"/", nil)
	if resp, err := http.DefaultClient.Do(wrong); err != nil || resp.StatusCode != 404 {
		t.Fatalf("wrong token: %v %v", resp, err)
	}
	opt, _ := http.NewRequest("OPTIONS", strings.SplitN(base, "/AAAA", 2)[0]+"/", nil)
	if resp, err := http.DefaultClient.Do(opt); err != nil || resp.StatusCode != 200 || resp.Header.Get("DAV") == "" {
		t.Fatalf("OPTIONS on the root (Windows probe): %v %v", resp, err)
	}

	// The top level lists the spaces.
	resp, body := do("PROPFIND", "/", nil, "Depth", "1")
	if resp.StatusCode != 207 || !strings.Contains(string(body), "/FrontDir/Home/") {
		t.Fatalf("root listing: %d %s", resp.StatusCode, body)
	}
	if resp.Header.Get("Content-Security-Policy") == "" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("responses are not marked inert")
	}

	// Create, write, read back (whole and by range), replace.
	if c := code(do("MKCOL", "/Home/Docs", nil)); c != 201 {
		t.Fatalf("mkcol: %d", c)
	}
	content := make([]byte, 200_000) // spans four chunks
	rand.Read(content)
	if c := code(do("PUT", "/Home/Docs/report.bin", content)); c != 201 {
		t.Fatalf("put: %d", c)
	}
	if _, got := do("GET", "/Home/Docs/report.bin", nil); !bytes.Equal(got, content) {
		t.Fatal("read back differs")
	}
	resp, got := do("GET", "/Home/Docs/report.bin", nil, "Range", "bytes=131000-131099")
	if resp.StatusCode != 206 || !bytes.Equal(got, content[131000:131100]) {
		t.Fatalf("range read: %d", resp.StatusCode)
	}
	content2 := []byte("second version")
	if c := code(do("PUT", "/Home/Docs/report.bin", content2)); c != 201 && c != 204 {
		t.Fatalf("overwrite: %d", c)
	}
	if _, got := do("GET", "/home/docs/REPORT.bin", nil); !bytes.Equal(got, content2) {
		t.Fatal("case-insensitive read of the new version failed")
	}
	// What the server holds is ciphertext.
	filepath.WalkDir(dataDir, func(p string, d fs.DirEntry, err error) error {
		if b, _ := os.ReadFile(p); d != nil && !d.IsDir() && bytes.Contains(b, content2) {
			t.Errorf("plaintext reached the server: %s", p)
		}
		return nil
	})

	// Move and rename in one step; delete goes to the trash.
	if c := code(do("MOVE", "/Home/Docs/report.bin", nil, "Destination", base+"/Home/moved.bin")); c != 201 {
		t.Fatalf("move: %d", c)
	}
	if c := code(do("GET", "/Home/moved.bin", nil)); c != 200 {
		t.Fatalf("moved file: %d", c)
	}
	if c := code(do("DELETE", "/Home/moved.bin", nil)); c != 204 {
		t.Fatalf("delete: %d", c)
	}
	me := must[*client.Me](t)(alice.Me(ctx))
	trash := must[[]*client.Node](t)(alice.TrashItems(ctx, me.PersonalSpace.ID))
	if len(trash) != 1 || trash[0].Name != "moved.bin" {
		t.Fatalf("deleted file is not in the trash: %+v", trash)
	}
	// Nothing at the top level can be created or removed.
	if c := code(do("MKCOL", "/NewSpace", nil)); c != 403 && c != 405 {
		t.Fatalf("top-level mkcol: %d", c)
	}

	// Operating-system clutter stays local.
	for _, name := range []string{"/Home/.DS_Store", "/Home/Docs/._notes.txt", "/Home/~$draft.docx"} {
		if c := code(do("PUT", name, []byte("clutter"))); c != 201 {
			t.Fatalf("clutter %s: %d", name, c)
		}
		if _, got := do("GET", name, nil); string(got) != "clutter" {
			t.Fatalf("clutter %s not readable in the session", name)
		}
	}
	for _, n := range must[[]*client.Node](t)(alice.List(ctx, me.PersonalSpace.RootID)) {
		if strings.HasPrefix(n.Name, ".DS") || strings.HasPrefix(n.Name, "~$") {
			t.Fatalf("clutter was uploaded: %s", n.Name)
		}
	}

	// Tampering. Flip the last byte (part of the signature) of a stored
	// container: ranged reads still decrypt (every chunk authenticates),
	// but reading the file to the end fails, and the file is refused after.
	sig := make([]byte, 150_000)
	rand.Read(sig)
	if c := code(do("PUT", "/Home/signed.bin", sig)); c != 201 {
		t.Fatalf("put: %d", c)
	}
	flipLast(t, dataDir, int64(len(sig)))
	if resp, got := do("GET", "/Home/signed.bin", nil, "Range", "bytes=0-99"); resp.StatusCode != 206 || !bytes.Equal(got, sig[:100]) {
		t.Fatalf("ranged read of an authentic chunk: %d", resp.StatusCode)
	}
	if _, got := do("GET", "/Home/signed.bin", nil); bytes.Equal(got, sig) {
		t.Fatal("a file with a broken signature was served in full")
	}
	if _, got := do("GET", "/Home/signed.bin", nil, "Range", "bytes=0-99"); len(got) == 100 {
		t.Fatal("a file that failed its signature check is still served")
	}

	// A read-only gateway changes nothing.
	_, ro := start(true)
	if c := code(ro("PUT", "/Home/new.txt", []byte("x"))); c < 400 {
		t.Fatalf("read-only put: %d", c)
	}
	if c := code(ro("DELETE", "/Home/Docs", nil)); c < 400 {
		t.Fatalf("read-only delete: %d", c)
	}
}

// flipLast flips the final byte of the stored blob whose container holds
// plain bytes of plaintext (there must be exactly one).
func flipLast(t *testing.T, dir string, plain int64) {
	t.Helper()
	var found []string
	filepath.WalkDir(filepath.Join(dir, "blobs"), func(p string, d fs.DirEntry, err error) error {
		if d != nil && !d.IsDir() {
			if fi, _ := d.Info(); fi != nil && fi.Size() > plain && fi.Size() < plain+4096 {
				found = append(found, p)
			}
		}
		return nil
	})
	if len(found) != 1 {
		t.Fatalf("expected one blob near %d bytes, found %v", plain, found)
	}
	b, _ := os.ReadFile(found[0])
	b[len(b)-1] ^= 1
	os.WriteFile(found[0], b, 0o600)
}
