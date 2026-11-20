package e2ee

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestBrowserInterop checks that the browser implementation (web/static/e2ee.js)
// and this package agree byte-for-byte on docs/E2EE.md, in both directions.
// It needs Node.js with Playwright and Chromium; set FRONTDIR_BROWSER_TEST=1.
func TestBrowserInterop(t *testing.T) {
	if os.Getenv("FRONTDIR_BROWSER_TEST") == "" {
		t.Skip("set FRONTDIR_BROWSER_TEST=1 (needs node + playwright)")
	}
	_, here, _, _ := runtime.Caller(0)
	repo := filepath.Join(filepath.Dir(here), "..", "..")

	// ---- vectors written by Go ----
	const userID = "0123456789abcdef0123456789abcdef"
	acct, bundle, code, err := NewAccount(userID, "go passphrase 1234")
	if err != nil {
		t.Fatal(err)
	}
	spaceID, rootID, childID := strings.Repeat("5", 32), strings.Repeat("6", 32), strings.Repeat("7", 32)
	space := acct.PersonalSpace(spaceID)
	root, child := NewNodeKey(), NewNodeKey()
	plain := strings.Repeat("hello from Go ✓ ", 9000) // spans several chunks
	r, _, _ := NewWriter(strings.NewReader(plain), WriteParams{Size: int64(len(plain)), NodeKey: child, SpaceID: spaceID,
		SpacePub: space.Priv.PublicKey(), Meta: Meta{Name: "Résumé ✓.txt", Type: "text/plain", MTime: 1}, Signer: acct})
	container, _ := io.ReadAll(r)
	cp, _ := ParsePrefix(bytes.NewReader(container))
	ck, _ := cp.Keys(child)
	thumbImg := []byte("\xff\xd8\xff thumbnail from Go")
	thumbEnc, thumbSig, err := SealThumb(acct, childID, cp, ck, thumbImg, "image/jpeg", 64, 48)
	if err != nil {
		t.Fatal(err)
	}
	hashKey := NewNodeKey()
	hashNames := []string{"Report.PDF", "report.pdf", "İstanbul", "ΣΟΦΟΣ", "ΌΣΟΣ ΧΡΌΝΟΣ", "STRASSE", "straße", "ǅemal",
		"ﬀ", "é", "é", "Ⅻ", "ΑΣ.txt", "日本語", "😀 emoji"}
	contactID, contactFP := strings.Repeat("c", 32), strings.Repeat("f", 40)
	sealedContacts, err := acct.SealContacts(&Contacts{V: 1, Contacts: map[string]Contact{
		contactID: {FP: contactFP, Name: "Bob ✓", Email: "bob@example.test", VerifiedAt: 1700000000000}}})
	if err != nil {
		t.Fatal(err)
	}
	vectors := map[string]any{
		"bundle": bundle, "passphrase": "go passphrase 1234", "recoveryCode": code, "fingerprint": acct.Fingerprint(),
		"spaceId": spaceID, "spacePub": B64(space.PublicKey()), "rootId": rootID, "rootKey": space.WrapRoot(rootID, root),
		"rootRaw": B64(root.Raw()), "childId": childID, "childWrapped": root.WrapChild(childID, child), "childRaw": B64(child.Raw()),
		"childName": "Résumé ✓.txt", "childNameEnc": root.EncryptName(childID, "Résumé ✓.txt"), "container": B64(container),
		"plaintext": plain, "hashKeyRaw": B64(hashKey.Raw()), "hashNames": hashNames,
		"jsSpaceId": strings.Repeat("8", 32), "teamId": strings.Repeat("9", 32), "shareId": strings.Repeat("a", 32),
		"contacts": sealedContacts, "contactId": contactID, "contactFp": contactFP,
		"thumb": map[string]string{"enc": thumbEnc, "sig": thumbSig, "data": B64(thumbImg)},
	}
	vjson, _ := json.Marshal(vectors)

	mux := http.NewServeMux()
	mux.HandleFunc("/index.html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<!doctype html><title>interop</title>"))
	})
	mux.HandleFunc("/e2ee.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		http.ServeFile(w, r, filepath.Join(repo, "web", "static", "e2ee.js"))
	})
	mux.HandleFunc("/vectors.json", func(w http.ResponseWriter, r *http.Request) { w.Write(vjson) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	base := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1) // a secure context, so WebCrypto is available

	cmd := exec.Command("node", filepath.Join(repo, "test", "interop", "interop.mjs"), base)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("browser driver: %v\n%s", err, stderr.String())
	}
	var res struct {
		Checks     map[string]string `json:"checks"`
		NameHashes map[string]string `json:"nameHashes"`
		PageErrors []string          `json:"pageErrors"`
		JS         json.RawMessage   `json:"js"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("driver output: %v\n%s", err, out)
	}
	for name, outcome := range res.Checks {
		if outcome != "ok" {
			t.Errorf("browser check %s: %s", name, outcome)
		}
	}
	if len(res.Checks) < 10 || len(res.PageErrors) > 0 {
		t.Fatalf("checks %v, page errors %v", res.Checks, res.PageErrors)
	}
	for _, n := range hashNames {
		if got, want := res.NameHashes[n], hashKey.NameHash(n); got != want {
			t.Errorf("name hash for %q differs: browser %s, Go %s", n, got, want)
		}
	}

	// ---- verify what the browser wrote ----
	var js struct {
		Bundle       Bundle            `json:"bundle"`
		RecoveryCode string            `json:"recoveryCode"`
		Passphrase   string            `json:"passphrase"`
		SpaceID      string            `json:"spaceId"`
		SpacePub     string            `json:"spacePub"`
		SpaceKeySig  string            `json:"spaceKeySig"`
		RootID       string            `json:"rootId"`
		RootKey      string            `json:"rootKey"`
		RootRaw      string            `json:"rootRaw"`
		ChildID      string            `json:"childId"`
		ChildRaw     string            `json:"childRaw"`
		Entry        map[string]string `json:"entry"`
		Container    string            `json:"container"`
		Plaintext    string            `json:"plaintext"`
		Share        map[string]string `json:"share"`
		TeamSecret   string            `json:"teamSecret"`
		TeamGrant    map[string]string `json:"teamGrant"`
		TeamName     string            `json:"teamName"`
		LinkSecret   string            `json:"linkSecret"`
		LinkKey      string            `json:"linkKey"`
		Trash        map[string]string `json:"trash"`
		Contacts     string            `json:"contacts"`
		Thumb        map[string]string `json:"thumb"`
	}
	if err := json.Unmarshal(res.JS, &js); err != nil {
		t.Fatal(err)
	}
	jsAcct, err := Unlock(&js.Bundle, js.Passphrase)
	if err != nil {
		t.Fatalf("Go cannot unlock the browser's bundle: %v", err)
	}
	if _, err := UnlockWithRecoveryCode(&js.Bundle, js.RecoveryCode); err != nil {
		t.Fatalf("Go cannot use the browser's recovery code: %v", err)
	}
	jsPub, err := VerifyPublicKeys(js.Bundle.UserID, js.Bundle.Pub, js.Bundle.SelfSig)
	if err != nil {
		t.Fatal(err)
	}
	jsSpace := jsAcct.PersonalSpace(js.SpaceID)
	if B64(jsSpace.PublicKey()) != js.SpacePub {
		t.Fatal("space public key derivation differs")
	}
	if _, err := VerifySpaceKey(jsPub, js.SpaceID, js.SpacePub, js.SpaceKeySig); err != nil {
		t.Fatal(err)
	}
	jsRoot, err := jsSpace.UnwrapRoot(js.RootID, js.RootKey)
	if err != nil || B64(jsRoot.Raw()) != js.RootRaw {
		t.Fatalf("root key: %v", err)
	}
	jsChild, err := jsRoot.UnwrapChild(js.ChildID, js.Entry["wrappedKey"])
	if err != nil || B64(jsChild.Raw()) != js.ChildRaw {
		t.Fatalf("child key: %v", err)
	}
	if n, err := jsRoot.DecryptName(js.ChildID, js.Entry["nameEnc"]); err != nil || n != "Ünïcode name.txt" {
		t.Fatalf("name: %q %v", n, err)
	}
	if js.Entry["nameHash"] != jsRoot.NameHash("ünïcode NAME.txt") {
		t.Fatal("browser name hash is not case-insensitive in the same way as Go")
	}
	ct, _ := UnB64(js.Container)
	p, err := ParsePrefix(bytes.NewReader(ct))
	if err != nil {
		t.Fatal(err)
	}
	if p.TotalSize() != int64(len(ct)) {
		t.Fatal("browser container size is wrong")
	}
	k, err := p.Keys(jsChild)
	if err != nil {
		t.Fatal(err)
	}
	var plainOut bytes.Buffer
	if err := DecryptVerify(bytes.NewReader(ct[p.BodyOffset():]), &plainOut, p, k, jsPub); err != nil || plainOut.String() != js.Plaintext {
		t.Fatalf("Go cannot decrypt/verify the browser container: %v", err)
	}
	if nk, err := p.OwnerNodeKey(jsSpace); err != nil || B64(nk.Raw()) != js.ChildRaw {
		t.Fatalf("owner seal: %v", err)
	}
	if th, img, err := OpenThumb(jsPub, js.ChildID, p, k, js.Thumb["enc"], js.Thumb["sig"]); err != nil ||
		string(img) != "browser thumbnail" || th.Type != "image/webp" || th.W != 32 || !ThumbAuthorOK(p, jsPub, "someone else") {
		t.Fatalf("Go cannot open the browser's thumbnail: %v", err)
	}
	nk, name, err := OpenShare(acct, jsPub, strings.Repeat("a", 32), js.ChildID, "write", js.Share["sealedKey"], js.Share["sig"])
	if err != nil || name != "Shared folder" || B64(nk.Raw()) != js.ChildRaw {
		t.Fatalf("share: %v", err)
	}
	team, err := OpenGrant(acct, jsPub, strings.Repeat("9", 32), js.TeamGrant["grant"], js.TeamGrant["grantSig"])
	if err != nil || B64(team.Secret) != js.TeamSecret {
		t.Fatalf("team grant: %v", err)
	}
	if n, err := team.DecryptName(js.TeamName); err != nil || n != "Team ✓" {
		t.Fatalf("team name: %v", err)
	}
	ls, _ := UnB64(js.LinkSecret)
	if nk, n, err := OpenLinkKey(ls, strings.Repeat("a", 32), js.ChildID, js.LinkKey); err != nil || n != "Linked" || B64(nk.Raw()) != js.ChildRaw {
		t.Fatalf("link key: %v", err)
	}
	if nk, kn, err := OpenTrashKey(space, jsPub, js.ChildID, js.Trash["restoreKey"], js.Trash["restoreSig"]); err != nil || kn.Name != "trashed.txt" || B64(nk.Raw()) != js.ChildRaw {
		t.Fatalf("trash key: %v", err)
	}
	c, err := jsAcct.OpenContacts(js.Contacts)
	if err != nil || c.Contacts[strings.Repeat("d", 32)].Name != "From the browser ✓" || c.Contacts[strings.Repeat("d", 32)].FP != strings.Repeat("e", 40) {
		t.Fatalf("Go cannot open the browser's contact list: %+v %v", c, err)
	}
	if _, err := acct.OpenContacts(js.Contacts); err == nil {
		t.Fatal("a contact list opened under another account")
	}
}
