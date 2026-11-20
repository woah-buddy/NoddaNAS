package e2ee

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

const uid = "0123456789abcdef0123456789abcdef"

func mustAccount(t *testing.T, id string) (*Account, *Bundle, string) {
	t.Helper()
	a, b, code, err := NewAccount(id, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	return a, b, code
}

func TestAccountUnlock(t *testing.T) {
	a, b, code := mustAccount(t, uid)
	if len(strings.ReplaceAll(code, "-", "")) != 32 {
		t.Fatalf("recovery code %q", code)
	}
	// The bundle survives a JSON round trip (it is stored by the server).
	raw, _ := json.Marshal(b)
	var b2 Bundle
	if err := json.Unmarshal(raw, &b2); err != nil {
		t.Fatal(err)
	}
	for name, unlock := range map[string]func() (*Account, error){
		"passphrase": func() (*Account, error) { return Unlock(&b2, "correct horse battery staple") },
		"recovery":   func() (*Account, error) { return UnlockWithRecoveryCode(&b2, strings.ToLower(code)) },
	} {
		got, err := unlock()
		if err != nil || !bytes.Equal(got.MK, a.MK) || got.Fingerprint() != a.Fingerprint() {
			t.Fatalf("%s unlock: %v", name, err)
		}
	}
	if _, err := Unlock(&b2, "wrong passphrase!!"); !errors.Is(err, ErrWrongSecret) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if _, _, _, err := NewAccount(uid, "short"); err == nil {
		t.Fatal("short passphrase accepted")
	}
	// Changing the passphrase keeps the same keys and the recovery code.
	if err := a.ChangePassphrase(&b2, "a whole new passphrase"); err != nil {
		t.Fatal(err)
	}
	if _, err := Unlock(&b2, "correct horse battery staple"); err == nil {
		t.Fatal("old passphrase still works")
	}
	if got, err := Unlock(&b2, "a whole new passphrase"); err != nil || got.Fingerprint() != a.Fingerprint() {
		t.Fatal("new passphrase does not unlock the same keys")
	}
	if _, err := UnlockWithRecoveryCode(&b2, code); err != nil {
		t.Fatal("recovery code lost by passphrase change")
	}
}

func TestBundleTamperingDetected(t *testing.T) {
	_, b, _ := mustAccount(t, uid)
	_, other, _ := mustAccount(t, uid)
	// A server swapping in someone else's public keys is caught on unlock.
	swapped := *b
	swapped.Pub = other.Pub
	if _, err := Unlock(&swapped, "correct horse battery staple"); err == nil {
		t.Fatal("unlock accepted mismatched public keys")
	}
	// A bundle moved to another user ID does not open (IDs are bound in AADs).
	moved := *b
	moved.UserID = strings.Repeat("f", 32)
	if _, err := Unlock(&moved, "correct horse battery staple"); err == nil {
		t.Fatal("bundle opened under a different user ID")
	}
	// Self-signatures bind keys to the user.
	if _, err := VerifyPublicKeys(uid, b.Pub, b.SelfSig); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPublicKeys(uid, other.Pub, b.SelfSig); err == nil {
		t.Fatal("self-signature verified for different keys")
	}
}

func TestRecoveryCodes(t *testing.T) {
	for range 50 {
		b := random(20)
		s := FormatRecoveryCode(b)
		got, err := ParseRecoveryCode(strings.ToLower(strings.ReplaceAll(s, "0", "o")))
		if err != nil || !bytes.Equal(got, b) {
			t.Fatalf("round trip %q: %v", s, err)
		}
	}
	for _, bad := range []string{"", "ABC", strings.Repeat("U", 32), strings.Repeat("A", 33)} {
		if _, err := ParseRecoveryCode(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestSpacesAndGrants(t *testing.T) {
	alice, _, _ := mustAccount(t, uid)
	bob, _, _ := mustAccount(t, strings.Repeat("b", 32))
	mallory, _, _ := mustAccount(t, strings.Repeat("c", 32))
	spaceID := strings.Repeat("1", 32)
	team := OpenSpace(spaceID, NewTeamSecret())

	grant, sig, err := team.Grant(alice, bob.Public())
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenGrant(bob, alice.Public(), spaceID, grant, sig)
	if err != nil || !bytes.Equal(got.Secret, team.Secret) {
		t.Fatalf("open grant: %v", err)
	}
	// Anyone can seal to Bob's key; only a signature makes a grant trustworthy.
	forged, _, _ := OpenSpace(spaceID, NewTeamSecret()).Grant(mallory, bob.Public())
	if _, err := OpenGrant(bob, alice.Public(), spaceID, forged, sig); err == nil {
		t.Fatal("forged grant accepted")
	}
	// A grant for another space or member does not open.
	if _, err := OpenGrant(bob, alice.Public(), strings.Repeat("2", 32), grant, sig); err == nil {
		t.Fatal("grant opened for the wrong space")
	}

	root := NewNodeKey()
	rootID := strings.Repeat("3", 32)
	w := team.WrapRoot(rootID, root)
	if k, err := got.UnwrapRoot(rootID, w); err != nil || !bytes.Equal(k.Raw(), root.Raw()) {
		t.Fatal("root key round trip")
	}
	name := team.EncryptName("Family Photos")
	if n, err := got.DecryptName(name); err != nil || n != "Family Photos" {
		t.Fatalf("team name: %q %v", n, err)
	}
	pubSig := SignSpaceKey(alice, spaceID, team.PublicKey())
	if _, err := VerifySpaceKey(alice.Public(), spaceID, B64(team.PublicKey()), pubSig); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySpaceKey(mallory.Public(), spaceID, B64(team.PublicKey()), pubSig); err == nil {
		t.Fatal("space key verified against the wrong creator")
	}
}

func TestNodeHierarchy(t *testing.T) {
	parent, child := NewNodeKey(), NewNodeKey()
	a, b := strings.Repeat("a", 32), strings.Repeat("b", 32)
	w := parent.WrapChild(a, child)
	if k, err := parent.UnwrapChild(a, w); err != nil || !bytes.Equal(k.Raw(), child.Raw()) {
		t.Fatal("unwrap")
	}
	if _, err := parent.UnwrapChild(b, w); err == nil {
		t.Fatal("wrapped key accepted for a different node")
	}
	enc := parent.EncryptName(a, "Résumé.pdf")
	if n, err := parent.DecryptName(a, enc); err != nil || n != "Résumé.pdf" {
		t.Fatalf("name: %q %v", n, err)
	}
	if _, err := parent.DecryptName(b, enc); err == nil {
		t.Fatal("name accepted for a different node")
	}
	if len(enc) != len(parent.EncryptName(a, "x")) {
		t.Error("short names should pad to the same length")
	}
	if parent.NameHash("Report.PDF") != parent.NameHash("report.pdf") ||
		parent.NameHash("é") != parent.NameHash("é") ||
		parent.NameHash("a") == NewNodeKey().NameHash("a") {
		t.Fatal("name hashes must be case-insensitive, normalized and keyed per folder")
	}
}

type fixture struct {
	alice  *Account
	space  *Space
	nk     *NodeKey
	plain  []byte
	ct     []byte
	prefix *Prefix
}

func newFixture(t *testing.T, size int) *fixture {
	t.Helper()
	alice, _, _ := mustAccount(t, uid)
	space := alice.PersonalSpace(strings.Repeat("5", 32))
	nk := NewNodeKey()
	plain := make([]byte, size)
	rand.Read(plain)
	r, total, err := NewWriter(bytes.NewReader(plain), WriteParams{
		Size: int64(size), NodeKey: nk, SpaceID: space.ID, SpacePub: space.Priv.PublicKey(),
		Meta: Meta{Name: "holiday.mp4", Type: "video/mp4", MTime: 1700000000000}, Signer: alice,
	})
	if err != nil {
		t.Fatal(err)
	}
	ct, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(ct)) != total {
		t.Fatalf("container is %d bytes, writer promised %d", len(ct), total)
	}
	p, err := ParsePrefix(bytes.NewReader(ct))
	if err != nil {
		t.Fatal(err)
	}
	if p.TotalSize() != total {
		t.Fatalf("TotalSize %d != %d", p.TotalSize(), total)
	}
	return &fixture{alice, space, nk, plain, ct, p}
}

func (f *fixture) decrypt(ct []byte, nk *NodeKey) ([]byte, error) {
	p, err := ParsePrefix(bytes.NewReader(ct))
	if err != nil {
		return nil, err
	}
	k, err := p.Keys(nk)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	src := bytes.NewReader(ct[p.BodyOffset():])
	err = DecryptVerify(src, &out, p, k, f.alice.Public())
	return out.Bytes(), err
}

func TestContainerRoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, ChunkSize - 1, ChunkSize, ChunkSize + 1, 3*ChunkSize + 7} {
		f := newFixture(t, size)
		got, err := f.decrypt(f.ct, f.nk)
		if err != nil || !bytes.Equal(got, f.plain) {
			t.Fatalf("size %d: %v", size, err)
		}
		// Random access.
		k, _ := f.prefix.Keys(f.nk)
		r := NewReader(bytes.NewReader(f.ct), f.prefix, k)
		if size > 10 {
			r.Seek(int64(size-10), io.SeekStart)
			tail, err := io.ReadAll(r)
			if err != nil || !bytes.Equal(tail, f.plain[size-10:]) {
				t.Fatalf("seek: %v", err)
			}
		}
		m, err := f.prefix.DecryptMeta(k)
		if err != nil || m.Name != "holiday.mp4" {
			t.Fatalf("meta: %v", err)
		}
	}
}

// The core promise: one container plus the owner's key material, and
// nothing else, gives back the file.
func TestIndependentRestore(t *testing.T) {
	f := newFixture(t, 2*ChunkSize+5)
	_, bundle, code := mustAccount(t, uid)
	_ = bundle
	// Re-derive everything from scratch, as an offline tool would.
	again, err := UnlockWithRecoveryCode(mustReBundle(t, f.alice, code), code)
	if err != nil {
		t.Fatal(err)
	}
	space := again.PersonalSpace(f.space.ID)
	p, _ := ParsePrefix(bytes.NewReader(f.ct))
	nk, err := p.OwnerNodeKey(space)
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.decrypt(f.ct, nk)
	if err != nil || !bytes.Equal(got, f.plain) {
		t.Fatalf("restore: %v", err)
	}
	// Another space's keys cannot open it.
	if _, err := p.OwnerNodeKey(OpenSpace(f.space.ID, NewTeamSecret())); err == nil {
		t.Fatal("owner seal opened with the wrong space secret")
	}
}

// mustReBundle builds a bundle for an existing account with a known recovery code.
func mustReBundle(t *testing.T, a *Account, code string) *Bundle {
	t.Helper()
	raw, err := ParseRecoveryCode(code)
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := json.Marshal(map[string]string{"enc": B64(a.Enc.Bytes()), "sig": B64(a.Sig.Seed())})
	pub := a.Public()
	return &Bundle{V: 1, UserID: a.UserID,
		Pub:     PublicKeys{Enc: B64(pub.Enc.Bytes()), Sig: B64(pub.Sig)},
		Private: B64(gcmSeal(kdf(a.MK, nil, "mk/private-keys"), priv, join("private-keys", a.UserID))),
		Unlock:  []Unlocker{recoveryUnlocker(a.UserID, raw, a.MK)},
	}
}

func TestContainerTampering(t *testing.T) {
	f := newFixture(t, 3*ChunkSize)
	body := int(f.prefix.BodyOffset())
	chunk := ChunkSize + tagSize
	flip := func(i int) []byte { c := bytes.Clone(f.ct); c[i] ^= 1; return c }
	swapped := bytes.Clone(f.ct)
	copy(swapped[body:body+chunk], f.ct[body+chunk:body+2*chunk])
	copy(swapped[body+chunk:body+2*chunk], f.ct[body:body+chunk])

	cases := map[string][]byte{
		"body bit flip":   flip(body + 100),
		"swapped chunks":  swapped,
		"truncated":       f.ct[:len(f.ct)-TrailerSize-chunk],
		"signature flip":  flip(len(f.ct) - 1),
		"trailing data":   append(bytes.Clone(f.ct), 0),
		"missing trailer": f.ct[:len(f.ct)-TrailerSize],
	}
	for name, ct := range cases {
		if _, err := f.decrypt(ct, f.nk); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A different node key fails the key commitment before any decryption.
	if _, err := f.prefix.Keys(NewNodeKey()); !errors.Is(err, ErrAuth) {
		t.Errorf("wrong node key: %v", err)
	}
	// Re-signing by someone else does not pass as the original signer.
	mallory, _, _ := mustAccount(t, strings.Repeat("c", 32))
	k, _ := f.prefix.Keys(f.nk)
	err := DecryptVerify(bytes.NewReader(f.ct[body:]), io.Discard, f.prefix, k, mallory.Public())
	if err == nil {
		t.Error("verified against the wrong signer")
	}
	// Header changes (e.g. altered size) break parsing, commitment or signature.
	for _, bad := range [][]byte{[]byte("NOTMAGIC"), f.ct[:11]} {
		if _, err := ParsePrefix(bytes.NewReader(bad)); err == nil {
			t.Error("malformed prefix accepted")
		}
	}
}

func TestSharesLinksTrash(t *testing.T) {
	alice, _, _ := mustAccount(t, uid)
	bob, _, _ := mustAccount(t, strings.Repeat("b", 32))
	mallory, _, _ := mustAccount(t, strings.Repeat("c", 32))
	nk := NewNodeKey()
	shareID, nodeID := strings.Repeat("d", 32), strings.Repeat("e", 32)

	sealed, sig, _ := ShareNode(alice, bob.Public(), shareID, nodeID, "write", "Projects", nk)
	k, name, err := OpenShare(bob, alice.Public(), shareID, nodeID, "write", sealed, sig)
	if err != nil || name != "Projects" || !bytes.Equal(k.Raw(), nk.Raw()) {
		t.Fatalf("share: %v", err)
	}
	if _, _, err := OpenShare(bob, alice.Public(), shareID, nodeID, "read", sealed, sig); err == nil {
		t.Fatal("permission is bound into the signature")
	}
	if _, _, err := OpenShare(bob, mallory.Public(), shareID, nodeID, "write", sealed, sig); err == nil {
		t.Fatal("share accepted from the wrong sharer")
	}

	secret := NewLinkSecret()
	lk := LinkKey(secret, shareID, nodeID, "Projects", nk)
	if k, n, err := OpenLinkKey(secret, shareID, nodeID, lk); err != nil || n != "Projects" || !bytes.Equal(k.Raw(), nk.Raw()) {
		t.Fatalf("link: %v", err)
	}
	if _, _, err := OpenLinkKey(NewLinkSecret(), shareID, nodeID, lk); err == nil {
		t.Fatal("link opened with the wrong secret")
	}

	space := alice.PersonalSpace(strings.Repeat("5", 32))
	tk, tsig, _ := TrashKey(bob, space.Priv.PublicKey(), nodeID, "old.txt", "file", nk)
	k, kn, err := OpenTrashKey(space, bob.Public(), nodeID, tk, tsig)
	if err != nil || kn.Name != "old.txt" || kn.Kind != "file" || !bytes.Equal(k.Raw(), nk.Raw()) {
		t.Fatalf("trash: %v", err)
	}
	if _, _, err := OpenTrashKey(space, mallory.Public(), nodeID, tk, tsig); err == nil {
		t.Fatal("trash key accepted from the wrong trasher")
	}
}

func TestValidateName(t *testing.T) {
	for _, ok := range []string{"a", "Résumé.pdf", ".bashrc"} {
		if ValidateName(ok) != nil {
			t.Errorf("rejected %q", ok)
		}
	}
	for _, bad := range []string{"", ".", "..", "a/b", "a\\b", " x", "x ", "a\x00b", "evil\u202efdp.exe", strings.Repeat("a", 256)} {
		if ValidateName(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestContacts(t *testing.T) {
	alice, _, _, _ := NewAccount(strings.Repeat("a", 32), "alice passphrase!")
	bob, _, _, _ := NewAccount(strings.Repeat("b", 32), "bob passphrase!!")
	list := &Contacts{V: 1, Contacts: map[string]Contact{
		bob.UserID: {FP: bob.Fingerprint(), Name: "Bob", Email: "bob@example.test", VerifiedAt: 1700000000000},
	}}
	sealed, err := alice.SealContacts(list)
	if err != nil {
		t.Fatal(err)
	}
	got, err := alice.OpenContacts(sealed)
	if err != nil || got.Contacts[bob.UserID].FP != bob.Fingerprint() {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	// Bound to its owner: another account cannot open it, and the server
	// cannot hand Alice's list to Bob or alter it.
	if _, err := bob.OpenContacts(sealed); err == nil {
		t.Fatal("another user opened the contact list")
	}
	raw, _ := UnB64(sealed)
	raw[len(raw)/2] ^= 1
	if _, err := alice.OpenContacts(B64(raw)); err == nil {
		t.Fatal("tampered contact list accepted")
	}
	for name, bad := range map[string]*Contacts{
		"version":     {V: 2, Contacts: map[string]Contact{}},
		"nil map":     {V: 1},
		"bad user id": {V: 1, Contacts: map[string]Contact{"__proto__": {FP: bob.Fingerprint(), VerifiedAt: 1}}},
		"bad fp":      {V: 1, Contacts: map[string]Contact{bob.UserID: {FP: "zz", VerifiedAt: 1}}},
		"no time":     {V: 1, Contacts: map[string]Contact{bob.UserID: {FP: bob.Fingerprint()}}},
	} {
		if _, err := alice.SealContacts(bad); err == nil {
			t.Errorf("%s: sealed", name)
		}
	}
}

// A Verifier fed by a random-access Reader verifies the signature when the
// file is read in order, and cannot be satisfied any other way.
func TestStreamingVerifier(t *testing.T) {
	for _, size := range []int{0, 10, ChunkSize, 2*ChunkSize + 7} {
		f := newFixture(t, size)
		k, _ := f.prefix.Keys(f.nk)
		trailer := f.ct[len(f.ct)-TrailerSize:]
		read := func(seekFirst bool) (*Verifier, []byte) {
			v, err := f.prefix.NewVerifier(f.alice.Public())
			if err != nil {
				t.Fatal(err)
			}
			r := NewReader(bytes.NewReader(f.ct), f.prefix, k)
			r.OnChunk = func(i int64, ct []byte) { v.Chunk(i, ct) }
			if seekFirst && size > ChunkSize {
				r.Read(make([]byte, 1))           // chunk 0 ...
				r.Seek(2*ChunkSize, io.SeekStart) // ... then skip chunk 1
			}
			out, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			return v, out
		}
		v, out := read(false)
		if !bytes.Equal(out, f.plain) || !v.Complete() || v.Finish(trailer) != nil {
			t.Fatalf("size %d: in-order read did not verify", size)
		}
		bad := bytes.Clone(trailer)
		bad[10] ^= 1
		if v.Finish(bad) == nil {
			t.Fatalf("size %d: forged signature accepted", size)
		}
		if size > ChunkSize {
			v, _ = read(true)
			if v.Complete() || v.Finish(trailer) == nil {
				t.Fatalf("size %d: a read that skipped a chunk claimed verification", size)
			}
		}
	}
	f := newFixture(t, 10)
	mallory, _, _ := mustAccount(t, strings.Repeat("c", 32))
	if _, err := f.prefix.NewVerifier(mallory.Public()); err == nil {
		t.Fatal("verifier accepted a signer the header does not name")
	}
}

func TestDigest(t *testing.T) {
	for _, size := range []int{0, 1, ChunkSize - 1, ChunkSize, ChunkSize + 1, 3*ChunkSize + 5} {
		f := newFixture(t, size)
		d := f.prefix.NewDigester()
		// Feed it in awkward pieces, as a network body arrives.
		for rest, step := f.ct, 1; len(rest) > 0; step = step*3 + 1 {
			k := min(step, len(rest))
			if _, err := d.Write(rest[:k]); err != nil {
				t.Fatalf("size %d: %v", size, err)
			}
			rest = rest[k:]
		}
		dg, err := d.Digest()
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if !bytes.Equal(dg.Header, f.ct[:f.prefix.BodyOffset()]) || !bytes.Equal(dg.Trailer, f.ct[len(f.ct)-TrailerSize:]) {
			t.Fatalf("size %d: header or trailer not captured", size)
		}
		if err := f.prefix.VerifyDigest(f.alice.Public(), dg.BodyHash, dg.Trailer); err != nil {
			t.Fatalf("size %d: genuine digest rejected: %v", size, err)
		}
		// The body hash must be the one the full read verifies.
		k, _ := f.prefix.Keys(f.nk)
		v, _ := f.prefix.NewVerifier(f.alice.Public())
		r := NewReader(bytes.NewReader(f.ct), f.prefix, k)
		r.OnChunk = func(i int64, ct []byte) { v.Chunk(i, ct) }
		if _, err := io.ReadAll(r); err != nil || !bytes.Equal(v.bh.Sum(nil), dg.BodyHash) {
			t.Fatalf("size %d: digester and verifier disagree", size)
		}
	}

	f := newFixture(t, 2*ChunkSize+3)
	d := f.prefix.NewDigester()
	d.Write(f.ct)
	dg, _ := d.Digest()
	// A server cannot pass off a wrong body hash or trailer ...
	for i, mut := range []func(bh, tr []byte){
		func(bh, _ []byte) { bh[0] ^= 1 },
		func(_, tr []byte) { tr[20] ^= 1 },
		func(_, tr []byte) { tr[0] = 'X' },
	} {
		bh, tr := bytes.Clone(dg.BodyHash), bytes.Clone(dg.Trailer)
		mut(bh, tr)
		if f.prefix.VerifyDigest(f.alice.Public(), bh, tr) == nil {
			t.Fatalf("tampering %d accepted", i)
		}
	}
	if f.prefix.VerifyDigest(f.alice.Public(), dg.BodyHash[:31], dg.Trailer) == nil {
		t.Fatal("short body hash accepted")
	}
	// ... or another header (here: a different size claim) ...
	other := bytes.Replace(f.ct[:f.prefix.BodyOffset()], []byte(`"size":131075`), []byte(`"size":131076`), 1)
	if bytes.Equal(other, f.ct[:f.prefix.BodyOffset()]) {
		t.Fatal("test did not alter the header")
	}
	op, err := ParsePrefix(bytes.NewReader(other))
	if err != nil {
		t.Fatal(err)
	}
	if op.VerifyDigest(f.alice.Public(), dg.BodyHash, dg.Trailer) == nil {
		t.Fatal("signature transferred to an altered header")
	}
	// ... or name someone else as the author.
	mallory, _, _ := mustAccount(t, strings.Repeat("c", 32))
	if f.prefix.VerifyDigest(mallory.Public(), dg.BodyHash, dg.Trailer) == nil {
		t.Fatal("digest verified against a signer the header does not name")
	}
	// Incomplete or overlong input is refused.
	short := f.prefix.NewDigester()
	short.Write(f.ct[:len(f.ct)-1])
	if _, err := short.Digest(); err == nil {
		t.Fatal("digest of a truncated container")
	}
	long := f.prefix.NewDigester()
	long.Write(f.ct)
	long.Write([]byte{0})
	if _, err := long.Digest(); err == nil {
		t.Fatal("digester accepted trailing data")
	}
}

func TestThumbnails(t *testing.T) {
	f := newFixture(t, 100)
	k, _ := f.prefix.Keys(f.nk)
	node := strings.Repeat("e", 32)
	img := []byte("\xff\xd8\xff pretend jpeg")
	enc, sig, err := SealThumb(f.alice, node, f.prefix, k, img, "image/jpeg", 256, 171)
	if err != nil {
		t.Fatal(err)
	}
	th, got, err := OpenThumb(f.alice.Public(), node, f.prefix, k, enc, sig)
	if err != nil || !bytes.Equal(got, img) || th.W != 256 || th.Type != "image/jpeg" {
		t.Fatalf("open: %v", err)
	}
	// Bound to the node, to the version (salt), and to its maker.
	if _, _, err := OpenThumb(f.alice.Public(), strings.Repeat("f", 32), f.prefix, k, enc, sig); err == nil {
		t.Fatal("thumbnail moved to another node")
	}
	other := newFixture(t, 100)
	ok, _ := other.prefix.Keys(other.nk)
	if _, _, err := OpenThumb(other.alice.Public(), node, other.prefix, ok, enc, sig); err == nil {
		t.Fatal("thumbnail moved to another version")
	}
	mallory, _, _ := mustAccount(t, strings.Repeat("c", 32))
	if _, _, err := OpenThumb(mallory.Public(), node, f.prefix, k, enc, sig); err == nil {
		t.Fatal("thumbnail attributed to someone who did not sign it")
	}
	// The display rule: the version's author, or the viewer; nobody else.
	// "Author" means verified author: without that, only your own counts.
	alice := f.alice.Public()
	if !ThumbAuthorOK(alice, alice, "viewer") || ThumbAuthorOK(alice, mallory.Public(), "viewer") ||
		!ThumbAuthorOK(alice, mallory.Public(), mallory.UserID) || ThumbAuthorOK(nil, alice, "viewer") ||
		!ThumbAuthorOK(nil, mallory.Public(), mallory.UserID) {
		t.Fatal("display rule wrong")
	}
	// Shape limits.
	for _, bad := range []struct {
		typ  string
		w, h int
		n    int
	}{{"image/png", 10, 10, 10}, {"image/svg+xml", 10, 10, 10}, {"image/jpeg", 0, 10, 10}, {"image/jpeg", 10, 600, 10}, {"image/jpeg", 10, 10, MaxThumbBytes + 1}} {
		if _, _, err := SealThumb(f.alice, node, f.prefix, k, make([]byte, bad.n), bad.typ, bad.w, bad.h); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}
