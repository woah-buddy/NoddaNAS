package e2ee

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// containerBy makes a small container signed by acct and returns its prefix.
func containerBy(t *testing.T, acct *Account) *Prefix {
	t.Helper()
	r, _, err := NewWriter(strings.NewReader("hello"), WriteParams{Size: 5, NodeKey: NewNodeKey(),
		SpaceID: strings.Repeat("5", 32), SpacePub: acct.PersonalSpace(strings.Repeat("5", 32)).Priv.PublicKey(),
		Meta: Meta{Name: "a.txt"}, Signer: acct})
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := io.ReadAll(r)
	p, err := ParsePrefix(bytes.NewReader(ct))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type historyFixture struct {
	node       string
	alice, bob *Account
	users      map[string]*PublicUser
	entries    []HistoryEntry // newest first
}

func (f *historyFixture) signerFor(id string) (*PublicUser, error) {
	if u, ok := f.users[id]; ok {
		return u, nil
	}
	return nil, errors.New("no such user")
}

func (f *historyFixture) clone() []HistoryEntry {
	out := make([]HistoryEntry, len(f.entries))
	copy(out, f.entries)
	return out
}

// newHistory builds: alice saves v1, bob saves v2, bob restores v1 (v3).
func newHistory(t *testing.T) *historyFixture {
	t.Helper()
	alice, _, _ := mustAccount(t, uid)
	bob, _, _ := mustAccount(t, strings.Repeat("b", 32))
	f := &historyFixture{node: strings.Repeat("e", 32), alice: alice, bob: bob,
		users: map[string]*PublicUser{alice.UserID: alice.Public(), bob.UserID: bob.Public()}}
	p1, p2 := containerBy(t, alice), containerBy(t, bob)
	mk := func(by *Account, p *Prefix, kind string, prev *SignedRecord) *SignedRecord {
		rec := VersionRecord{Node: f.node, Seq: 1, Container: B64(p.Hash()), Kind: kind, At: 1700000000000}
		if prev != nil {
			rec.Seq, rec.Prev = prev.Seq+1, B64(prev.Hash())
		}
		r, err := SignRecord(by, rec)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	r1 := mk(alice, p1, KindSave, nil)
	r2 := mk(bob, p2, KindSave, r1)
	r3 := mk(bob, p1, KindRestore, r2)
	f.entries = []HistoryEntry{{Prefix: p1, Record: r3}, {Prefix: p2, Record: r2}, {Prefix: p1, Record: r1}}
	return f
}

func TestVersionHistory(t *testing.T) {
	f := newHistory(t)
	es := f.clone()
	head, err := VerifyHistory(f.node, es, f.signerFor)
	if err != nil || head != f.entries[0].Record {
		t.Fatalf("genuine history rejected: %v", err)
	}
	if es[0].StoredBy.ID != f.bob.UserID || es[2].StoredBy.ID != f.alice.UserID {
		t.Fatal("StoredBy not set")
	}
	// Versions from before records existed may sit below the signed ones.
	legacy := append(f.clone(), HistoryEntry{Prefix: containerBy(t, f.alice)})
	if _, err := VerifyHistory(f.node, legacy, f.signerFor); err != nil {
		t.Fatalf("legacy versions below the chain: %v", err)
	}
	// Old versions deleted as too old: the chain may start above 1, as
	// long as nothing older remains.
	if _, err := VerifyHistory(f.node, f.clone()[:2], f.signerFor); err != nil {
		t.Fatalf("pruned history: %v", err)
	}
	if _, err := VerifyHistory(f.node, append(f.clone()[:2], HistoryEntry{Prefix: containerBy(t, f.alice)}), f.signerFor); err == nil {
		t.Fatal("an unsigned version where a signed one must be")
	}

	other, _ := SignRecord(f.alice, VersionRecord{Node: strings.Repeat("d", 32), Seq: 2,
		Prev: f.entries[1].Record.Prev, Container: f.entries[1].Record.Container, Kind: KindSave, At: 1})
	forged := *f.entries[1].Record
	forged.Sig = bytes.Clone(forged.Sig)
	forged.Sig[0] ^= 1
	saveByOther, _ := SignRecord(f.alice, VersionRecord{Node: f.node, Seq: 2, Prev: f.entries[1].Record.Prev,
		Container: f.entries[1].Record.Container, Kind: KindSave, At: 1}) // bob's container, "saved" by alice
	cases := map[string]func(es []HistoryEntry) []HistoryEntry{
		"reordered":            func(es []HistoryEntry) []HistoryEntry { es[0], es[1] = es[1], es[0]; return es },
		"middle dropped":       func(es []HistoryEntry) []HistoryEntry { return []HistoryEntry{es[0], es[2]} },
		"unsigned in between":  func(es []HistoryEntry) []HistoryEntry { es[1].Record = nil; return es },
		"unsigned on top":      func(es []HistoryEntry) []HistoryEntry { return append([]HistoryEntry{{Prefix: es[1].Prefix}}, es...) },
		"other file's record":  func(es []HistoryEntry) []HistoryEntry { es[1].Record = other; return es },
		"wrong container":      func(es []HistoryEntry) []HistoryEntry { es[1].Prefix = es[0].Prefix; return es },
		"forged signature":     func(es []HistoryEntry) []HistoryEntry { es[1].Record = &forged; return es },
		"save by a non-author": func(es []HistoryEntry) []HistoryEntry { es[1].Record = saveByOther; return es },
		"record replaced":      func(es []HistoryEntry) []HistoryEntry { es[0].Record = es[1].Record; return es },
	}
	for name, mut := range cases {
		if _, err := VerifyHistory(f.node, mut(f.clone()), f.signerFor); !errors.Is(err, ErrHistory) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A signer the directory does not know.
	delete(f.users, f.bob.UserID)
	if _, err := VerifyHistory(f.node, f.clone(), f.signerFor); !errors.Is(err, ErrHistory) {
		t.Fatal("unknown signer accepted")
	}
}

func TestFreshness(t *testing.T) {
	f := newHistory(t)
	recs := []*SignedRecord{f.entries[0].Record, f.entries[1].Record, f.entries[2].Record} // seq 3, 2, 1
	at := func(i int) *Seen { s := SeenOf(recs[i]); return &s }

	if CheckFresh(nil, recs) != nil || CheckFresh(at(0), recs) != nil || CheckFresh(at(2), recs) != nil {
		t.Fatal("fresh history flagged")
	}
	if !errors.Is(CheckFresh(at(0), recs[1:]), ErrRolledBack) || !errors.Is(CheckFresh(at(0), nil), ErrRolledBack) {
		t.Fatal("rollback not detected")
	}
	// A different version 2 than the one seen: a fork.
	alt, _ := SignRecord(f.alice, VersionRecord{Node: f.node, Seq: 2, Prev: recs[1].Prev, Container: recs[1].Container, Kind: KindRestore, At: 2})
	if !errors.Is(CheckFresh(&Seen{Seq: 2, Hash: alt.Hash()}, recs), ErrForked) {
		t.Fatal("fork not detected")
	}
	// Seen version older than everything kept: nothing to compare.
	if CheckFresh(at(2), recs[:2]) != nil {
		t.Fatal("pruned history flagged")
	}

	type want struct {
		decided bool
		err     error
	}
	for name, c := range map[string]struct {
		seen *Seen
		head *SignedRecord
		want
	}{
		"nothing seen":     {nil, recs[0], want{true, nil}},
		"same":             {at(0), recs[0], want{true, nil}},
		"next":             {at(1), recs[0], want{true, nil}},
		"two ahead":        {at(2), recs[0], want{false, nil}},
		"older":            {at(0), recs[1], want{true, ErrRolledBack}},
		"none":             {at(0), nil, want{true, ErrRolledBack}},
		"same seq, differ": {&Seen{Seq: 2, Hash: alt.Hash()}, recs[1], want{true, ErrForked}},
		"next, not linked": {&Seen{Seq: 2, Hash: alt.Hash()}, recs[0], want{true, ErrForked}},
	} {
		d, err := CheckFreshHead(c.seen, c.head)
		if d != c.decided || !errors.Is(err, c.err) || (c.err == nil && err != nil) {
			t.Errorf("%s: decided %v, %v", name, d, err)
		}
	}
}

func TestParseRecord(t *testing.T) {
	f := newHistory(t)
	r := f.entries[1].Record
	if got, err := ParseRecord(r.Raw, r.Sig); err != nil || got.Seq != 2 || got.Verify(f.bob.Public()) != nil {
		t.Fatalf("round trip: %v", err)
	}
	if r.Verify(f.alice.Public()) == nil {
		t.Fatal("verified against the wrong user")
	}
	edit := func(fn func(m map[string]any)) []byte {
		var m map[string]any
		json.Unmarshal(r.Raw, &m)
		fn(m)
		b, _ := json.Marshal(m)
		return b
	}
	for name, raw := range map[string][]byte{
		"unknown field":   edit(func(m map[string]any) { m["extra"] = 1 }),
		"version":         edit(func(m map[string]any) { m["v"] = 2 }),
		"seq 1 with prev": edit(func(m map[string]any) { m["seq"] = 1 }),
		"seq 2 no prev":   edit(func(m map[string]any) { m["prev"] = "" }),
		"kind":            edit(func(m map[string]any) { m["kind"] = "copy" }),
		"node":            edit(func(m map[string]any) { m["node"] = "../x" }),
		"short container": edit(func(m map[string]any) { m["container"] = "AAAA" }),
		"huge seq":        edit(func(m map[string]any) { m["seq"] = 1 << 60 }),
		"trailing data":   append(bytes.Clone(r.Raw), []byte(` {}`)...),
		"not canonical":   append([]byte(" "), r.Raw...),
		"key case":        bytes.Replace(r.Raw, []byte(`"seq"`), []byte(`"SEQ"`), 1),
		"number format":   bytes.Replace(r.Raw, []byte(`"seq":2`), []byte(`"seq":2.0`), 1),
		"key order":       edit(func(m map[string]any) {}), // map keys marshal sorted
		"too long":        bytes.Repeat([]byte(" "), MaxRecordLen+1),
	} {
		if _, err := ParseRecord(raw, r.Sig); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := ParseRecord(r.Raw, r.Sig[:63]); err == nil {
		t.Error("short signature accepted")
	}
}
