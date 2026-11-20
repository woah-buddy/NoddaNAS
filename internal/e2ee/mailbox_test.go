package e2ee

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestMailboxDropAndFile(t *testing.T) {
	alice, _, _ := mustAccount(t, uid)
	space := alice.PersonalSpace(strings.Repeat("5", 32))
	folder := NewNodeKey()
	boxID, dropID := strings.Repeat("a", 32), strings.Repeat("d", 32)
	box, err := NewMailbox(boxID)
	if err != nil {
		t.Fatal(err)
	}
	pub := box.Public()

	// The private key is wrapped under the folder key, bound to the mailbox.
	wrapped := box.Wrap(folder)
	if got, err := OpenMailbox(boxID, folder, wrapped); err != nil || !bytes.Equal(got.Public(), pub) {
		t.Fatalf("unwrap: %v", err)
	}
	if _, err := OpenMailbox(strings.Repeat("b", 32), folder, wrapped); err == nil {
		t.Fatal("mailbox key moved to another mailbox")
	}
	if _, err := OpenMailbox(boxID, NewNodeKey(), wrapped); err == nil {
		t.Fatal("mailbox key opened without the folder key")
	}
	// The description opens with the public key (the link), nothing else.
	info := must[string](t)(SealMailboxInfo(boxID, pub, MailboxInfo{Title: "Tax documents ✓", Owner: "Alice"}))
	if got, err := OpenMailboxInfo(boxID, pub, info); err != nil || got.Title != "Tax documents ✓" || got.Owner != "Alice" {
		t.Fatalf("info: %v", err)
	}
	other := must[*Mailbox](t)(NewMailbox(boxID))
	if _, err := OpenMailboxInfo(boxID, other.Public(), info); err == nil {
		t.Fatal("info opened with another key")
	}

	for _, size := range []int{0, 5, ChunkSize, 2*ChunkSize + 9} {
		plain := bytes.Repeat([]byte("x"), size)
		note := &DropNote{Name: "Bob", Email: "bob@example.test", Message: "Here are my receipts"}
		h, body, bodySize, err := NewDrop(bytes.NewReader(plain), boxID, dropID, pub, int64(size), Meta{Name: "receipts.pdf", Type: "application/pdf", MTime: 7}, note)
		if err != nil {
			t.Fatal(err)
		}
		ct, _ := io.ReadAll(body)
		if int64(len(ct)) != bodySize || bodySize != BodySize(int64(size)) {
			t.Fatalf("size %d: body %d bytes, want %d", size, len(ct), bodySize)
		}
		raw, _ := jsonMarshal(h)
		ph, err := ParseDropHeader(raw)
		if err != nil {
			t.Fatalf("size %d: header: %v", size, err)
		}
		// What the server computes at upload.
		dg := NewBodyDigester(ph.Size)
		dg.Write(ct)
		digest, err := dg.Digest()
		if err != nil {
			t.Fatalf("size %d: digest: %v", size, err)
		}

		// Only the mailbox's key opens it.
		if _, err := other.OpenDrop(ph); err == nil {
			t.Fatal("drop opened with another mailbox key")
		}
		d, err := box.OpenDrop(ph)
		if err != nil || d.Meta.Name != "receipts.pdf" || d.Note == nil || d.Note.Message != "Here are my receipts" {
			t.Fatalf("open: %v", err)
		}
		got, err := io.ReadAll(d.Body(bytes.NewReader(ct)))
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("size %d: review read: %v", size, err)
		}

		// Filing: a normal container around the unchanged body, signed by
		// the filer, that anyone with the file's key reads and verifies.
		prefix, err := d.FilePrefix(space.ID, space.Priv.PublicKey(), alice)
		if err != nil {
			t.Fatal(err)
		}
		container := append(append(bytes.Clone(prefix), ct...), FileTrailer(alice, prefix, digest.BodyHash)...)
		p, err := ParsePrefix(bytes.NewReader(container))
		if err != nil || p.TotalSize() != int64(len(container)) {
			t.Fatalf("filed container: %v", err)
		}
		k, err := p.Keys(d.NK)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := DecryptVerify(bytes.NewReader(container[p.BodyOffset():]), &out, p, k, alice.Public()); err != nil || !bytes.Equal(out.Bytes(), plain) {
			t.Fatalf("size %d: filed container does not verify: %v", size, err)
		}
		meta := must[*Meta](t)(p.DecryptMeta(k))
		if meta.Name != "receipts.pdf" || meta.From == nil || meta.From.Email != "bob@example.test" {
			t.Fatalf("meta %+v", meta)
		}
		// Restorable from the container alone, as every container is.
		if nk, err := p.OwnerNodeKey(space); err != nil || !bytes.Equal(nk.Raw(), d.NK.Raw()) {
			t.Fatalf("owner seal: %v", err)
		}
	}

	// A drop is bound to its mailbox and its own ID.
	h, _, _, _ := NewDrop(strings.NewReader("hi"), boxID, dropID, pub, 2, Meta{Name: "a"}, nil)
	moved := *h
	moved.ID = strings.Repeat("e", 32)
	if _, err := box.OpenDrop(&moved); err == nil {
		t.Fatal("drop key moved to another drop")
	}
	bad := *h
	bad.Commit = B64(make([]byte, 32))
	if _, err := box.OpenDrop(&bad); err == nil {
		t.Fatal("wrong key commitment accepted")
	}
	// The server's shape checks.
	for name, raw := range map[string]string{
		"unknown field": `{"v":1,"id":"` + dropID + `","size":1,"salt":"","commit":"","key":"","meta":"","x":1}`,
		"not json":      `{`,
		"bad id":        `{"v":1,"id":"../x","size":1}`,
	} {
		if _, err := ParseDropHeader([]byte(raw)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, _, _, err := NewDrop(strings.NewReader(""), boxID, dropID, pub, 0, Meta{}, &DropNote{Message: strings.Repeat("m", MaxDropNote+1)}); err == nil {
		t.Fatal("overlong note accepted")
	}
}

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

func must[T any](t *testing.T) func(T, error) T {
	return func(v T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}
