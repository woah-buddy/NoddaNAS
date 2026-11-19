package blobcrypt

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"
)

func testKeyring(t *testing.T, ids ...string) *Keyring {
	t.Helper()
	var lines []string
	for _, id := range ids {
		l, err := GenerateKeyLine(id)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, l)
	}
	k, err := ParseKeyring([]byte("# test keyring\n" + strings.Join(lines, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func encrypt(t *testing.T, plain, dek []byte) []byte {
	t.Helper()
	r, err := NewEncryptReader(bytes.NewReader(plain), dek)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(ct)) != CiphertextSize(int64(len(plain))) {
		t.Fatalf("ciphertext size %d, want %d", len(ct), CiphertextSize(int64(len(plain))))
	}
	return ct
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func TestRoundTripSizes(t *testing.T) {
	dek := randBytes(KeySize)
	for _, n := range []int{0, 1, ChunkSize - 1, ChunkSize, ChunkSize + 1, 3*ChunkSize + 17} {
		plain := randBytes(n)
		ct := encrypt(t, plain, dek)
		r, err := NewReader(bytes.NewReader(ct), dek, int64(n))
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("size %d: %v", n, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("size %d: plaintext mismatch", n)
		}
	}
}

func TestSeek(t *testing.T) {
	dek := randBytes(KeySize)
	plain := randBytes(5*ChunkSize + 123)
	r, _ := NewReader(bytes.NewReader(encrypt(t, plain, dek)), dek, int64(len(plain)))
	for _, off := range []int64{0, 1, ChunkSize - 1, ChunkSize, 3*ChunkSize + 5, int64(len(plain)) - 1} {
		if _, err := r.Seek(off, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 100)
		n, err := io.ReadFull(r, buf)
		if err != nil && err != io.ErrUnexpectedEOF {
			t.Fatalf("off %d: %v", off, err)
		}
		if !bytes.Equal(buf[:n], plain[off:off+int64(n)]) {
			t.Fatalf("off %d: mismatch", off)
		}
	}
}

func TestTamperingIsDetected(t *testing.T) {
	dek := randBytes(KeySize)
	plain := randBytes(3 * ChunkSize)
	ct := encrypt(t, plain, dek)
	size := int64(len(plain))
	chunkCT := ChunkSize + tagSize

	cases := map[string]struct {
		ct   []byte
		size int64
		key  []byte
	}{
		"bit flip":       {flip(ct, int(headerLen)+10), size, dek},
		"bad header":     {flip(ct, 0), size, dek},
		"truncated":      {ct[:int(headerLen)+2*chunkCT], size, dek},
		"drop last only": {ct[:int(headerLen)+2*chunkCT], 2 * ChunkSize, dek}, // claims a shorter file
		"swapped chunks": {swap(ct, int(headerLen), int(headerLen)+chunkCT, chunkCT), size, dek},
		"wrong key":      {ct, size, randBytes(KeySize)},
	}
	for name, c := range cases {
		r, _ := NewReader(bytes.NewReader(c.ct), c.key, c.size)
		_, err := io.ReadAll(r)
		if !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: got %v, want ErrCorrupt", name, err)
		}
	}
}

func TestEmptyFileIsAuthenticated(t *testing.T) {
	dek := randBytes(KeySize)
	ct := encrypt(t, nil, dek)
	r, _ := NewReader(bytes.NewReader(flip(ct, len(ct)-1)), dek, 0)
	if _, err := io.ReadAll(r); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("got %v, want ErrCorrupt", err)
	}
}

func TestKeyringWrapAndRotate(t *testing.T) {
	k1, _ := GenerateKeyLine("k1")
	k2, _ := GenerateKeyLine("k2")
	old, err := ParseKeyring([]byte(k1))
	if err != nil {
		t.Fatal(err)
	}
	dek, wrapped, err := old.NewDataKey("blob-a")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := old.Unwrap(wrapped, "blob-a"); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unwrap: %v", err)
	}
	if _, err := old.Unwrap(wrapped, "blob-b"); err == nil {
		t.Fatal("unwrap with a different binding must fail")
	}

	// Rotation: k2 becomes primary; k1 stays for unwrapping existing keys.
	rotated, err := ParseKeyring([]byte(k2 + "\n" + k1))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := rotated.Unwrap(wrapped, "blob-a"); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("old key no longer unwraps after rotation: %v", err)
	}
	if !rotated.NeedsRewrap(wrapped) {
		t.Fatal("key wrapped under k1 should need rewrap")
	}
	_, fresh, _ := rotated.NewDataKey("blob-c")
	if rotated.NeedsRewrap(fresh) || !strings.HasPrefix(fresh, "v1.k2.") {
		t.Fatalf("new keys must use the primary KEK, got %q", fresh[:6])
	}
	if _, err := old.Unwrap(fresh, "blob-c"); err == nil {
		t.Fatal("a keyring without k2 must not unwrap k2 keys")
	}
}

func TestParseKeyringRejectsBadInput(t *testing.T) {
	for _, in := range []string{
		"",
		"# only comments",
		"BAD:" + strings.Repeat("A", 44),
		"k1:not-base64",
		"k1:AAAA",
	} {
		if _, err := ParseKeyring([]byte(in)); err == nil {
			t.Errorf("ParseKeyring(%q) succeeded, want error", in)
		}
	}
	l, _ := GenerateKeyLine("k1")
	if _, err := ParseKeyring([]byte(l + "\n" + l)); err == nil {
		t.Error("duplicate key ids must be rejected")
	}
}

func flip(b []byte, i int) []byte {
	c := bytes.Clone(b)
	c[i] ^= 0x01
	return c
}

func swap(b []byte, i, j, n int) []byte {
	c := bytes.Clone(b)
	copy(c[i:i+n], b[j:j+n])
	copy(c[j:j+n], b[i:i+n])
	return c
}
