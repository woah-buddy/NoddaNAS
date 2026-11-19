package fsblob

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/woah-buddy/NoddaNAS/internal/domain"
)

const key = "0123456789abcdef0123456789abcdef"

func TestRoundTripAndNoClobber(t *testing.T) {
	ctx := context.Background()
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if n, err := s.Create(ctx, key, strings.NewReader("ciphertext")); err != nil || n != 10 {
		t.Fatalf("create: %d %v", n, err)
	}
	if _, err := s.Create(ctx, key, strings.NewReader("other")); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second create = %v, want conflict", err)
	}
	f, err := s.Open(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(f)
	f.Close()
	if string(got) != "ciphertext" {
		t.Fatalf("read %q", got)
	}
	if err := s.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open(ctx, key); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("open after delete = %v", err)
	}
	if err := s.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "../../etc/passwd", "0123456789ABCDEF0123456789ABCDEF", key + "/x"} {
		if _, err := s.Open(ctx, bad); err == nil {
			t.Errorf("key %q accepted", bad)
		}
	}
}

// Even if something inside the data directory pointed outside it (a symlink
// planted by another process), the store refuses to follow it.
func TestConfinedToDataDirectory(t *testing.T) {
	ctx := context.Background()
	dir, outside := t.TempDir(), t.TempDir()
	secret := filepath.Join(outside, "secret")
	os.WriteFile(secret, []byte("not yours"), 0o600)
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, blobsDir, key[0:2], key[2:4])
	os.MkdirAll(link, 0o700)
	if err := os.Symlink(secret, filepath.Join(link, key)); err != nil {
		t.Fatal(err)
	}
	if f, err := s.Open(ctx, key); err == nil {
		got, _ := io.ReadAll(f)
		f.Close()
		t.Fatalf("followed a symlink out of the data directory: %q", got)
	}
	// A symlinked shard directory is refused for writes too.
	other := "fedcba9876543210fedcba9876543210"
	os.Symlink(outside, filepath.Join(dir, blobsDir, other[0:2]))
	if _, err := s.Create(ctx, other, bytes.NewReader([]byte("x"))); err == nil {
		t.Fatal("wrote through a symlink out of the data directory")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 1 {
		t.Fatalf("outside directory changed: %v", entries)
	}
}
