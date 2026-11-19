// Package fsblob stores blobs on a local or shared POSIX filesystem (a
// Docker volume, a NAS mount, an NFS/CephFS share, a Kubernetes PVC).
//
// Blob keys are server-generated random IDs, never user input, and they are
// still validated before being turned into a path. Writes go to a temporary
// file first and are linked into place only once complete and fsynced, so a
// crash never leaves a half-written blob under a real key.
package fsblob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/woah-buddy/NoddaNAS/internal/domain"
	"github.com/woah-buddy/NoddaNAS/internal/validate"
)

// Store is a filesystem-backed blob store.
type Store struct {
	blobs string
	tmp   string
}

// New prepares root (which must be an absolute path) for use.
func New(root string) (*Store, error) {
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("fsblob: root %q must be an absolute path", root)
	}
	s := &Store{blobs: filepath.Join(root, "blobs"), tmp: filepath.Join(root, "tmp")}
	for _, d := range []string{s.blobs, s.tmp} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, fmt.Errorf("fsblob: %w", err)
		}
	}
	return s, nil
}

func (s *Store) path(key string) (string, error) {
	// Keys are 32 lowercase hex characters, so the resulting path can only
	// ever be blobs/xx/yy/<key>: no separators, no "..", no surprises.
	if err := validate.ID(key); err != nil {
		return "", fmt.Errorf("fsblob: invalid key")
	}
	return filepath.Join(s.blobs, key[0:2], key[2:4], key), nil
}

// Create writes r to a new blob. It fails if the key already exists.
func (s *Store) Create(ctx context.Context, key string, r io.Reader) (int64, error) {
	final, err := s.path(key)
	if err != nil {
		return 0, err
	}
	f, err := os.CreateTemp(s.tmp, "upload-*")
	if err != nil {
		return 0, err
	}
	tmpName := f.Name()
	defer os.Remove(tmpName) // no-op once linked into place

	n, err := io.Copy(f, ctxReader{ctx, r})
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return n, err
	}
	if err := os.MkdirAll(filepath.Dir(final), 0o700); err != nil {
		return n, err
	}
	// os.Link refuses to replace an existing file, which makes the write
	// no-clobber; fall back to rename on filesystems without hard links.
	if err := os.Link(tmpName, final); err != nil {
		if errors.Is(err, os.ErrExist) {
			return n, domain.E(domain.CodeConflict, "blob exists")
		}
		if _, statErr := os.Lstat(final); statErr == nil {
			return n, domain.E(domain.CodeConflict, "blob exists")
		}
		if err := os.Rename(tmpName, final); err != nil {
			return n, err
		}
	}
	syncDir(filepath.Dir(final))
	return n, nil
}

// Open returns the blob for reading.
func (s *Store) Open(_ context.Context, key string) (io.ReadSeekCloser, error) {
	p, err := s.path(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, domain.ErrNotFound
	}
	return f, err
}

// Delete removes a blob. Deleting a missing blob is not an error.
func (s *Store) Delete(_ context.Context, key string) error {
	p, err := s.path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Ping verifies the storage root is writable (used by readiness checks).
func (s *Store) Ping(context.Context) error {
	f, err := os.CreateTemp(s.tmp, "ping-*")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

// ctxReader stops a long copy promptly when the request is cancelled
// (e.g. the client disconnects mid-upload).
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}
