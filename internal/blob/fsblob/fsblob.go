// Package fsblob stores blobs on a local or shared POSIX filesystem (a
// Docker volume, a NAS mount, an NFS/CephFS share, a Kubernetes PVC).
//
// Blob keys are server-generated random IDs, never user input, and they are
// still validated before being turned into a path. On top of that, every
// file operation goes through an os.Root opened on the data directory, so
// even a bug in key validation could not reach a file outside it (the
// kernel-level equivalent of a chroot for this one directory: "..", absolute
// paths and symlinks that point outside are all refused).
//
// Writes go to a temporary file first and are linked into place only once
// complete and fsynced, so a crash never leaves a half-written blob under a
// real key.
package fsblob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/woah-buddy/NoddaNAS/internal/domain"
	"github.com/woah-buddy/NoddaNAS/internal/secure"
	"github.com/woah-buddy/NoddaNAS/internal/validate"
)

// Store is a filesystem-backed blob store.
type Store struct {
	root *os.Root // the data directory; all paths below are relative to it
}

const (
	blobsDir = "blobs"
	tmpDir   = "tmp"
)

// New prepares dir (which must be an absolute path) for use.
func New(dir string) (*Store, error) {
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("fsblob: root %q must be an absolute path", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("fsblob: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("fsblob: %w", err)
	}
	for _, d := range []string{blobsDir, tmpDir} {
		if err := root.MkdirAll(d, 0o700); err != nil {
			_ = root.Close()
			return nil, fmt.Errorf("fsblob: %w", err)
		}
	}
	return &Store{root: root}, nil
}

func (s *Store) path(key string) (string, error) {
	// Keys are 32 lowercase hex characters, so the resulting path can only
	// ever be blobs/xx/yy/<key>: no separators, no "..", no surprises.
	if err := validate.ID(key); err != nil {
		return "", fmt.Errorf("fsblob: invalid key")
	}
	return filepath.Join(blobsDir, key[0:2], key[2:4], key), nil
}

// Create writes r to a new blob. It fails if the key already exists.
func (s *Store) Create(ctx context.Context, key string, r io.Reader) (int64, error) {
	final, err := s.path(key)
	if err != nil {
		return 0, err
	}
	tmpName := filepath.Join(tmpDir, "upload-"+secure.NewID())
	f, err := s.root.OpenFile(tmpName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	defer func() { _ = s.root.Remove(tmpName) }() // no-op once moved into place

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
	if err := s.root.MkdirAll(filepath.Dir(final), 0o700); err != nil {
		return n, err
	}
	// Link refuses to replace an existing file, which makes the write
	// no-clobber; fall back to rename on filesystems without hard links.
	if err := s.root.Link(tmpName, final); err != nil {
		if errors.Is(err, os.ErrExist) {
			return n, domain.E(domain.CodeConflict, "blob exists")
		}
		if _, statErr := s.root.Lstat(final); statErr == nil {
			return n, domain.E(domain.CodeConflict, "blob exists")
		}
		if err := s.root.Rename(tmpName, final); err != nil {
			return n, err
		}
	}
	s.syncDir(filepath.Dir(final))
	return n, nil
}

// Open returns the blob for reading.
func (s *Store) Open(_ context.Context, key string) (io.ReadSeekCloser, error) {
	p, err := s.path(key)
	if err != nil {
		return nil, err
	}
	f, err := s.root.Open(p)
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
	if err := s.root.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Ping verifies the storage root is writable (used by readiness checks).
func (s *Store) Ping(context.Context) error {
	name := filepath.Join(tmpDir, "ping-"+secure.NewID())
	f, err := s.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		_ = s.root.Remove(name)
		return err
	}
	return s.root.Remove(name)
}

// syncDir makes a directory entry durable. Best effort: not every
// filesystem supports fsync on directories.
func (s *Store) syncDir(dir string) {
	if d, err := s.root.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
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
