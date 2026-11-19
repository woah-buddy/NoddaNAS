package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"github.com/woah-buddy/NoddaNAS/internal/domain"
)

// BlobLister is implemented by blob stores that can enumerate their keys.
type BlobLister interface {
	Keys(ctx context.Context, fn func(key string) error) error
}

// StorageProblem identifies a stored file version that failed verification.
type StorageProblem struct {
	NodeID, VersionID, SpaceID string
}

// StorageReport is the result of OperatorVerifyStorage.
type StorageReport struct {
	Versions  int64 // file versions recorded in the database
	Bytes     int64 // their total (encrypted) size
	Hashed    bool  // whether contents were re-hashed, not just sized
	Missing   []StorageProblem
	WrongSize []StorageProblem
	WrongHash []StorageProblem
	Orphans   int64 // blobs no version refers to (-1: not checked)
}

// OK reports whether every recorded version is present and intact.
func (r *StorageReport) OK() bool {
	return len(r.Missing) == 0 && len(r.WrongSize) == 0 && len(r.WrongHash) == 0
}

// OperatorVerifyStorage checks, for every file version the database
// records, that its encrypted container exists in blob storage with the
// recorded size and (with hash) the recorded SHA-256 of the ciphertext.
//
// It decrypts nothing and needs no keys: integrity of an encrypted backup
// can be proven by the administrator, while confidentiality stays with the
// users. Use it after restoring a backup, before letting users back in.
func (s *Service) OperatorVerifyStorage(ctx context.Context, hash bool) (*StorageReport, error) {
	r := &StorageReport{Hashed: hash}
	known := map[string]struct{}{}
	const page = 500
	after := ""
	for {
		vs, err := s.store.ListVersionBlobs(ctx, after, page)
		if err != nil {
			return nil, err
		}
		for _, v := range vs {
			known[v.BlobKey] = struct{}{}
			r.Versions++
			r.Bytes += v.Size
			if err := s.verifyBlob(ctx, v, hash, r); err != nil {
				return nil, err
			}
		}
		if len(vs) < page {
			break
		}
		after = vs[len(vs)-1].BlobKey
	}
	r.Orphans = -1
	if l, ok := s.blobs.(BlobLister); ok {
		r.Orphans = 0
		if err := l.Keys(ctx, func(k string) error {
			if _, ok := known[k]; !ok {
				r.Orphans++
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	s.log.InfoContext(ctx, "audit", "event", "operator.storage.verify", "actor", "cli", "versions", r.Versions,
		"hashed", hash, "missing", len(r.Missing), "wrong_size", len(r.WrongSize), "wrong_hash", len(r.WrongHash), "orphans", r.Orphans)
	return r, nil
}

func (s *Service) verifyBlob(ctx context.Context, v *domain.Version, hash bool, r *StorageReport) error {
	p := StorageProblem{NodeID: v.NodeID, VersionID: v.ID, SpaceID: v.SpaceID}
	f, err := s.blobs.Open(ctx, v.BlobKey)
	if errors.Is(err, domain.ErrNotFound) {
		r.Missing = append(r.Missing, p)
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	var n int64
	h := sha256.New()
	if hash {
		n, err = io.Copy(h, f)
	} else {
		n, err = f.Seek(0, io.SeekEnd)
	}
	if err != nil {
		return err
	}
	switch {
	case n != v.Size:
		r.WrongSize = append(r.WrongSize, p)
	case hash && hex.EncodeToString(h.Sum(nil)) != v.SHA256:
		r.WrongHash = append(r.WrongHash, p)
	}
	return nil
}
