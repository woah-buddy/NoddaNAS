package blobcrypt

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Stream format (version 1):
//
//	header  = "NDNSBLB1"                         (8 bytes)
//	chunk_i = AES-256-GCM(DEK, nonce_i, plaintext_i) (plaintext ≤ 64 KiB, +16-byte tag)
//	nonce_i = uint88_be(i) || last_flag          (12 bytes; last_flag = 1 only on the final chunk)
//
// This is the STREAM construction (Hoang, Reyhanitabar, Rogaway, Vizár 2015),
// the same one used by age and Tink. Putting the chunk index in the nonce
// stops chunks being reordered; the last-chunk flag stops truncation; a fresh
// random DEK per blob means a (key, nonce) pair is never reused. Fixed-size
// chunks let a reader seek straight to any offset, which HTTP Range requests
// (video scrubbing, resumable downloads) need.

const (
	ChunkSize = 64 * 1024
	tagSize   = 16
	magic     = "NDNSBLB1"
	headerLen = int64(len(magic))
)

// ErrCorrupt means ciphertext failed authentication: it was modified,
// truncated, or does not belong to this key.
var ErrCorrupt = errors.New("blobcrypt: content failed authentication")

// CiphertextSize returns the stored size of a blob with the given plaintext size.
func CiphertextSize(plain int64) int64 {
	return headerLen + plain + chunks(plain)*tagSize
}

func chunks(plain int64) int64 {
	if plain == 0 {
		return 1
	}
	return (plain + ChunkSize - 1) / ChunkSize
}

func nonce(i int64, last bool) []byte {
	var n [12]byte
	// 88-bit counter: the top 3 bytes stay zero for any realistic file size.
	binary.BigEndian.PutUint64(n[3:11], uint64(i))
	if last {
		n[11] = 1
	}
	return n[:]
}

// encryptReader turns a plaintext reader into a ciphertext reader.
type encryptReader struct {
	src     io.Reader
	aead    cipher.AEAD
	plain   []byte
	out     []byte // pending ciphertext
	next    int64  // next chunk index
	peeked  []byte // one byte read ahead to detect the final chunk
	done    bool
	started bool
}

// NewEncryptReader returns a reader that yields the encrypted form of src
// under dek.
func NewEncryptReader(src io.Reader, dek []byte) (io.Reader, error) {
	aead, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	return &encryptReader{src: src, aead: aead, plain: make([]byte, ChunkSize)}, nil
}

func (e *encryptReader) Read(p []byte) (int, error) {
	if !e.started {
		e.started = true
		e.out = append(e.out[:0], magic...)
	}
	for len(e.out) == 0 {
		if e.done {
			return 0, io.EOF
		}
		if err := e.sealNext(); err != nil {
			return 0, err
		}
	}
	n := copy(p, e.out)
	e.out = e.out[n:]
	return n, nil
}

func (e *encryptReader) sealNext() error {
	// Fill one chunk, starting with any byte we read ahead last time.
	n := copy(e.plain, e.peeked)
	e.peeked = e.peeked[:0]
	m, err := io.ReadFull(e.src, e.plain[n:])
	n += m
	last := false
	switch {
	case err == io.EOF || err == io.ErrUnexpectedEOF:
		last = true
	case err != nil:
		return err
	default:
		// Full chunk: read one byte ahead to learn whether more follows.
		var b [1]byte
		k, perr := io.ReadFull(e.src, b[:])
		switch {
		case perr == io.EOF:
			last = true
		case perr != nil:
			return perr
		default:
			e.peeked = append(e.peeked, b[:k]...)
		}
	}
	e.out = e.aead.Seal(e.out[:0], nonce(e.next, last), e.plain[:n], nil)
	e.next++
	e.done = last
	return nil
}

// Reader decrypts a blob with random access. It implements io.ReadSeeker
// over the plaintext, so it can be passed straight to http.ServeContent.
type Reader struct {
	src     io.ReadSeeker
	aead    cipher.AEAD
	size    int64 // plaintext size, from trusted metadata
	nchunks int64
	off     int64 // plaintext offset
	srcPos  int64 // current ciphertext offset in src, -1 if unknown
	buf     []byte
	chunk   []byte // decrypted current chunk
	cur     int64  // index of chunk held in `chunk`, -1 if none
	checked bool
}

// NewReader returns a decrypting reader. size is the plaintext size recorded
// in the metadata store; because the final chunk is flagged, a blob that was
// truncated or extended will fail authentication rather than read short.
func NewReader(src io.ReadSeeker, dek []byte, size int64) (*Reader, error) {
	if size < 0 {
		return nil, errors.New("blobcrypt: negative size")
	}
	aead, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	return &Reader{
		src: src, aead: aead, size: size, nchunks: chunks(size),
		srcPos: -1, cur: -1, buf: make([]byte, ChunkSize+tagSize),
	}, nil
}

func (r *Reader) Read(p []byte) (int, error) {
	if r.off >= r.size {
		if r.size == 0 && !r.checked {
			// Authenticate the single empty chunk so an empty file is still verified.
			if err := r.load(0); err != nil {
				return 0, err
			}
		}
		return 0, io.EOF
	}
	idx := r.off / ChunkSize
	if idx != r.cur {
		if err := r.load(idx); err != nil {
			return 0, err
		}
	}
	n := copy(p, r.chunk[r.off-idx*ChunkSize:])
	r.off += int64(n)
	return n, nil
}

func (r *Reader) load(idx int64) error {
	if !r.checked {
		if err := r.seekSrc(0); err != nil {
			return err
		}
		var h [headerLen]byte
		if _, err := io.ReadFull(r.src, h[:]); err != nil {
			return fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		r.srcPos = headerLen
		if string(h[:]) != magic {
			return ErrCorrupt
		}
		r.checked = true
	}
	plainLen := min(int64(ChunkSize), r.size-idx*ChunkSize)
	ctOff := headerLen + idx*(ChunkSize+tagSize)
	if err := r.seekSrc(ctOff); err != nil {
		return err
	}
	ct := r.buf[:plainLen+tagSize]
	if _, err := io.ReadFull(r.src, ct); err != nil {
		r.srcPos = -1
		return fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	r.srcPos = ctOff + int64(len(ct))
	pt, err := r.aead.Open(r.chunk[:0], nonce(idx, idx == r.nchunks-1), ct, nil)
	if err != nil {
		r.cur = -1
		return ErrCorrupt
	}
	r.chunk, r.cur = pt, idx
	return nil
}

func (r *Reader) seekSrc(off int64) error {
	if r.srcPos == off {
		return nil
	}
	if _, err := r.src.Seek(off, io.SeekStart); err != nil {
		r.srcPos = -1
		return err
	}
	r.srcPos = off
	return nil
}

// Seek implements io.Seeker over plaintext offsets.
func (r *Reader) Seek(offset int64, whence int) (int64, error) {
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = r.off + offset
	case io.SeekEnd:
		abs = r.size + offset
	default:
		return 0, errors.New("blobcrypt: invalid whence")
	}
	if abs < 0 {
		return 0, errors.New("blobcrypt: negative position")
	}
	r.off = abs
	return abs, nil
}
