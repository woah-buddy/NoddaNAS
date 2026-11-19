package e2ee

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
)

// Container format constants (docs/E2EE.md §5).
const (
	Magic        = "NDNSE2E1"
	Alg          = "X25519+HKDF-SHA256+AES-256-GCM/STREAM-64K"
	ChunkSize    = 64 * 1024
	tagSize      = 16
	trailerMagic = "SIG1"
	TrailerSize  = 4 + ed25519.SignatureSize
	MaxHeaderLen = 64 * 1024
	// MaxSize bounds plaintext size so every size computation stays exact.
	MaxSize = 1 << 50
)

// Header is a container's JSON header.
type Header struct {
	V      int    `json:"v"`
	Alg    string `json:"alg"`
	Size   int64  `json:"size"`
	Salt   string `json:"salt"`
	Commit string `json:"commit"`
	Owner  struct {
		Space string `json:"space"`
		Key   string `json:"key"`
	} `json:"owner"`
	Meta   string `json:"meta"`
	Signer struct {
		User string `json:"user"`
		FP   string `json:"fp"`
	} `json:"signer"`
}

// Meta is a file's encrypted metadata.
type Meta struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	MTime int64  `json:"mtime"` // Unix milliseconds
}

// Chunks returns the number of chunks for a plaintext size.
func Chunks(size int64) int64 {
	if size == 0 {
		return 1
	}
	return (size + ChunkSize - 1) / ChunkSize
}

// BodySize returns the encrypted body size for a plaintext size.
func BodySize(size int64) int64 { return size + Chunks(size)*tagSize }

func chunkNonce(i int64, last bool) []byte {
	var n [12]byte
	binary.BigEndian.PutUint64(n[3:11], uint64(i)) // #nosec G115 -- i is a chunk index, never negative
	if last {
		n[11] = 1
	}
	return n[:]
}

// fileKeys are a container's content/meta/commit keys, derived from NK and salt.
type fileKeys struct {
	content, meta, commit []byte
}

func deriveFileKeys(nk *NodeKey, salt []byte) *fileKeys {
	return &fileKeys{
		content: kdf(nk.raw, salt, "file/content"),
		meta:    kdf(nk.raw, salt, "file/meta"),
		commit:  kdf(nk.raw, salt, "file/commit"),
	}
}

func ownerCtx(spaceID string) []byte { return join("file-owner", spaceID) }

// ---- writing -------------------------------------------------------------------

// WriteParams describe a container to produce.
type WriteParams struct {
	Size     int64           // exact plaintext size
	NodeKey  *NodeKey        // the file's node key
	SpaceID  string          // owning space
	SpacePub *ecdh.PublicKey // owning space's public key (for the independent-restore seal)
	Meta     Meta
	Signer   *Account
}

// NewWriter returns a reader that yields the complete container for src,
// which must supply exactly p.Size bytes. Memory use is constant.
func NewWriter(src io.Reader, p WriteParams) (io.Reader, int64, error) {
	if p.Size < 0 || p.Size > MaxSize {
		return nil, 0, errors.New("e2ee: invalid size")
	}
	salt := random(32)
	fk := deriveFileKeys(p.NodeKey, salt)
	ownerKey, err := Seal(p.SpacePub, p.NodeKey.raw, ownerCtx(p.SpaceID))
	if err != nil {
		return nil, 0, err
	}
	metaJSON, _ := json.Marshal(p.Meta)
	var h Header
	h.V, h.Alg, h.Size, h.Salt, h.Commit = 1, Alg, p.Size, B64(salt), B64(fk.commit)
	h.Owner.Space, h.Owner.Key = p.SpaceID, B64(ownerKey)
	h.Meta = B64(gcmSeal(fk.meta, metaJSON, join("file/meta")))
	h.Signer.User, h.Signer.FP = p.Signer.UserID, p.Signer.Fingerprint()
	hdr, _ := json.Marshal(h)
	if len(hdr) > MaxHeaderLen {
		return nil, 0, errors.New("e2ee: container header too large")
	}
	prefix := make([]byte, 0, 12+len(hdr))
	prefix = append(prefix, Magic...)
	prefix = binary.BigEndian.AppendUint32(prefix, uint32(len(hdr))) // #nosec G115 -- bounded by MaxHeaderLen above
	prefix = append(prefix, hdr...)
	total := int64(len(prefix)) + BodySize(p.Size) + TrailerSize
	return &writer{
		src: src, size: p.Size, n: Chunks(p.Size), aead: gcmFor(fk.content), signer: p.Signer,
		prefixHash: sum(prefix), bh: sha256.New(), out: prefix, buf: make([]byte, ChunkSize),
	}, total, nil
}

type writer struct {
	src        io.Reader
	size, read int64
	n, next    int64
	aead       cipher.AEAD
	signer     *Account
	prefixHash []byte
	bh         hash.Hash
	out        []byte
	buf        []byte
	done       bool
}

func (w *writer) Read(p []byte) (int, error) {
	for len(w.out) == 0 {
		if w.done {
			return 0, io.EOF
		}
		if err := w.fill(); err != nil {
			return 0, err
		}
	}
	n := copy(p, w.out)
	w.out = w.out[n:]
	return n, nil
}

func (w *writer) fill() error {
	if w.next == w.n {
		// All chunks written: the source must be exhausted, then sign.
		var b [1]byte
		if k, _ := io.ReadFull(w.src, b[:]); k != 0 {
			return errors.New("e2ee: source is longer than the declared size")
		}
		msg := append(append(join("container"), 0), w.prefixHash...)
		msg = append(msg, w.bh.Sum(nil)...)
		w.out = append([]byte(trailerMagic), sign(w.signer.Sig, msg)...)
		w.done = true
		return nil
	}
	want := min(int64(ChunkSize), w.size-w.read)
	if _, err := io.ReadFull(w.src, w.buf[:want]); err != nil {
		return fmt.Errorf("e2ee: source is shorter than the declared size: %w", err)
	}
	w.read += want
	ct := w.aead.Seal(nil, chunkNonce(w.next, w.next == w.n-1), w.buf[:want], nil)
	w.bh.Write(sum(ct))
	w.out = ct
	w.next++
	return nil
}

// ---- reading -------------------------------------------------------------------

// Prefix is a parsed container header.
type Prefix struct {
	Header
	HeaderLen int
	raw       []byte // magic || length || header
	salt      []byte
	commit    []byte
}

// BodyOffset is where the encrypted body starts.
func (p *Prefix) BodyOffset() int64 { return int64(len(p.raw)) }

// TotalSize is the exact size a well-formed container must have.
func (p *Prefix) TotalSize() int64 { return p.BodyOffset() + BodySize(p.Size) + TrailerSize }

// ErrMalformed means the bytes are not a valid container.
var ErrMalformed = errors.New("e2ee: malformed container")

// ParsePrefix reads and validates a container's magic and header. It needs
// no keys, which is why the server can use it to check uploads.
func ParsePrefix(r io.Reader) (*Prefix, error) {
	var head [12]byte
	if _, err := io.ReadFull(r, head[:]); err != nil || string(head[:8]) != Magic {
		return nil, ErrMalformed
	}
	hl := binary.BigEndian.Uint32(head[8:])
	if hl == 0 || hl > MaxHeaderLen {
		return nil, ErrMalformed
	}
	hdr := make([]byte, hl)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, ErrMalformed
	}
	p := &Prefix{HeaderLen: int(hl), raw: append(head[:], hdr...)}
	dec := json.NewDecoder(bytes.NewReader(hdr))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p.Header); err != nil {
		return nil, ErrMalformed
	}
	var err1, err2 error
	p.salt, err1 = UnB64(p.Salt)
	p.commit, err2 = UnB64(p.Commit)
	if p.V != 1 || p.Alg != Alg || p.Size < 0 || p.Size > MaxSize || err1 != nil || err2 != nil ||
		len(p.salt) != 32 || len(p.commit) != 32 || !isID(p.Owner.Space) {
		return nil, ErrMalformed
	}
	return p, nil
}

func isID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Keys derives the container's keys from a node key obtained through the
// folder hierarchy, and checks the key commitment.
func (p *Prefix) Keys(nk *NodeKey) (*FileKeys, error) {
	fk := deriveFileKeys(nk, p.salt)
	if subtle.ConstantTimeCompare(fk.commit, p.commit) != 1 {
		return nil, ErrAuth
	}
	return &FileKeys{fk: fk, nk: nk}, nil
}

// OwnerNodeKey recovers the file's node key from the owner seal, using the
// owning space's keys. This is the independent-restore path.
func (p *Prefix) OwnerNodeKey(s *Space) (*NodeKey, error) {
	if s.ID != p.Owner.Space {
		return nil, fmt.Errorf("e2ee: container belongs to space %s", p.Owner.Space)
	}
	sealed, err := UnB64(p.Owner.Key)
	if err != nil {
		return nil, ErrAuth
	}
	raw, err := Open(s.Priv, sealed, ownerCtx(s.ID))
	if err != nil {
		return nil, err
	}
	return nodeKeyFrom(raw)
}

// FileKeys are a container's verified keys.
type FileKeys struct {
	fk *fileKeys
	nk *NodeKey
}

// NodeKey returns the node key the keys were derived from.
func (k *FileKeys) NodeKey() *NodeKey { return k.nk }

// Meta decrypts the container's metadata.
func (p *Prefix) DecryptMeta(k *FileKeys) (*Meta, error) {
	pt, err := openB64(k.fk.meta, p.Meta, join("file/meta"))
	if err != nil {
		return nil, err
	}
	var m Meta
	if err := json.Unmarshal(pt, &m); err != nil {
		return nil, ErrAuth
	}
	return &m, nil
}

// Reader decrypts a container's body with random access.
type Reader struct {
	src     io.ReadSeeker // the whole container
	p       *Prefix
	aead    cipher.AEAD
	off     int64
	srcPos  int64
	buf     []byte
	chunk   []byte
	cur     int64
	checked bool

	// OnChunk, if set, receives each encrypted chunk after it decrypted
	// successfully (for a Verifier). ct is only valid during the call.
	OnChunk func(idx int64, ct []byte)
}

// NewReader returns a seekable plaintext reader. src holds the complete
// container (any position).
func NewReader(src io.ReadSeeker, p *Prefix, k *FileKeys) *Reader {
	return &Reader{src: src, p: p, aead: gcmFor(k.fk.content), srcPos: -1, cur: -1, buf: make([]byte, ChunkSize+tagSize)}
}

func (r *Reader) Read(b []byte) (int, error) {
	if r.off >= r.p.Size {
		if r.p.Size == 0 && !r.checked {
			if err := r.load(0); err != nil {
				return 0, err
			}
			r.checked = true
		}
		return 0, io.EOF
	}
	idx := r.off / ChunkSize
	if idx != r.cur {
		if err := r.load(idx); err != nil {
			return 0, err
		}
	}
	n := copy(b, r.chunk[r.off-idx*ChunkSize:])
	r.off += int64(n)
	return n, nil
}

func (r *Reader) load(idx int64) error {
	plain := min(int64(ChunkSize), r.p.Size-idx*ChunkSize)
	off := r.p.BodyOffset() + idx*(ChunkSize+tagSize)
	if r.srcPos != off {
		if _, err := r.src.Seek(off, io.SeekStart); err != nil {
			r.srcPos = -1
			return err
		}
	}
	ct := r.buf[:plain+tagSize]
	if _, err := io.ReadFull(r.src, ct); err != nil {
		r.srcPos = -1
		return ErrAuth
	}
	r.srcPos = off + int64(len(ct))
	pt, err := r.aead.Open(r.chunk[:0], chunkNonce(idx, idx == Chunks(r.p.Size)-1), ct, nil)
	if err != nil {
		r.cur = -1
		return ErrAuth
	}
	r.chunk, r.cur = pt, idx
	if r.OnChunk != nil {
		r.OnChunk(idx, ct)
	}
	return nil
}

// Seek implements io.Seeker over plaintext offsets.
func (r *Reader) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		offset += r.off
	case io.SeekEnd:
		offset += r.p.Size
	default:
		return 0, errors.New("e2ee: invalid whence")
	}
	if offset < 0 {
		return 0, errors.New("e2ee: negative position")
	}
	r.off = offset
	return offset, nil
}

// DecryptVerify reads a complete container sequentially from src (positioned
// just after the prefix), writes the plaintext to dst, and finally checks
// the signer's signature. Callers must discard dst's output on error.
func DecryptVerify(src io.Reader, dst io.Writer, p *Prefix, k *FileKeys, signer *PublicUser) error {
	v, err := p.NewVerifier(signer)
	if err != nil {
		return err
	}
	aead := gcmFor(k.fk.content)
	n := Chunks(p.Size)
	buf := make([]byte, ChunkSize+tagSize)
	for i := int64(0); i < n; i++ {
		plain := min(int64(ChunkSize), p.Size-i*ChunkSize)
		ct := buf[:plain+tagSize]
		if _, err := io.ReadFull(src, ct); err != nil {
			return ErrAuth
		}
		v.Chunk(i, ct)
		pt, err := aead.Open(nil, chunkNonce(i, i == n-1), ct, nil)
		if err != nil {
			return ErrAuth
		}
		if _, err := dst.Write(pt); err != nil {
			return err
		}
	}
	var tr [TrailerSize]byte
	if _, err := io.ReadFull(src, tr[:]); err != nil {
		return ErrAuth
	}
	if extra, _ := io.ReadFull(src, make([]byte, 1)); extra != 0 {
		return ErrMalformed
	}
	return v.Finish(tr[:])
}

// ---- verifying while streaming --------------------------------------------------

// Verifier checks a container's signature from its encrypted chunks as a
// reader hands them out, for readers that cannot hold a whole file before
// releasing plaintext (the local WebDAV gateway, streaming downloads).
//
// Each chunk is authenticated by AES-GCM before any of its plaintext is
// released, so nobody without the file's key (the server included) can
// change, reorder, drop or swap anything unnoticed. What the Verifier adds
// at the end is attribution: the signature of the user named in the header
// over every chunk. A reader that reaches the end must fail its last read
// if Finish fails, so a copy or download of a forged file never completes.
type Verifier struct {
	p      *Prefix
	signer *PublicUser
	bh     hash.Hash
	next   int64
}

// NewVerifier starts verifying the container against signer, who must be
// the user its header names.
func (p *Prefix) NewVerifier(signer *PublicUser) (*Verifier, error) {
	if signer.ID != p.Signer.User || signer.Finger != p.Signer.FP {
		return nil, fmt.Errorf("e2ee: container claims signer %s, verifying against %s", p.Signer.User, signer.ID)
	}
	return &Verifier{p: p, signer: signer, bh: sha256.New()}, nil
}

// Chunk records encrypted chunk idx. Chunks count only in order; anything
// else (a repeat after seeking back, a jump ahead) is ignored and returns
// false, after which Complete stays false.
func (v *Verifier) Chunk(idx int64, ct []byte) bool {
	if idx != v.next {
		return false
	}
	v.bh.Write(sum(ct))
	v.next++
	return true
}

// Complete reports whether every chunk has been recorded in order.
func (v *Verifier) Complete() bool { return v.next == Chunks(v.p.Size) }

// Finish checks the trailer: the container's last TrailerSize bytes.
func (v *Verifier) Finish(trailer []byte) error {
	if !v.Complete() {
		return errors.New("e2ee: cannot verify a container that was not read in order")
	}
	if len(trailer) != TrailerSize || string(trailer[:4]) != trailerMagic {
		return ErrAuth
	}
	msg := append(append(join("container"), 0), sum(v.p.raw)...)
	msg = append(msg, v.bh.Sum(nil)...)
	return verify(v.signer.Sig, msg, trailer[4:])
}
