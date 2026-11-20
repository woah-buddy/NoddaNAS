package e2ee

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"hash"
)

// Version attribution (docs/E2EE.md §5b): knowing who wrote a version of a
// file without downloading it.
//
// A container's signature covers two things: a hash of its header and its
// body hash BH (the hash of the chunks' hashes). Checking it normally means
// reading the whole file to compute BH. But BH is not secret, and the
// server, which stores the ciphertext, can compute it once at upload. With
// the header, BH and the trailer, a client checks the signature in an
// instant, whatever the file's size.
//
// The server cannot use this to misattribute a version. Only the signer can
// make a signature over (header, BH), and a header belongs to exactly one
// container (it carries a fresh random salt), so the only BH that verifies
// is the one the signer computed over the chunks they encrypted. A server
// that lies about BH, the header or the trailer makes the check fail; it
// cannot make it name someone else. What the check does not prove is that
// the stored body still matches BH: reading the file proves that, as ever.

// Digest is what a signature check needs besides the signer's key.
type Digest struct {
	Header   []byte // the container's prefix: magic || length || header JSON
	BodyHash []byte // SHA-256 over the concatenated SHA-256 of each encrypted chunk
	Trailer  []byte // "SIG1" || Ed25519 signature
}

// Digester computes a container's Digest from its bytes as they stream past
// (all of them, prefix included). It needs no keys: the chunk boundaries
// follow from the header's plaintext size.
type Digester struct {
	p       *Prefix
	off     int64     // container bytes seen
	bh      hash.Hash // over chunk hashes
	ch      hash.Hash // over the current chunk
	inChunk int64     // bytes of the current chunk seen
	idx     int64
	trailer []byte
	over    bool // more bytes than the header allows
	// noTrailer: a drop body (§6a), which ends after its last chunk.
	noTrailer bool
}

// NewDigester starts a Digester for the container p was parsed from.
func (p *Prefix) NewDigester() *Digester {
	return &Digester{p: p, bh: sha256.New(), ch: sha256.New()}
}

// chunkLen is the encrypted length of chunk i.
func (p *Prefix) chunkLen(i int64) int64 {
	return min(int64(ChunkSize), p.Size-i*ChunkSize) + tagSize
}

// Write consumes the next container bytes. It never fails, so it can sit
// beside other writers in an io.MultiWriter; bytes beyond what the header
// allows make Digest fail instead.
func (d *Digester) Write(b []byte) (int, error) {
	n := len(b)
	bodyEnd := d.p.BodyOffset() + BodySize(d.p.Size)
	for len(b) > 0 {
		switch {
		case d.off < d.p.BodyOffset(): // the prefix: already parsed
			k := min(int64(len(b)), d.p.BodyOffset()-d.off)
			b, d.off = b[k:], d.off+k
		case d.off < bodyEnd:
			k := min(int64(len(b)), d.p.chunkLen(d.idx)-d.inChunk)
			d.ch.Write(b[:k])
			b, d.off, d.inChunk = b[k:], d.off+k, d.inChunk+k
			if d.inChunk == d.p.chunkLen(d.idx) {
				d.bh.Write(d.ch.Sum(nil))
				d.ch.Reset()
				d.idx++
				d.inChunk = 0
			}
		default:
			if d.noTrailer || len(d.trailer)+len(b) > TrailerSize {
				d.over = true
				return n, nil
			}
			d.trailer = append(d.trailer, b...)
			d.off += int64(len(b))
			b = nil
		}
	}
	return n, nil
}

// Digest returns the result once the whole container has been written.
func (d *Digester) Digest() (*Digest, error) {
	end := d.p.TotalSize()
	if d.noTrailer {
		end = d.p.BodyOffset() + BodySize(d.p.Size)
	}
	if d.over || d.off != end || d.idx != Chunks(d.p.Size) {
		return nil, ErrMalformed
	}
	return &Digest{Header: bytes.Clone(d.p.raw), BodyHash: d.bh.Sum(nil), Trailer: bytes.Clone(d.trailer)}, nil
}

// Raw returns the container's prefix bytes.
func (p *Prefix) Raw() []byte { return bytes.Clone(p.raw) }

// VerifyDigest checks that signer, whom the header must name (same user and
// key fingerprint), signed the container with this header and body hash.
// Callers check the key commitment (Keys) separately, which ties the header
// to the file the folder hierarchy says it belongs to.
func (p *Prefix) VerifyDigest(signer *PublicUser, bodyHash, trailer []byte) error {
	if signer.ID != p.Signer.User || signer.Finger != p.Signer.FP {
		return fmt.Errorf("e2ee: container claims signer %s, verifying against %s", p.Signer.User, signer.ID)
	}
	if len(bodyHash) != sha256.Size {
		return ErrAuth
	}
	return p.checkTrailer(signer, bodyHash, trailer)
}

// checkTrailer verifies the signature in trailer over the header and BH.
func (p *Prefix) checkTrailer(signer *PublicUser, bodyHash, trailer []byte) error {
	if len(trailer) != TrailerSize || string(trailer[:4]) != trailerMagic {
		return ErrAuth
	}
	msg := append(append(join("container"), 0), sum(p.raw)...)
	msg = append(msg, bodyHash...)
	return verify(signer.Sig, msg, trailer[4:])
}
