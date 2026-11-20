package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/woah-buddy/FrontDir/internal/e2ee"
)

// Reading files without downloading them whole.
//
// A RemoteFile reads one version of a file's container from the server
// with HTTP range requests, only the parts a reader asks for, and decrypts
// them with random access. It is what the local WebDAV gateway uses, so
// that opening a 20 GB video to watch the first minute fetches about a
// minute of it.
//
// Every request names the version it started with, so a new upload while
// the file is open cannot mix two versions (they have different keys, so
// it would fail anyway, but loudly rather than with a clear error).

// ErrSignature means a file read to its end did not carry a valid signature
// from the user its header names. Its contents must not be trusted.
var ErrSignature = errors.New("the file's signature does not verify")

// RemoteFile is one version of a file, opened for random-access reading.
type RemoteFile struct {
	c       *Client
	nodeID  string
	Version string // the version being read
	total   int64  // container bytes
	Prefix  *e2ee.Prefix
	Meta    *e2ee.Meta
	keys    *e2ee.FileKeys
	Signer  *e2ee.PublicUser

	mu    sync.Mutex
	start int64  // window position in the container
	win   []byte // cached ciphertext window

	record, recordSig string // the version record served with the first fetch (§5c)
}

const (
	seqWindow    = 4 << 20   // read-ahead when reading sequentially
	randomWindow = 256 << 10 // fetch size after a jump
)

// OpenRemote opens a file's current version: it fetches the header (and the
// first part of the body), checks the key commitment against the key the
// folder hierarchy gives, decrypts the metadata and looks up the signer.
func (c *Client) OpenRemote(ctx context.Context, nodeID string) (*RemoteFile, error) {
	nk, err := c.cachedKey(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	rf := &RemoteFile{c: c, nodeID: nodeID}
	first := int64(12 + e2ee.MaxHeaderLen + seqWindow)
	if err := rf.fetch(ctx, 0, first); err != nil {
		return nil, err
	}
	p, err := e2ee.ParsePrefix(bytes.NewReader(rf.win))
	if err != nil {
		return nil, err
	}
	if p.TotalSize() != rf.total {
		return nil, e2ee.ErrMalformed // the server's length disagrees with the header
	}
	if rf.keys, err = p.Keys(nk); err != nil { // key commitment: this container belongs to this node
		return nil, err
	}
	if rf.Meta, err = p.DecryptMeta(rf.keys); err != nil {
		return nil, err
	}
	if rf.Signer, err = c.UserKeys(ctx, p.Signer.User); err != nil {
		return nil, err
	}
	// Not older than, or different from, what this client saw (§5c).
	if err := c.checkServedRecord(ctx, nodeID, p, rf.record, rf.recordSig); err != nil {
		return nil, err
	}
	rf.Prefix = p
	return rf, nil
}

// Size is the plaintext size.
func (rf *RemoteFile) Size() int64 { return rf.Prefix.Size }

// fetch loads container bytes [off, off+n) (clipped to the end) into the
// window. The first fetch learns the version and total size; later ones
// are pinned to that version and must agree with both.
func (rf *RemoteFile) fetch(ctx context.Context, off, n int64) error {
	path := "/api/v1/nodes/" + url.PathEscape(rf.nodeID) + "/content"
	if rf.Version != "" {
		path += "?version=" + url.QueryEscape(rf.Version)
		n = min(n, rf.total-off)
	}
	if n <= 0 {
		return io.ErrUnexpectedEOF
	}
	resp, err := rf.c.do(ctx, "GET", path, nil, map[string]string{"Range": fmt.Sprintf("bytes=%d-%d", off, off+n-1)}, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	ver := resp.Header.Get("X-FrontDir-Version")
	if rf.Version == "" {
		rf.Version = ver
		rf.record, rf.recordSig = resp.Header.Get("X-FrontDir-Record"), resp.Header.Get("X-FrontDir-Record-Sig")
	} else if ver != rf.Version {
		return errors.New("the server returned a different version of the file")
	}
	var start, total int64
	switch resp.StatusCode {
	case http.StatusPartialContent:
		if start, total, err = contentRange(resp.Header.Get("Content-Range")); err != nil {
			return err
		}
	case http.StatusOK: // a server that ignores Range sends everything from 0
		total = resp.ContentLength
	default:
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	if rf.total == 0 {
		rf.total = total
	}
	if total != rf.total || start > off {
		return errors.New("the server returned an inconsistent range")
	}
	if _, err := io.CopyN(io.Discard, resp.Body, off-start); err != nil {
		return err
	}
	buf := make([]byte, min(n, total-off))
	if _, err := io.ReadFull(resp.Body, buf); err != nil {
		return err
	}
	rf.start, rf.win = off, buf
	return nil
}

func contentRange(h string) (start, total int64, err error) {
	// "bytes START-END/TOTAL"
	spec, ok := strings.CutPrefix(h, "bytes ")
	rng, tot, ok2 := strings.Cut(spec, "/")
	s, _, ok3 := strings.Cut(rng, "-")
	if !ok || !ok2 || !ok3 {
		return 0, 0, errors.New("malformed Content-Range")
	}
	if start, err = strconv.ParseInt(s, 10, 64); err != nil {
		return 0, 0, errors.New("malformed Content-Range")
	}
	if total, err = strconv.ParseInt(tot, 10, 64); err != nil {
		return 0, 0, errors.New("malformed Content-Range")
	}
	return start, total, nil
}

// readAt reads container bytes, from the window or the server.
func (rf *RemoteFile) readAt(ctx context.Context, b []byte, off int64) (int, error) {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	if off >= rf.total {
		return 0, io.EOF
	}
	if off < rf.start || off >= rf.start+int64(len(rf.win)) {
		size := int64(randomWindow)
		if off == rf.start+int64(len(rf.win)) {
			size = seqWindow // reading on from where the window ended
		}
		if err := rf.fetch(ctx, off, max(size, int64(len(b)))); err != nil {
			return 0, err
		}
	}
	return copy(b, rf.win[off-rf.start:]), nil
}

// Reader returns a plaintext reader over the file. Each chunk it releases
// was authenticated by AES-GCM under the file's committed key. If the file
// is read in order up to its end, the author's signature is checked before
// the final chunk is released, and a failure is reported as ErrSignature
// instead of those bytes: a copy of a forged file never completes, however
// the copier detects the end (EOF, or a known length). Verified reports
// whether that check ran and passed.
func (rf *RemoteFile) Reader(ctx context.Context) (*PlainReader, error) {
	v, err := rf.Prefix.NewVerifier(rf.Signer)
	if err != nil {
		return nil, err
	}
	src := &containerSeeker{rf: rf, ctx: ctx}
	r := e2ee.NewReader(src, rf.Prefix, rf.keys)
	r.OnChunk = func(i int64, ct []byte) { v.Chunk(i, ct) }
	return &PlainReader{rf: rf, ctx: ctx, r: r, v: v}, nil
}

// PlainReader is a seekable plaintext view of a RemoteFile.
type PlainReader struct {
	rf       *RemoteFile
	ctx      context.Context
	r        *e2ee.Reader
	v        *e2ee.Verifier
	pos      int64
	verified bool
	err      error
}

// Verified reports whether the file was read in order to its end and its
// signature verified.
func (p *PlainReader) Verified() bool { return p.verified }

func (p *PlainReader) Read(b []byte) (int, error) {
	if p.err != nil {
		return 0, p.err
	}
	n, err := p.r.Read(b)
	p.pos += int64(n)
	if p.pos >= p.rf.Size() && !p.verified && p.v.Complete() {
		// Every chunk, the last included, has been seen in order: check the
		// signature now, before handing out the last bytes.
		tr := make([]byte, e2ee.TrailerSize)
		if _, terr := p.rf.readAt(p.ctx, tr, p.rf.total-e2ee.TrailerSize); terr != nil {
			p.err = terr
			return 0, terr
		}
		if verr := p.v.Finish(tr); verr != nil {
			p.err = ErrSignature
			return 0, p.err
		}
		p.verified = true
	}
	if err != nil && !errors.Is(err, io.EOF) {
		p.err = err
	}
	return n, err
}

// Seek moves within the plaintext.
func (p *PlainReader) Seek(off int64, whence int) (int64, error) {
	n, err := p.r.Seek(off, whence)
	if err == nil {
		p.pos = n
	}
	return n, err
}

// containerSeeker adapts RemoteFile to the io.ReadSeeker e2ee.Reader wants.
type containerSeeker struct {
	rf  *RemoteFile
	ctx context.Context
	off int64
}

func (s *containerSeeker) Read(b []byte) (int, error) {
	n, err := s.rf.readAt(s.ctx, b, s.off)
	s.off += int64(n)
	return n, err
}

func (s *containerSeeker) Seek(off int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		off += s.off
	case io.SeekEnd:
		off += s.rf.total
	}
	if off < 0 {
		return 0, errors.New("negative position")
	}
	s.off = off
	return off, nil
}
