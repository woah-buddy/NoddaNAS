package davgw

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"io/fs"
	"mime"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/webdav"

	"github.com/woah-buddy/FrontDir/internal/client"
)

// ---- file info -----------------------------------------------------------------------

type fileInfo struct {
	name  string
	size  int64
	dir   bool
	mod   time.Time
	ro    bool
	etag  string
	ctype string
}

func (i *fileInfo) Name() string       { return i.name }
func (i *fileInfo) Size() int64        { return i.size }
func (i *fileInfo) ModTime() time.Time { return i.mod }
func (i *fileInfo) IsDir() bool        { return i.dir }
func (i *fileInfo) Sys() any           { return nil }
func (i *fileInfo) Mode() fs.FileMode {
	m := fs.FileMode(0o644)
	if i.dir {
		m = fs.ModeDir | 0o755
	}
	if i.ro {
		m &^= 0o222
	}
	return m
}

// ContentType answers from the name, so listings never fetch file bytes.
func (i *fileInfo) ContentType(context.Context) (string, error) {
	if i.ctype != "" {
		return i.ctype, nil
	}
	if t := mime.TypeByExtension(path.Ext(i.name)); t != "" {
		return t, nil
	}
	return "application/octet-stream", nil
}

// ETag is the stored container's hash: it changes with every version.
func (i *fileInfo) ETag(context.Context) (string, error) {
	if i.etag == "" {
		return "", webdav.ErrNotImplemented
	}
	return `"` + i.etag + `"`, nil
}

func (f *FS) infoOf(e *entry) *fileInfo {
	if e.node == nil {
		return &fileInfo{name: "/", dir: true, ro: true, mod: f.now()}
	}
	n := e.node
	return &fileInfo{name: e.name, size: n.PlainSize, dir: e.dir(), mod: n.ModifiedAt,
		ro: f.readOnly || !e.writable(), etag: n.SHA256}
}

// ---- folders -----------------------------------------------------------------------------

type dirFile struct {
	fs    *FS
	ctx   context.Context
	e     *entry
	items []fs.FileInfo
	read  bool
}

func (d *dirFile) Readdir(count int) ([]fs.FileInfo, error) {
	if !d.read {
		if err := d.load(); err != nil {
			return nil, err
		}
		d.read = true
	}
	if count <= 0 {
		out := d.items
		d.items = nil
		return out, nil
	}
	if len(d.items) == 0 {
		return nil, io.EOF
	}
	n := min(count, len(d.items))
	out := d.items[:n]
	d.items = d.items[n:]
	return out, nil
}

func (d *dirFile) load() error {
	if d.e.node == nil {
		roots, err := d.fs.rootEntries(d.ctx)
		if err != nil {
			return err
		}
		for _, r := range roots {
			d.items = append(d.items, d.fs.infoOf(r))
		}
		return nil
	}
	kids, err := d.fs.list(d.ctx, d.e.node.ID)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, k := range kids {
		d.items = append(d.items, d.fs.infoOf(&entry{name: k.Name, node: k, perm: d.e.perm}))
		seen[k.Name] = true
	}
	for _, j := range d.fs.junkIn(d.e.path) {
		if !seen[j.name] {
			d.items = append(d.items, j.info())
		}
	}
	return nil
}

func (d *dirFile) Stat() (fs.FileInfo, error)     { return d.fs.infoOf(d.e), nil }
func (d *dirFile) Read([]byte) (int, error)       { return 0, os.ErrInvalid }
func (d *dirFile) Write([]byte) (int, error)      { return 0, os.ErrPermission }
func (d *dirFile) Seek(int64, int) (int64, error) { return 0, nil }
func (d *dirFile) Close() error                   { return nil }

// ---- reading -------------------------------------------------------------------------------

// readFile opens the remote file only when content is first needed, so the
// many opens behind a folder listing cost nothing.
type readFile struct {
	fs  *FS
	ctx context.Context
	e   *entry
	rf  *client.RemoteFile
	pr  *client.PlainReader
	off int64
}

var errForged = errors.New("this file's signature does not verify; it is not served")

func (r *readFile) open() error {
	if r.pr != nil {
		return nil
	}
	rf, err := r.fs.c.OpenRemote(r.ctx, r.e.node.ID)
	if err != nil {
		if herr := r.fs.historyProblem(r.e.path, err); herr != nil {
			return herr
		}
		return mapErr(err)
	}
	if r.fs.failedVerification(rf.Version) {
		return errForged
	}
	pr, err := rf.Reader(r.ctx)
	if err != nil {
		return err
	}
	if _, err := pr.Seek(r.off, io.SeekStart); err != nil {
		return err
	}
	r.rf, r.pr = rf, pr
	return nil
}

func (r *readFile) Read(b []byte) (int, error) {
	if err := r.open(); err != nil {
		return 0, err
	}
	n, err := r.pr.Read(b)
	r.off += int64(n)
	switch {
	case errors.Is(err, client.ErrSignature):
		r.fs.recordVerification(r.rf.Version, false, r.e.path)
		return n, errForged
	case r.pr.Verified():
		r.fs.recordVerification(r.rf.Version, true, r.e.path)
	}
	return n, err
}

func (r *readFile) Seek(off int64, whence int) (int64, error) {
	if r.pr != nil {
		n, err := r.pr.Seek(off, whence)
		r.off = n
		return n, err
	}
	switch whence {
	case io.SeekCurrent:
		off += r.off
	case io.SeekEnd:
		off += r.e.node.PlainSize
	}
	if off < 0 {
		return 0, os.ErrInvalid
	}
	r.off = off
	return off, nil
}

func (r *readFile) Readdir(int) ([]fs.FileInfo, error) { return nil, os.ErrInvalid }
func (r *readFile) Stat() (fs.FileInfo, error)         { return r.fs.infoOf(r.e), nil }
func (r *readFile) Write([]byte) (int, error)          { return 0, os.ErrPermission }
func (r *readFile) Close() error                       { return nil }

// ---- writing ----------------------------------------------------------------------------------

// writeFile buffers a new file or version and uploads it, encrypted, when
// closed: the size must be known before the container can be written.
type writeFile struct {
	fs       *FS
	ctx      context.Context
	parent   *entry
	name     string
	existing *client.Node
	buf      *spool
	closed   bool
}

func (f *FS) newWriteFile(ctx context.Context, parent *entry, name string, existing *client.Node) *writeFile {
	return &writeFile{fs: f, ctx: ctx, parent: parent, name: name, existing: existing, buf: &spool{dir: f.tmp}}
}

func (w *writeFile) Write(b []byte) (int, error) { return w.buf.Write(b) }

func (w *writeFile) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	defer w.buf.Close()
	rd, err := w.buf.Reader()
	if err != nil {
		return err
	}
	now := w.fs.now()
	if w.existing != nil {
		_, err = w.fs.c.UploadVersion(w.ctx, w.existing.ID, w.name, rd, w.buf.size, now)
	} else {
		_, err = w.fs.c.Upload(w.ctx, w.parent.node.ID, w.name, rd, w.buf.size, now)
		var ee *client.ErrExists
		if errors.As(err, &ee) && ee.Kind == "file" { // created meanwhile: becomes a new version
			if rd, err = w.buf.Reader(); err == nil {
				_, err = w.fs.c.UploadVersion(w.ctx, ee.ExistingID, w.name, rd, w.buf.size, now)
			}
		}
	}
	w.fs.invalidate(w.parent.node.ID)
	if herr := w.fs.historyProblem(path.Join(w.parent.path, w.name), err); herr != nil {
		return herr
	}
	return mapErr(err)
}

func (w *writeFile) Stat() (fs.FileInfo, error) {
	return &fileInfo{name: w.name, size: w.buf.size, mod: w.fs.now()}, nil
}
func (w *writeFile) Read([]byte) (int, error)           { return 0, os.ErrInvalid }
func (w *writeFile) Seek(int64, int) (int64, error)     { return 0, os.ErrInvalid }
func (w *writeFile) Readdir(int) ([]fs.FileInfo, error) { return nil, os.ErrInvalid }

// spool holds an upload in memory, spilling to a temporary file past
// memLimit. What spills is encrypted with AES-CTR under a key that exists
// only in this process, so a crash or a forgotten temp directory never
// leaves plaintext on disk. (Integrity is not needed: only this process
// writes and reads the file, and the upload itself is authenticated.)
type spool struct {
	dir  string
	mem  []byte
	f    *os.File
	key  []byte
	iv   []byte
	w    io.Writer
	size int64
}

const memLimit = 16 << 20

func (s *spool) Write(b []byte) (int, error) {
	if s.f == nil && len(s.mem)+len(b) <= memLimit {
		s.mem = append(s.mem, b...)
		s.size += int64(len(b))
		return len(b), nil
	}
	if s.f == nil {
		if err := s.spill(); err != nil {
			return 0, err
		}
	}
	n, err := s.w.Write(b)
	s.size += int64(n)
	return n, err
}

func (s *spool) spill() error {
	f, err := os.CreateTemp(s.dir, "upload-*")
	if err != nil {
		return err
	}
	s.key, s.iv = make([]byte, 32), make([]byte, aes.BlockSize)
	_, _ = rand.Read(s.key)
	_, _ = rand.Read(s.iv)
	block, err := aes.NewCipher(s.key)
	if err != nil {
		_ = f.Close()
		return err
	}
	s.f, s.w = f, &cipher.StreamWriter{S: cipher.NewCTR(block, s.iv), W: f}
	if _, err := s.w.Write(s.mem); err != nil {
		return err
	}
	s.mem = nil
	return nil
}

func (s *spool) Reader() (io.Reader, error) {
	if s.f == nil {
		return bytes.NewReader(s.mem), nil
	}
	if _, err := s.f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	return &cipher.StreamReader{S: cipher.NewCTR(block, s.iv), R: s.f}, nil
}

func (s *spool) Close() {
	s.mem = nil
	if s.f != nil {
		_ = s.f.Close()
		_ = os.Remove(s.f.Name())
		s.f = nil
	}
}

// ---- operating-system clutter -------------------------------------------------------------

// isJunk matches files that operating systems and office suites create on
// network drives for their own bookkeeping. Uploading them would fill the
// encrypted store (and every other device) with clutter, so they live in
// this process's memory for the session only.
func isJunk(base string) bool {
	l := strings.ToLower(base)
	return strings.HasPrefix(base, "._") || l == ".ds_store" || l == "thumbs.db" || l == "desktop.ini" ||
		strings.HasPrefix(base, "~$") || strings.HasPrefix(base, ".~lock.")
}

const (
	maxJunkSize  = 1 << 20
	maxJunkFiles = 4096
)

type junkFile struct {
	path string
	name string
	data []byte
	mod  time.Time
}

func (j *junkFile) info() *fileInfo {
	return &fileInfo{name: j.name, size: int64(len(j.data)), mod: j.mod, ctype: "application/octet-stream"}
}

func (f *FS) getJunk(p string) *junkFile {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.junk[p]
}

func (f *FS) junkIn(dir string) []*junkFile {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*junkFile
	for _, j := range f.junk {
		if path.Dir(j.path) == dir {
			out = append(out, j)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].name < out[b].name })
	return out
}

func (f *FS) removeJunk(p string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.junk[p]; ok {
		delete(f.junk, p)
		return true
	}
	return isJunk(path.Base(p))
}

func (f *FS) moveJunkUnder(from, to string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for p, j := range f.junk {
		if strings.HasPrefix(p, from+"/") {
			delete(f.junk, p)
			j.path = to + strings.TrimPrefix(p, from)
			f.junk[j.path] = j
		}
	}
}

func (f *FS) renameJunk(ctx context.Context, from, to string) (bool, error) {
	fj, tj := isJunk(path.Base(from)), isJunk(path.Base(to))
	switch {
	case !fj && !tj:
		return false, nil
	case fj && tj:
		f.mu.Lock()
		defer f.mu.Unlock()
		j, ok := f.junk[from]
		if !ok {
			return true, os.ErrNotExist
		}
		delete(f.junk, from)
		j.path, j.name = to, path.Base(to)
		f.junk[to] = j
		return true, nil
	default:
		// Turning bookkeeping into a real file, or the reverse, is not
		// something any client needs; refuse rather than guess.
		return true, os.ErrPermission
	}
}

func (f *FS) openJunk(ctx context.Context, p string, flag int) (webdav.File, error) {
	if flag&(os.O_CREATE|os.O_TRUNC|os.O_WRONLY) == 0 {
		j := f.getJunk(p)
		if j == nil {
			return nil, os.ErrNotExist
		}
		return &junkHandle{fs: f, j: j, r: bytes.NewReader(j.data)}, nil
	}
	dir := path.Dir(p)
	if dir == "/" {
		return nil, os.ErrPermission
	}
	if e, err := f.resolve(ctx, dir); err != nil || !e.dir() {
		return nil, os.ErrNotExist
	}
	return &junkHandle{fs: f, j: &junkFile{path: p, name: path.Base(p)}, writing: true}, nil
}

type junkHandle struct {
	fs      *FS
	j       *junkFile
	r       *bytes.Reader
	buf     bytes.Buffer
	writing bool
}

func (h *junkHandle) Write(b []byte) (int, error) {
	if !h.writing {
		return 0, os.ErrPermission
	}
	if h.buf.Len()+len(b) > maxJunkSize {
		return 0, os.ErrInvalid
	}
	return h.buf.Write(b)
}

func (h *junkHandle) Close() error {
	if !h.writing {
		return nil
	}
	h.fs.mu.Lock()
	defer h.fs.mu.Unlock()
	if _, exists := h.fs.junk[h.j.path]; !exists && len(h.fs.junk) >= maxJunkFiles {
		return os.ErrInvalid
	}
	h.j.data, h.j.mod = bytes.Clone(h.buf.Bytes()), h.fs.now()
	h.fs.junk[h.j.path] = h.j
	return nil
}

func (h *junkHandle) Read(b []byte) (int, error) {
	if h.r == nil {
		return 0, os.ErrInvalid
	}
	return h.r.Read(b)
}

func (h *junkHandle) Seek(off int64, whence int) (int64, error) {
	if h.r == nil {
		return 0, os.ErrInvalid
	}
	return h.r.Seek(off, whence)
}

func (h *junkHandle) Readdir(int) ([]fs.FileInfo, error) { return nil, os.ErrInvalid }
func (h *junkHandle) Stat() (fs.FileInfo, error) {
	if h.writing {
		return &fileInfo{name: h.j.name, size: int64(h.buf.Len()), mod: h.fs.now()}, nil
	}
	return h.j.info(), nil
}
