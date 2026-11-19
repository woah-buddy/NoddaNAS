package httpapi

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/webdav"

	"github.com/woah-buddy/NoddaNAS/internal/auth"
	"github.com/woah-buddy/NoddaNAS/internal/domain"
	"github.com/woah-buddy/NoddaNAS/internal/service"
)

// WebDAV lets desktop and mobile clients (Finder, Windows Explorer, rclone,
// davfs2, Cyberduck, mobile file managers) mount NoddaNAS as a drive. It is
// a thin adapter: every operation goes through the same service methods,
// and so the same authorization checks, as the JSON API.
//
// Security notes:
//   - Only app passwords are accepted (HTTP Basic). Browser session cookies
//     are not, so WebDAV adds no new cookie-authenticated surface.
//   - DELETE moves items to the trash rather than destroying them.
//   - Files are always served as sandboxed application/octet-stream: a
//     browser that has cached Basic credentials must not render uploaded
//     HTML or SVG from our origin.
//   - Locks are kept in memory per replica (see docs/ARCHITECTURE.md).

func (s *Server) newDAV() http.Handler {
	locks := webdav.NewMemLS()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
		p, method, err := s.auth.Authenticate(r)
		if err != nil || method != auth.MethodAppPassword {
			if !s.authFailures.allow(s.clientIP(r)) {
				w.Header().Set("Retry-After", "60")
				http.Error(w, "too many failed attempts", http.StatusTooManyRequests)
				return
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="NoddaNAS WebDAV (use an app password)", charset="UTF-8"`)
			http.Error(w, "app password required", http.StatusUnauthorized)
			return
		}
		info(r.Context()).userID = p.UserID
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			// x/net/webdav hands GETs to http.ServeContent, which would
			// otherwise infer text/html from a ".html" name. Presetting
			// the type stops that (ServeContent never overrides it).
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", "attachment")
		}
		rc := http.NewResponseController(w)
		body := &bodyState{r: &idleReader{r: r.Body, rc: rc, d: time.Minute}, c: r.Body}
		r.Body = body
		w = &idleWriter{ResponseWriter: w, rc: rc, d: time.Minute}
		h := &webdav.Handler{
			Prefix:     "/dav",
			FileSystem: &davFS{svc: s.svc, p: p, body: body},
			LockSystem: locks,
			Logger: func(r *http.Request, err error) {
				if err != nil && !errors.Is(err, os.ErrNotExist) {
					s.log.DebugContext(r.Context(), "webdav", "method", r.Method, "err", err)
				}
			},
		}
		h.ServeHTTP(w, r)
	})
}

// bodyState records whether a request body was read to a clean EOF.
type bodyState struct {
	r   io.Reader
	c   io.Closer
	eof bool
}

func (b *bodyState) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if err == io.EOF {
		b.eof = true
	}
	return n, err
}

func (b *bodyState) Close() error { return b.c.Close() }

// davFS adapts the service to webdav.FileSystem for one principal.
type davFS struct {
	svc  *service.Service
	p    service.Principal
	body *bodyState
}

func splitPath(name string) []string {
	clean := strings.Trim(path.Clean("/"+name), "/")
	if clean == "" {
		return nil
	}
	return strings.Split(clean, "/")
}

// osErr translates service errors into the os errors the webdav package
// understands. Unknown errors pass through (and become 500s).
func osErr(err error) error {
	switch domain.CodeOf(err) {
	case "":
		return err
	case domain.CodeNotFound:
		return os.ErrNotExist
	case domain.CodeForbidden, domain.CodeUnauthorized:
		return os.ErrPermission
	case domain.CodeConflict:
		return os.ErrExist
	default:
		return err
	}
}

func (f *davFS) lookup(ctx context.Context, parts []string) (*service.NodeInfo, error) {
	info, err := f.svc.Lookup(ctx, f.p, parts)
	return info, osErr(err)
}

func (f *davFS) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	info, err := f.lookup(ctx, splitPath(name))
	if err != nil {
		return nil, err
	}
	return nodeFileInfo{info.Node}, nil
}

func (f *davFS) Mkdir(ctx context.Context, name string, _ os.FileMode) error {
	parts := splitPath(name)
	if len(parts) == 0 {
		return os.ErrExist
	}
	parent, err := f.lookup(ctx, parts[:len(parts)-1])
	if err != nil {
		return err
	}
	_, err = f.svc.CreateFolder(ctx, f.p, parent.Node.ID, parts[len(parts)-1])
	return osErr(err)
}

func (f *davFS) RemoveAll(ctx context.Context, name string) error {
	info, err := f.lookup(ctx, splitPath(name))
	if err != nil {
		return err
	}
	return osErr(f.svc.Trash(ctx, f.p, info.Node.ID, 0))
}

func (f *davFS) Rename(ctx context.Context, oldName, newName string) error {
	src, err := f.lookup(ctx, splitPath(oldName))
	if err != nil {
		return err
	}
	dst := splitPath(newName)
	if len(dst) == 0 {
		return os.ErrPermission
	}
	parent, err := f.lookup(ctx, dst[:len(dst)-1])
	if err != nil {
		return err
	}
	name := dst[len(dst)-1]
	_, err = f.svc.Update(ctx, f.p, src.Node.ID, service.UpdateRequest{Name: &name, ParentID: &parent.Node.ID})
	return osErr(err)
}

func (f *davFS) OpenFile(ctx context.Context, name string, flag int, _ os.FileMode) (webdav.File, error) {
	parts := splitPath(name)
	if flag&(os.O_WRONLY|os.O_RDWR) == 0 {
		info, err := f.lookup(ctx, parts)
		if err != nil {
			return nil, err
		}
		return &davFile{ctx: ctx, fs: f, node: info.Node}, nil
	}
	if len(parts) == 0 {
		return nil, os.ErrPermission
	}
	existing, err := f.lookup(ctx, parts)
	switch {
	case err == nil && existing.Node.Kind == domain.KindFolder:
		return nil, os.ErrPermission
	case err == nil && flag&os.O_EXCL != 0:
		return nil, os.ErrExist
	case errors.Is(err, os.ErrNotExist) && flag&os.O_CREATE == 0:
		return nil, err
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return nil, err
	}
	parent, err := f.lookup(ctx, parts[:len(parts)-1])
	if err != nil {
		return nil, err
	}
	return newDavWriter(ctx, f, parent.Node.ID, parts[len(parts)-1]), nil
}

// davWriter streams a PUT body into service.Upload through a pipe.
type davWriter struct {
	fs      *davFS
	name    string
	pw      *io.PipeWriter
	done    chan error
	written int64
	node    *domain.Node
}

var errIncompleteBody = errors.New("request body ended before completion")

func newDavWriter(ctx context.Context, f *davFS, parentID, name string) *davWriter {
	pr, pw := io.Pipe()
	w := &davWriter{fs: f, name: name, pw: pw, done: make(chan error, 1)}
	go func() {
		n, err := f.svc.Upload(ctx, f.p, service.UploadRequest{ParentID: parentID, Name: name, Overwrite: true, Size: -1}, pr)
		w.node = n
		pr.CloseWithError(err) // unblock the writer if the upload failed early
		w.done <- err
	}()
	return w
}

func (w *davWriter) Write(p []byte) (int, error) {
	n, err := w.pw.Write(p)
	w.written += int64(n)
	return n, err
}

func (w *davWriter) Close() error {
	// If the client disconnected mid-upload, abort instead of committing a
	// truncated file.
	if w.fs.body.eof {
		w.pw.Close()
	} else {
		w.pw.CloseWithError(errIncompleteBody)
	}
	return osErr(<-w.done)
}

func (w *davWriter) Stat() (fs.FileInfo, error) {
	return nodeFileInfo{&domain.Node{Name: w.name, Kind: domain.KindFile, Size: w.written, ModifiedAt: time.Now()}}, nil
}
func (w *davWriter) Read([]byte) (int, error)           { return 0, os.ErrPermission }
func (w *davWriter) Seek(int64, int) (int64, error)     { return 0, os.ErrPermission }
func (w *davWriter) Readdir(int) ([]fs.FileInfo, error) { return nil, os.ErrPermission }

// davFile is a node opened for reading or listing.
type davFile struct {
	ctx     context.Context
	fs      *davFS
	node    *domain.Node
	content *service.Content
	listed  []fs.FileInfo
	listPos int
	listed0 bool
}

func (d *davFile) open() error {
	if d.content != nil {
		return nil
	}
	if d.node.Kind != domain.KindFile {
		return os.ErrInvalid
	}
	c, err := d.fs.svc.OpenContent(d.ctx, d.fs.p, d.node.ID, "")
	if err != nil {
		return osErr(err)
	}
	d.content = c
	return nil
}

func (d *davFile) Read(p []byte) (int, error) {
	if err := d.open(); err != nil {
		return 0, err
	}
	return d.content.Read(p)
}

func (d *davFile) Seek(off int64, whence int) (int64, error) {
	if err := d.open(); err != nil {
		return 0, err
	}
	return d.content.Seek(off, whence)
}

const davMaxListing = 10000

func (d *davFile) Readdir(count int) ([]fs.FileInfo, error) {
	if d.node.Kind != domain.KindFolder {
		return nil, os.ErrInvalid
	}
	if !d.listed0 {
		d.listed0 = true
		cursor := ""
		for len(d.listed) < davMaxListing {
			_, kids, next, err := d.fs.svc.ListChildren(d.ctx, d.fs.p, d.node.ID, cursor, 1000)
			if err != nil {
				return nil, osErr(err)
			}
			for _, k := range kids {
				d.listed = append(d.listed, nodeFileInfo{k})
			}
			if next == "" {
				break
			}
			cursor = next
		}
	}
	rest := d.listed[d.listPos:]
	if count <= 0 {
		d.listPos = len(d.listed)
		return rest, nil
	}
	if len(rest) == 0 {
		return nil, io.EOF
	}
	n := min(count, len(rest))
	d.listPos += n
	return rest[:n], nil
}

func (d *davFile) Stat() (fs.FileInfo, error) { return nodeFileInfo{d.node}, nil }
func (d *davFile) Write([]byte) (int, error)  { return 0, os.ErrPermission }
func (d *davFile) Close() error {
	if d.content != nil {
		return d.content.Close()
	}
	return nil
}

// nodeFileInfo presents a node as an os.FileInfo.
type nodeFileInfo struct{ n *domain.Node }

func (i nodeFileInfo) Name() string {
	if i.n.Name == "" {
		return "/"
	}
	return i.n.Name
}
func (i nodeFileInfo) Size() int64        { return i.n.Size }
func (i nodeFileInfo) ModTime() time.Time { return i.n.ModifiedAt }
func (i nodeFileInfo) IsDir() bool        { return i.n.Kind == domain.KindFolder }
func (i nodeFileInfo) Sys() any           { return nil }
func (i nodeFileInfo) Mode() fs.FileMode {
	if i.IsDir() {
		return fs.ModeDir | 0o700
	}
	return 0o600
}

// ContentType implements webdav.ContentTyper (used for PROPFIND's
// getcontenttype). GET responses are pinned separately in newDAV.
func (i nodeFileInfo) ContentType(context.Context) (string, error) {
	return "application/octet-stream", nil
}

// ETag implements webdav.ETager using the content hash (files) or revision.
func (i nodeFileInfo) ETag(context.Context) (string, error) {
	if i.n.Kind == domain.KindFile && i.n.SHA256 != "" {
		return `"` + i.n.SHA256 + `"`, nil
	}
	return `"r` + i.n.ID + "-" + strconv.FormatInt(i.n.Revision, 10) + `"`, nil
}
