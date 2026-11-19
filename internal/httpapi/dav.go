package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"golang.org/x/net/webdav"

	"github.com/woah-buddy/NoddaNAS/internal/auth"
	"github.com/woah-buddy/NoddaNAS/internal/domain"
	"github.com/woah-buddy/NoddaNAS/internal/service"
)

// WebDAV exposes the caller's spaces as a read-only tree of encrypted
// containers, for backup tools (rclone, restic, Duplicati, plain mounts).
// With end-to-end encryption the server cannot offer plaintext WebDAV;
// the NoddaNAS CLI decrypts locally instead.
//
// Layout (names are IDs, because real names are encrypted):
//
//	/dav/<spaceId>/_noddanas-space.json     the space's public, encrypted key record
//	/dav/<spaceId>/_noddanas-folder.json    this folder's children: encrypted names + wrapped keys
//	/dav/<spaceId>/<folderId>/...           subfolders, recursively
//	/dav/<spaceId>/<fileId>.ndne            each file's current container
//
// A mirror of this tree is a complete backup that stays encrypted: every
// container restores on its own (docs/E2EE.md §5), and the JSON records let
// an offline tool rebuild the whole tree, names included, from the user's
// keys alone.
//
// Only app passwords are accepted; responses are sandboxed octet-streams.

const (
	davSpaceFile  = "_noddanas-space.json"
	davFolderFile = "_noddanas-folder.json"
	davExt        = ".ndne"
)

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
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			// x/net/webdav hands GETs to http.ServeContent, which would infer
			// a type from the name; pin it (ServeContent never overrides it).
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", "attachment")
		case http.MethodOptions, "PROPFIND", "LOCK", "UNLOCK":
		default:
			http.Error(w, "NoddaNAS WebDAV is read-only (end-to-end encrypted); use the web app or CLI to change files",
				http.StatusMethodNotAllowed)
			return
		}
		w = &idleWriter{ResponseWriter: w, rc: http.NewResponseController(w), d: time.Minute}
		h := &webdav.Handler{Prefix: "/dav", FileSystem: &davFS{svc: s.svc, p: p}, LockSystem: locks,
			Logger: func(r *http.Request, err error) {
				if err != nil && !errors.Is(err, os.ErrNotExist) {
					s.log.DebugContext(r.Context(), "webdav", "method", r.Method, "err", err)
				}
			}}
		h.ServeHTTP(w, r)
	})
}

type davFS struct {
	svc *service.Service
	p   service.Principal
}

// davTarget is what a path resolves to.
type davTarget struct {
	root    bool               // /dav/ itself
	space   *service.SpaceInfo // the space directory
	node    *domain.Node       // a folder or file node
	virtual string             // a generated JSON record's file name
}

func osErr(err error) error {
	switch domain.CodeOf(err) {
	case "":
		return err
	case domain.CodeNotFound, domain.CodeInvalid:
		return os.ErrNotExist
	case domain.CodeForbidden, domain.CodeUnauthorized:
		return os.ErrPermission
	default:
		return err
	}
}

func (f *davFS) resolve(ctx context.Context, name string) (*davTarget, error) {
	clean := strings.Trim(path.Clean("/"+name), "/")
	if clean == "" {
		return &davTarget{root: true}, nil
	}
	segs := strings.Split(clean, "/")
	sp, err := f.svc.GetSpace(ctx, f.p, segs[0])
	if err != nil {
		return nil, osErr(err)
	}
	root, err := f.svc.GetNode(ctx, f.p, sp.Space.RootID)
	if err != nil {
		return nil, osErr(err)
	}
	t := &davTarget{space: sp}
	cur := root.Node
	for i, seg := range segs[1:] {
		last := i == len(segs)-2
		if last && (seg == davFolderFile || seg == davSpaceFile && cur.IsRoot()) {
			t.node, t.virtual = cur, seg
			return t, nil
		}
		id, isFile := strings.CutSuffix(seg, davExt)
		info, err := f.svc.GetNode(ctx, f.p, id)
		if err != nil {
			return nil, osErr(err)
		}
		// The path must follow the real tree, so a node cannot be reached
		// under somebody else's folder.
		if info.Node.ParentID != cur.ID || isFile != (info.Node.Kind == domain.KindFile) || (isFile && !last) {
			return nil, os.ErrNotExist
		}
		cur = info.Node
	}
	t.node = cur
	return t, nil
}

func (f *davFS) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	t, err := f.resolve(ctx, name)
	if err != nil {
		return nil, err
	}
	file, err := f.open(ctx, t)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return file.Stat()
}

func (f *davFS) OpenFile(ctx context.Context, name string, flag int, _ os.FileMode) (webdav.File, error) {
	if flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC) != 0 {
		return nil, os.ErrPermission
	}
	t, err := f.resolve(ctx, name)
	if err != nil {
		return nil, err
	}
	return f.open(ctx, t)
}

func (f *davFS) Mkdir(context.Context, string, os.FileMode) error { return os.ErrPermission }
func (f *davFS) RemoveAll(context.Context, string) error          { return os.ErrPermission }
func (f *davFS) Rename(context.Context, string, string) error     { return os.ErrPermission }

func (f *davFS) open(ctx context.Context, t *davTarget) (webdav.File, error) {
	switch {
	case t.root:
		return &davDir{name: "/", list: func() ([]fs.FileInfo, error) { return f.listSpaces(ctx) }}, nil
	case t.virtual != "":
		data, err := f.record(ctx, t)
		if err != nil {
			return nil, err
		}
		return &davBlob{Reader: bytes.NewReader(data), info: davInfo{name: t.virtual, size: int64(len(data)), mod: t.node.ModifiedAt}}, nil
	case t.node.Kind == domain.KindFolder:
		name := t.node.ID
		if t.node.IsRoot() {
			name = t.space.Space.ID
		}
		node := t.node
		return &davDir{name: name, mod: node.ModifiedAt, list: func() ([]fs.FileInfo, error) { return f.listFolder(ctx, node) }}, nil
	default:
		return &davFile{ctx: ctx, fs: f, node: t.node}, nil
	}
}

func (f *davFS) listSpaces(ctx context.Context) ([]fs.FileInfo, error) {
	spaces, err := f.svc.ListSpaces(ctx, f.p)
	if err != nil {
		return nil, osErr(err)
	}
	out := make([]fs.FileInfo, len(spaces))
	for i, sp := range spaces {
		out[i] = davInfo{name: sp.Space.ID, dir: true, mod: sp.Space.CreatedAt}
	}
	return out, nil
}

const davMaxListing = 100_000

func (f *davFS) children(ctx context.Context, folder *domain.Node) ([]*domain.Node, error) {
	var out []*domain.Node
	cursor := ""
	for len(out) < davMaxListing {
		_, kids, next, err := f.svc.ListChildren(ctx, f.p, folder.ID, cursor, 1000)
		if err != nil {
			return nil, osErr(err)
		}
		out = append(out, kids...)
		if next == "" {
			break
		}
		cursor = next
	}
	return out, nil
}

func (f *davFS) listFolder(ctx context.Context, folder *domain.Node) ([]fs.FileInfo, error) {
	kids, err := f.children(ctx, folder)
	if err != nil {
		return nil, err
	}
	out := []fs.FileInfo{davInfo{name: davFolderFile, mod: folder.ModifiedAt}}
	if folder.IsRoot() {
		out = append(out, davInfo{name: davSpaceFile, mod: folder.ModifiedAt})
	}
	for _, k := range kids {
		if k.Kind == domain.KindFolder {
			out = append(out, davInfo{name: k.ID, dir: true, mod: k.ModifiedAt})
		} else {
			out = append(out, davInfo{name: k.ID + davExt, size: k.Size, mod: k.ModifiedAt, etag: k.SHA256})
		}
	}
	return out, nil
}

// SpaceRecord and FolderRecord are the backup metadata formats.
type SpaceRecord struct {
	Format    string `json:"format"` // "noddanas-space/v1"
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	RootID    string `json:"rootId"`
	NameEnc   string `json:"nameEnc,omitempty"`
	PublicKey string `json:"publicKey"`
	KeySig    string `json:"keySig"`
	KeySigner string `json:"keySigner"`
	RootKey   string `json:"rootKey"`
}

type FolderRecord struct {
	Format   string        `json:"format"` // "noddanas-folder/v1"
	ID       string        `json:"id"`
	SpaceID  string        `json:"spaceId"`
	ParentID string        `json:"parentId,omitempty"`
	Children []FolderEntry `json:"children"`
}

type FolderEntry struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	NameEnc    string `json:"nameEnc"`
	WrappedKey string `json:"wrappedKey"`
	Size       int64  `json:"size,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
}

// record renders a folder's or space's encrypted metadata as JSON.
func (f *davFS) record(ctx context.Context, t *davTarget) ([]byte, error) {
	if t.virtual == davSpaceFile {
		sp := t.space.Space
		return json.MarshalIndent(SpaceRecord{Format: "noddanas-space/v1", ID: sp.ID, Kind: string(sp.Kind),
			RootID: sp.RootID, NameEnc: sp.NameEnc, PublicKey: sp.PublicKey, KeySig: sp.KeySig,
			KeySigner: sp.KeySigner, RootKey: sp.RootKey}, "", "  ")
	}
	kids, err := f.children(ctx, t.node)
	if err != nil {
		return nil, err
	}
	rec := FolderRecord{Format: "noddanas-folder/v1", ID: t.node.ID, SpaceID: t.node.SpaceID, ParentID: t.node.ParentID,
		Children: make([]FolderEntry, len(kids))}
	for i, k := range kids {
		rec.Children[i] = FolderEntry{k.ID, string(k.Kind), k.NameEnc, k.WrappedKey, k.Size, k.SHA256}
	}
	return json.MarshalIndent(rec, "", "  ")
}

// ---- webdav.File implementations ----------------------------------------------------------

type davInfo struct {
	name string
	size int64
	mod  time.Time
	dir  bool
	etag string
}

func (i davInfo) Name() string       { return i.name }
func (i davInfo) Size() int64        { return i.size }
func (i davInfo) ModTime() time.Time { return i.mod }
func (i davInfo) IsDir() bool        { return i.dir }
func (i davInfo) Sys() any           { return nil }
func (i davInfo) Mode() fs.FileMode {
	if i.dir {
		return fs.ModeDir | 0o500
	}
	return 0o400
}

// ContentType implements webdav.ContentTyper (PROPFIND getcontenttype).
func (i davInfo) ContentType(context.Context) (string, error) {
	if i.dir {
		return "httpd/unix-directory", nil
	}
	return "application/octet-stream", nil
}

// ETag implements webdav.ETager.
func (i davInfo) ETag(context.Context) (string, error) {
	if i.etag != "" {
		return `"` + i.etag + `"`, nil
	}
	return "", webdav.ErrNotImplemented
}

type davDir struct {
	name    string
	mod     time.Time
	list    func() ([]fs.FileInfo, error)
	entries []fs.FileInfo
	loaded  bool
	pos     int
}

func (d *davDir) Readdir(count int) ([]fs.FileInfo, error) {
	if !d.loaded {
		entries, err := d.list()
		if err != nil {
			return nil, err
		}
		d.entries, d.loaded = entries, true
	}
	rest := d.entries[d.pos:]
	if count <= 0 {
		d.pos = len(d.entries)
		return rest, nil
	}
	if len(rest) == 0 {
		return nil, io.EOF
	}
	n := min(count, len(rest))
	d.pos += n
	return rest[:n], nil
}

func (d *davDir) Stat() (fs.FileInfo, error) {
	return davInfo{name: d.name, dir: true, mod: d.mod}, nil
}
func (d *davDir) Read([]byte) (int, error)       { return 0, os.ErrInvalid }
func (d *davDir) Seek(int64, int) (int64, error) { return 0, os.ErrInvalid }
func (d *davDir) Write([]byte) (int, error)      { return 0, os.ErrPermission }
func (d *davDir) Close() error                   { return nil }

type davBlob struct {
	*bytes.Reader
	info davInfo
}

func (b *davBlob) Stat() (fs.FileInfo, error)         { return b.info, nil }
func (b *davBlob) Readdir(int) ([]fs.FileInfo, error) { return nil, os.ErrInvalid }
func (b *davBlob) Write([]byte) (int, error)          { return 0, os.ErrPermission }
func (b *davBlob) Close() error                       { return nil }

type davFile struct {
	ctx     context.Context
	fs      *davFS
	node    *domain.Node
	content *service.Content
}

func (d *davFile) open() error {
	if d.content != nil {
		return nil
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

func (d *davFile) Stat() (fs.FileInfo, error) {
	return davInfo{name: d.node.ID + davExt, size: d.node.Size, mod: d.node.ModifiedAt, etag: d.node.SHA256}, nil
}
func (d *davFile) Readdir(int) ([]fs.FileInfo, error) { return nil, os.ErrInvalid }
func (d *davFile) Write([]byte) (int, error)          { return 0, os.ErrPermission }
func (d *davFile) Close() error {
	if d.content != nil {
		return d.content.Close()
	}
	return nil
}
