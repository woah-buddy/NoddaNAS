// Package davgw is a local, decrypting WebDAV gateway: it shows a user's
// FrontDir files, in plaintext, as a network drive on their own computer
// (Finder's "Connect to Server", Windows' "Map network drive", davfs2,
// GNOME Files), while everything that goes to the server stays end-to-end
// encrypted.
//
// It is the reverse of the server's own WebDAV endpoint. That one serves
// ciphertext to anyone with an app password, for backups. This one runs
// on the user's machine, holds their unlocked keys in memory, and serves
// plaintext, so it is built around keeping that plaintext on the machine:
//
//   - It listens on loopback only; there is no option to do otherwise.
//   - Every request must name a random 256-bit token in its path, so other
//     users of the same computer cannot browse it, and must carry a
//     loopback Host header and no browser Origin, so a web page cannot
//     reach it (cross-site requests, DNS rebinding).
//   - Responses are marked inert (sandbox CSP, nosniff, no caching), so a
//     file opened in a browser by mistake cannot run as a page.
//   - Reads fetch only the byte ranges asked for, decrypt them, and release
//     only chunks that pass AES-GCM under the file's committed key. A file
//     read to its end in order also has its author's signature checked,
//     and a failure turns the last read into an error, so a copy of a
//     forged file never completes (client.PlainReader).
//   - Writes are buffered (encrypted under a throwaway key if they spill to
//     disk), then encrypted and uploaded on close, exactly as frontdir-cli
//     put would. Deleting moves items to the trash.
//   - Files that operating systems scatter on network drives (.DS_Store,
//     AppleDouble "._" files, Thumbs.db, Office lock files) live in memory
//     for the session and are never uploaded.
package davgw

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/webdav"

	"github.com/woah-buddy/FrontDir/internal/client"
	"github.com/woah-buddy/FrontDir/internal/e2ee"
)

// Options configure the gateway's file system.
type Options struct {
	Client   *client.Client
	ReadOnly bool
	TempDir  string // private directory for upload buffers that spill to disk
	Log      *slog.Logger
}

// FS presents the user's spaces as one tree: "Home" is the personal space,
// and every team folder whose key the user holds appears beside it.
type FS struct {
	c        *client.Client
	readOnly bool
	tmp      string
	log      *slog.Logger
	now      func() time.Time

	mu       sync.Mutex
	roots    []*entry
	rootsAt  time.Time
	lists    map[string]*listing // folder node ID -> children
	junk     map[string]*junkFile
	verified map[string]bool // version ID -> signature verified (true) or failed (false)
}

const (
	listTTL  = 2 * time.Second
	rootsTTL = 30 * time.Second
	homeName = "Home"
)

type listing struct {
	at   time.Time
	kids []*client.Node
}

// entry is a resolved path: a space root, a folder or a file.
type entry struct {
	path  string
	name  string
	node  *client.Node // nil for the virtual root
	space bool         // a space's root folder
	perm  string       // the user's role in the space: read, write or manage
}

func (e *entry) dir() bool { return e.node == nil || e.node.Kind == "folder" }

// writable is a courtesy check (the server decides): it spares buffering
// an upload that would be refused.
func (e *entry) writable() bool {
	return e.node != nil && (e.perm == "write" || e.perm == "manage")
}

// New returns the gateway file system.
func New(o Options) *FS {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	return &FS{c: o.Client, readOnly: o.ReadOnly, tmp: o.TempDir, log: o.Log, now: time.Now,
		lists: map[string]*listing{}, junk: map[string]*junkFile{}, verified: map[string]bool{}}
}

var _ webdav.FileSystem = (*FS)(nil)

func clean(name string) string { return path.Clean("/" + name) }

// rootEntries lists Home and the team folders, with names that are safe
// as path segments and unique.
func (f *FS) rootEntries(ctx context.Context) ([]*entry, error) {
	f.mu.Lock()
	if f.roots != nil && f.now().Sub(f.rootsAt) < rootsTTL {
		r := f.roots
		f.mu.Unlock()
		return r, nil
	}
	f.mu.Unlock()
	spaces, err := f.c.Spaces(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	var out []*entry
	used := map[string]bool{}
	for _, sp := range spaces {
		name := homeName
		if sp.Kind == "team" {
			if sp.MyGrant == nil {
				continue // no key yet: nothing could be shown
			}
			name = sp.Name
			if e2ee.ValidateName(name) != nil || strings.ContainsAny(name, `/\`) {
				name = "Team " + sp.ID[:8]
			}
		}
		base := name
		for i := 2; used[strings.ToLower(name)]; i++ {
			name = fmt.Sprintf("%s (%d)", base, i)
		}
		used[strings.ToLower(name)] = true
		out = append(out, &entry{path: "/" + name, name: name, space: true, perm: sp.Role,
			node: &client.Node{ID: sp.RootID, SpaceID: sp.ID, Kind: "folder", Name: name}})
	}
	f.mu.Lock()
	f.roots, f.rootsAt = out, f.now()
	f.mu.Unlock()
	return out, nil
}

func (f *FS) list(ctx context.Context, folderID string) ([]*client.Node, error) {
	f.mu.Lock()
	if l, ok := f.lists[folderID]; ok && f.now().Sub(l.at) < listTTL {
		f.mu.Unlock()
		return l.kids, nil
	}
	f.mu.Unlock()
	kids, err := f.c.List(ctx, folderID)
	if err != nil {
		return nil, mapErr(err)
	}
	f.mu.Lock()
	f.lists[folderID] = &listing{at: f.now(), kids: kids}
	f.mu.Unlock()
	return kids, nil
}

func (f *FS) invalidate(ids ...string) {
	f.mu.Lock()
	for _, id := range ids {
		delete(f.lists, id)
	}
	f.mu.Unlock()
}

// resolve walks a path through the tree. Names match exactly, or else
// case-insensitively, as macOS and Windows expect.
func (f *FS) resolve(ctx context.Context, p string) (*entry, error) {
	p = clean(p)
	if p == "/" {
		return &entry{path: "/", name: "/"}, nil
	}
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	roots, err := f.rootEntries(ctx)
	if err != nil {
		return nil, err
	}
	var cur *entry
	for _, r := range roots {
		if r.name == segs[0] {
			cur = r
		}
	}
	for _, r := range roots {
		if cur == nil && strings.EqualFold(r.name, segs[0]) {
			cur = r
		}
	}
	if cur == nil {
		return nil, os.ErrNotExist
	}
	for _, seg := range segs[1:] {
		if !cur.dir() {
			return nil, os.ErrNotExist
		}
		kids, err := f.list(ctx, cur.node.ID)
		if err != nil {
			return nil, err
		}
		var next *client.Node
		for _, k := range kids {
			if k.Name == seg {
				next = k
			}
		}
		for _, k := range kids {
			if next == nil && strings.EqualFold(k.Name, seg) {
				next = k
			}
		}
		if next == nil {
			return nil, os.ErrNotExist
		}
		cur = &entry{path: path.Join(cur.path, next.Name), name: next.Name, node: next, perm: cur.perm}
	}
	return cur, nil
}

// parentFor resolves the folder a new item at p would go into, and checks
// that the user may write there.
func (f *FS) parentFor(ctx context.Context, p string) (*entry, error) {
	if f.readOnly {
		return nil, os.ErrPermission
	}
	dir := path.Dir(clean(p))
	if dir == "/" {
		return nil, os.ErrPermission // the top level is the list of spaces
	}
	parent, err := f.resolve(ctx, dir)
	if err != nil {
		return nil, err
	}
	if !parent.dir() {
		return nil, os.ErrNotExist
	}
	if !parent.writable() {
		return nil, os.ErrPermission
	}
	return parent, nil
}

// ---- webdav.FileSystem ---------------------------------------------------------------

// Mkdir creates a folder.
func (f *FS) Mkdir(ctx context.Context, name string, _ os.FileMode) error {
	name = clean(name)
	if isJunk(path.Base(name)) {
		return os.ErrPermission
	}
	parent, err := f.parentFor(ctx, name)
	if err != nil {
		return err
	}
	if _, err := f.c.Mkdir(ctx, parent.node.ID, path.Base(name)); err != nil {
		return mapErr(err)
	}
	f.invalidate(parent.node.ID)
	return nil
}

// OpenFile opens a file or folder. Opening for writing with truncation
// (what WebDAV PUT and COPY do) starts a new upload.
func (f *FS) OpenFile(ctx context.Context, name string, flag int, _ os.FileMode) (webdav.File, error) {
	name = clean(name)
	if isJunk(path.Base(name)) {
		return f.openJunk(ctx, name, flag)
	}
	creating := flag&(os.O_CREATE|os.O_TRUNC) != 0 || flag&os.O_WRONLY != 0
	e, err := f.resolve(ctx, name)
	switch {
	case err == nil && e.dir():
		if creating {
			return nil, os.ErrPermission
		}
		return &dirFile{fs: f, ctx: ctx, e: e}, nil
	case err == nil && !creating:
		return &readFile{fs: f, ctx: ctx, e: e}, nil
	case err == nil:
		if flag&os.O_EXCL != 0 {
			return nil, os.ErrExist
		}
		if f.readOnly || !e.writable() {
			return nil, os.ErrPermission
		}
		parent, err := f.resolve(ctx, path.Dir(name))
		if err != nil {
			return nil, err
		}
		return f.newWriteFile(ctx, parent, e.name, e.node), nil
	case errors.Is(err, os.ErrNotExist) && flag&os.O_CREATE != 0:
		parent, err := f.parentFor(ctx, name)
		if err != nil {
			return nil, err
		}
		if err := e2ee.ValidateName(path.Base(name)); err != nil {
			return nil, os.ErrInvalid
		}
		return f.newWriteFile(ctx, parent, path.Base(name), nil), nil
	default:
		return nil, err
	}
}

// RemoveAll moves an item to its space's trash (never deletes for good).
func (f *FS) RemoveAll(ctx context.Context, name string) error {
	name = clean(name)
	if f.removeJunk(name) {
		return nil
	}
	if f.readOnly || path.Dir(name) == "/" {
		return os.ErrPermission
	}
	e, err := f.resolve(ctx, name)
	if err != nil {
		return err
	}
	parent, err := f.resolve(ctx, path.Dir(name))
	if err != nil {
		return err
	}
	if !parent.writable() {
		return os.ErrPermission
	}
	if err := f.c.Trash(ctx, e.node); err != nil {
		return mapErr(err)
	}
	f.invalidate(parent.node.ID, e.node.ID)
	return nil
}

// Rename renames or moves an item within one space. Moving between spaces
// would mean re-encrypting under another space's keys; copy instead.
func (f *FS) Rename(ctx context.Context, oldName, newName string) error {
	oldName, newName = clean(oldName), clean(newName)
	if handled, err := f.renameJunk(ctx, oldName, newName); handled {
		return err
	}
	if f.readOnly || path.Dir(oldName) == "/" || path.Dir(newName) == "/" {
		return os.ErrPermission
	}
	e, err := f.resolve(ctx, oldName)
	if err != nil {
		return err
	}
	from, err := f.resolve(ctx, path.Dir(oldName))
	if err != nil {
		return err
	}
	to, err := f.parentFor(ctx, newName)
	if err != nil {
		return err
	}
	if !from.writable() {
		return os.ErrPermission
	}
	if to.node.SpaceID != e.node.SpaceID {
		return os.ErrPermission
	}
	newBase := path.Base(newName)
	if err := e2ee.ValidateName(newBase); err != nil {
		return os.ErrInvalid
	}
	if to.node.ID == from.node.ID {
		err = f.c.Rename(ctx, e.node, newBase)
	} else {
		err = f.c.MoveTo(ctx, e.node, to.node.ID, newBase)
	}
	if err != nil {
		return mapErr(err)
	}
	f.invalidate(from.node.ID, to.node.ID)
	f.moveJunkUnder(oldName, newName)
	return nil
}

// Stat describes a file or folder.
func (f *FS) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	name = clean(name)
	if j := f.getJunk(name); j != nil {
		return j.info(), nil
	}
	e, err := f.resolve(ctx, name)
	if err != nil {
		return nil, err
	}
	return f.infoOf(e), nil
}

// ---- signature results -------------------------------------------------------------

func (f *FS) recordVerification(version string, ok bool, p string) {
	f.mu.Lock()
	prev, seen := f.verified[version]
	f.verified[version] = ok
	f.mu.Unlock()
	if !ok && (!seen || prev) {
		f.log.Warn("a file failed its signature check and will not be served", "path", p, "version", version)
	}
}

func (f *FS) failedVerification(version string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	ok, seen := f.verified[version]
	return seen && !ok
}

// mapErr turns API errors into the os errors x/net/webdav maps to statuses.
func mapErr(err error) error {
	var ae *client.APIError
	var ee *client.ErrExists
	switch {
	case errors.As(err, &ee):
		return os.ErrExist
	case errors.As(err, &ae) && ae.Code == "not_found":
		return os.ErrNotExist
	case errors.As(err, &ae) && (ae.Code == "forbidden" || ae.Code == "unauthorized"):
		return os.ErrPermission
	}
	return err
}
