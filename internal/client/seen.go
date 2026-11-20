package client

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/woah-buddy/FrontDir/internal/e2ee"
)

// Remembering file histories (docs/E2EE.md §5c). A client keeps, per file,
// the newest signed version record it has verified. Later it notices if
// the server shows that file's history ending earlier (a rollback) or
// taking a different path (a fork). What is remembered is not secret
// (random IDs, a counter and a hash), but it must not be lost or rolled
// back itself, which is why it stays on this device rather than the server.

// SeenStore remembers the newest verified record per user and file.
type SeenStore interface {
	Get(userID, nodeID string) *e2ee.Seen
	Put(userID, nodeID string, s e2ee.Seen)
	Forget(userID, nodeID string)
}

// MemorySeen keeps what was seen for the life of the process (the default).
type MemorySeen struct {
	mu sync.Mutex
	m  map[string]map[string]e2ee.Seen
}

func (s *MemorySeen) Get(userID, nodeID string) *e2ee.Seen {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.m[userID][nodeID]; ok {
		return &v
	}
	return nil
}

func (s *MemorySeen) Put(userID, nodeID string, v e2ee.Seen) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]map[string]e2ee.Seen{}
	}
	if s.m[userID] == nil {
		s.m[userID] = map[string]e2ee.Seen{}
	}
	s.m[userID][nodeID] = v
}

func (s *MemorySeen) Forget(userID, nodeID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m[userID], nodeID)
}

// FileSeen is a SeenStore kept in a JSON file (created with permissions
// 0600), so that the CLI and the drive remember across runs. Each change
// re-reads the file and writes it back atomically, so separate processes
// sharing it lose at most a concurrent update, never the whole file.
type FileSeen struct {
	path string
	mu   sync.Mutex
	mem  MemorySeen
}

// OpenFileSeen opens (or starts) the store at path.
func OpenFileSeen(path string) (*FileSeen, error) {
	f := &FileSeen{path: path}
	if err := f.load(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *FileSeen) load() error {
	b, err := os.ReadFile(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var m map[string]map[string]e2ee.Seen
	if err := json.Unmarshal(b, &m); err != nil {
		return errors.New("the file history store " + f.path + " is damaged; move it aside to start over")
	}
	for u, nodes := range m {
		for n, s := range nodes {
			if cur := f.mem.Get(u, n); cur == nil || s.Seq > cur.Seq {
				f.mem.Put(u, n, s)
			}
		}
	}
	return nil
}

func (f *FileSeen) Get(userID, nodeID string) *e2ee.Seen { return f.mem.Get(userID, nodeID) }

func (f *FileSeen) Put(userID, nodeID string, s e2ee.Seen) {
	f.change(func() { f.mem.Put(userID, nodeID, s) })
}

func (f *FileSeen) Forget(userID, nodeID string) {
	f.change(func() { f.mem.Forget(userID, nodeID) })
}

// change applies fn on top of the file's current contents and saves. A
// failure to save is not fatal: what was seen stays remembered in memory.
func (f *FileSeen) change(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = f.load() // merge updates from other processes
	fn()
	f.mem.mu.Lock()
	b, err := json.Marshal(f.mem.m)
	f.mem.mu.Unlock()
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.path), ".seen-*")
	if err != nil {
		return
	}
	_, werr := tmp.Write(b)
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Rename(tmp.Name(), f.path) != nil {
		_ = os.Remove(tmp.Name())
	}
}

// SetSeenStore sets where the client remembers file histories. The
// default remembers only for the life of the process.
func (c *Client) SetSeenStore(s SeenStore) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen = s
}

func (c *Client) seenFor(acct *e2ee.Account, nodeID string) *e2ee.Seen {
	c.mu.Lock()
	s := c.seen
	c.mu.Unlock()
	return s.Get(acct.UserID, nodeID)
}

// remember records head as seen for the file, if it is newer than what is
// remembered (or always, with force).
func (c *Client) remember(acct *e2ee.Account, nodeID string, head *e2ee.SignedRecord, force bool) {
	c.mu.Lock()
	s := c.seen
	c.mu.Unlock()
	if cur := s.Get(acct.UserID, nodeID); !force && cur != nil && cur.Seq >= head.Seq {
		return
	}
	s.Put(acct.UserID, nodeID, e2ee.SeenOf(head))
}
