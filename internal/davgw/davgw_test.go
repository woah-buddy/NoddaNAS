package davgw

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestListenIsLoopbackOnly(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1:8484": true, "[::1]:8484": true, "localhost:8484": true, "127.0.0.2:1": true,
		"0.0.0.0:8484": false, ":8484": false, "192.168.1.5:8484": false, "[::]:8484": false, "example.com:80": false, "127.0.0.1": false,
	} {
		if err := CheckListen(addr); (err == nil) != ok {
			t.Errorf("%s: %v", addr, err)
		}
	}
}

func TestJunkNames(t *testing.T) {
	for name, junk := range map[string]bool{
		".DS_Store": true, "._report.pdf": true, "Thumbs.db": true, "desktop.ini": true, "~$budget.xlsx": true,
		".~lock.notes.odt#": true, "report.pdf": false, ".bashrc": false, "_notes": false, "~draft.txt": false,
	} {
		if isJunk(name) != junk {
			t.Errorf("%s: junk=%v", name, !junk)
		}
	}
}

// Uploads larger than the memory buffer spill to disk encrypted under a
// key held only in memory: no plaintext is ever written to disk.
func TestSpoolSpillsEncrypted(t *testing.T) {
	dir := t.TempDir()
	plain := make([]byte, memLimit+300_000)
	rand.Read(plain)
	copy(plain[memLimit+10:], "VERY-SECRET-MARKER")
	s := &spool{dir: dir}
	for off := 0; off < len(plain); off += 70_000 {
		if _, err := s.Write(plain[off:min(off+70_000, len(plain))]); err != nil {
			t.Fatal(err)
		}
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*"))
	if len(files) != 1 {
		t.Fatalf("expected one spill file, got %v", files)
	}
	onDisk, _ := os.ReadFile(files[0])
	if bytes.Contains(onDisk, []byte("VERY-SECRET-MARKER")) || bytes.Equal(onDisk[:1000], plain[:1000]) {
		t.Fatal("plaintext reached the disk")
	}
	r, _ := s.Reader()
	got, _ := io.ReadAll(r)
	if !bytes.Equal(got, plain) || s.size != int64(len(plain)) {
		t.Fatal("spool did not read back what was written")
	}
	s.Close()
	if files, _ := filepath.Glob(filepath.Join(dir, "*")); len(files) != 0 {
		t.Fatal("spill file left behind")
	}
}
