package service_test

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/woah-buddy/FrontDir/internal/domain"
	"github.com/woah-buddy/FrontDir/internal/e2ee"
	"github.com/woah-buddy/FrontDir/internal/service"
)

// The server keeps every file's signed history consistent (docs/E2EE.md
// §5c): each new version carries a record by its uploader that follows the
// current one, and nothing else is stored.
func TestVersionRecords(t *testing.T) {
	e := newEnv(t)
	a, b := e.user("alice"), e.user("bob")
	f := must[*domain.Node](t)(a.put(a.root, "plan.txt", "v1"))
	ct := a.container(a.home, a.keys[f.ID], "plan.txt", "v2")
	p, _ := e2ee.ParsePrefix(bytes.NewReader(ct))
	vs := must[[]*domain.Version](t)(e.svc.ListVersions(e.ctx, a.p, f.ID))
	if vs[0].Seq != 1 || len(vs[0].Record) == 0 {
		t.Fatalf("first version not recorded: seq %d", vs[0].Seq)
	}
	next := e2ee.VersionRecord{Node: f.ID, Seq: 2, Prev: e2ee.B64(vs[0].RecordHash), Container: e2ee.B64(p.Hash()),
		Kind: e2ee.KindSave, At: time.Now().UnixMilli()}
	sign := func(by *client, r e2ee.VersionRecord) *e2ee.SignedRecord {
		return must[*e2ee.SignedRecord](t)(e2ee.SignRecord(by.acct, r))
	}
	up := func(r *e2ee.SignedRecord) error {
		req := service.UploadRequest{NodeID: f.ID, Size: int64(len(ct))}
		if r != nil {
			req.Record, req.RecordSig = r.Raw, r.Sig
		}
		_, err := e.svc.Upload(e.ctx, a.p, req, bytes.NewReader(ct))
		return err
	}
	with := func(fn func(r *e2ee.VersionRecord)) e2ee.VersionRecord { r := next; fn(&r); return r }

	wantCode(t, up(nil), domain.CodeInvalid)
	wantCode(t, up(sign(a, with(func(r *e2ee.VersionRecord) { r.Node = a.root }))), domain.CodeInvalid)
	wantCode(t, up(sign(b, next)), domain.CodeInvalid) // signed by someone else
	wantCode(t, up(sign(a, with(func(r *e2ee.VersionRecord) { r.Container = r.Prev }))), domain.CodeInvalid)
	forged := sign(a, next)
	forged.Sig[3] ^= 1
	wantCode(t, up(forged), domain.CodeInvalid)
	// Out of place: an old position, or the right one naming another predecessor.
	wantCode(t, up(sign(a, with(func(r *e2ee.VersionRecord) { r.Seq, r.Prev = 1, "" }))), domain.CodePrecondition)
	wantCode(t, up(sign(a, with(func(r *e2ee.VersionRecord) { r.Prev = r.Container }))), domain.CodePrecondition)
	wantCode(t, up(sign(a, with(func(r *e2ee.VersionRecord) { r.Seq = 3 }))), domain.CodePrecondition)
	if n := len(e.blobFiles()); n != 1 {
		t.Fatalf("refused uploads left %d blobs", n-1)
	}

	// A restore must be recorded as one, and name the restored container.
	saveAsRestore, _ := a.record(f.ID, vs[0].Header, e2ee.KindSave)
	_, err := e.svc.RestoreVersion(e.ctx, a.p, f.ID, vs[0].ID, saveAsRestore, sign(a, next).Sig)
	wantCode(t, err, domain.CodeInvalid)
	wrongSource := sign(a, with(func(r *e2ee.VersionRecord) { r.Kind = e2ee.KindRestore }))
	_, err = e.svc.RestoreVersion(e.ctx, a.p, f.ID, vs[0].ID, wrongSource.Raw, wrongSource.Sig)
	wantCode(t, err, domain.CodeInvalid)

	// Racing for the same position: exactly one wins.
	good := sign(a, next)
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := up(good); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			} else if domain.CodeOf(err) != domain.CodePrecondition {
				t.Errorf("racing upload: %v", err)
			}
		}()
	}
	wg.Wait()
	vs = must[[]*domain.Version](t)(e.svc.ListVersions(e.ctx, a.p, f.ID))
	if wins != 1 || len(vs) != 2 || vs[0].Seq != 2 {
		t.Fatalf("%d uploads won the same position; %d versions", wins, len(vs))
	}
	if n := len(e.blobFiles()); n != 2 {
		t.Fatalf("lost races left %d extra blobs", n-2)
	}
}
