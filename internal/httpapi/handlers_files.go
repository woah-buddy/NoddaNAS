package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/woah-buddy/FrontDir/internal/domain"
	"github.com/woah-buddy/FrontDir/internal/service"
)

func queryInt(r *http.Request, key string) int64 {
	n, _ := strconv.ParseInt(r.URL.Query().Get(key), 10, 64)
	return n
}

type entryReq struct {
	NameEnc    string `json:"nameEnc"`
	NameHash   string `json:"nameHash"`
	WrappedKey string `json:"wrappedKey"`
}

func (e entryReq) toService() service.EntryFields {
	return service.EntryFields{NameEnc: e.NameEnc, NameHash: e.NameHash, WrappedKey: e.WrappedKey}
}

func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request, p service.Principal) {
	info, err := s.svc.GetNode(r.Context(), p, r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, viewInfo(info))
}

// handleNodePath returns what a client needs to derive a node's key.
func (s *Server) handleNodePath(w http.ResponseWriter, r *http.Request, p service.Principal) {
	path, err := s.svc.NodePath(r.Context(), p, r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	resp := map[string]any{
		"space": viewSpaceInfo(path.Space),
		"nodes": viewNodes(path.Nodes),
		"node":  viewInfo(path.Info),
	}
	if path.Share != nil {
		resp["share"] = viewShare(path.Share)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleListChildren(w http.ResponseWriter, r *http.Request, p service.Principal) {
	info, children, next, err := s.svc.ListChildren(r.Context(), p, r.PathValue("id"), r.URL.Query().Get("cursor"), int(queryInt(r, "limit")))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"node": viewInfo(info), "children": viewNodes(children), "nextCursor": next})
}

func (s *Server) handleCreateFolder(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req struct {
		ID string `json:"id"`
		entryReq
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	n, err := s.svc.CreateFolder(r.Context(), p, r.PathValue("id"), req.ID, req.entryReq.toService())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, viewNode(n))
}

// idleReader extends the connection's read deadline as data arrives: a
// large upload may take hours, but a stalled one (slowloris) is cut off.
type idleReader struct {
	r  io.Reader
	rc *http.ResponseController
	d  time.Duration
}

func (i *idleReader) Read(p []byte) (int, error) {
	_ = i.rc.SetReadDeadline(time.Now().Add(i.d))
	return i.r.Read(p)
}

// handleUploadFile stores a new encrypted file in folder {id}. The body is
// the container; the encrypted directory entry travels in a header so the
// body can stream straight through.
func (s *Server) handleUploadFile(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var meta struct {
		ID string `json:"id"`
		entryReq
	}
	raw := r.Header.Get("X-FrontDir-Entry")
	if len(raw) > 4096 || json.Unmarshal([]byte(raw), &meta) != nil {
		s.writeError(w, r, domain.E(domain.CodeInvalid, "missing or malformed X-FrontDir-Entry header"))
		return
	}
	s.upload(w, r, p, service.UploadRequest{ParentID: r.PathValue("id"), NewID: meta.ID, Entry: meta.entryReq.toService()}, http.StatusCreated)
}

// handleUploadVersion stores a new encrypted version of file {id}.
func (s *Server) handleUploadVersion(w http.ResponseWriter, r *http.Request, p service.Principal) {
	s.upload(w, r, p, service.UploadRequest{NodeID: r.PathValue("id"), Revision: queryInt(r, "revision")}, http.StatusOK)
}

func (s *Server) upload(w http.ResponseWriter, r *http.Request, p service.Principal, req service.UploadRequest, status int) {
	req.Size = r.ContentLength
	// The signed version record (docs/E2EE.md §5c) travels in headers too.
	var err error
	if req.Record, req.RecordSig, err = decodeRecord(r.Header.Get("X-FrontDir-Record"), r.Header.Get("X-FrontDir-Record-Sig")); err != nil {
		s.writeError(w, r, err)
		return
	}
	body := &idleReader{r: r.Body, rc: http.NewResponseController(w), d: time.Minute}
	n, err := s.svc.Upload(r.Context(), p, req, body)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, status, viewNode(n))
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request, p service.Principal) {
	c, err := s.svc.OpenContent(r.Context(), p, r.PathValue("id"), r.URL.Query().Get("version"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.serveContainer(w, r, c)
}

func (s *Server) handleUpdateNode(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req struct {
		ParentID *string `json:"parentId"`
		Revision int64   `json:"revision"`
		entryReq
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	n, err := s.svc.Update(r.Context(), p, r.PathValue("id"), service.UpdateRequest{ParentID: req.ParentID,
		Entry: req.entryReq.toService(), Revision: req.Revision})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, viewNode(n))
}

func (s *Server) handleTrashNode(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req struct {
		RestoreKey string `json:"restoreKey"`
		RestoreSig string `json:"restoreSig"`
		Revision   int64  `json:"revision"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.svc.Trash(r.Context(), p, r.PathValue("id"), service.TrashRequest{RestoreKey: req.RestoreKey,
		RestoreSig: req.RestoreSig, Revision: req.Revision}); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListVersions(w http.ResponseWriter, r *http.Request, p service.Principal) {
	vs, err := s.svc.ListVersions(r.Context(), p, r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	out := make([]versionView, len(vs))
	for i, v := range vs {
		out[i] = viewVersion(v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": out})
}

// decodeRecord decodes a version record and its signature (base64url).
// Both empty is allowed here; the service decides whether one is needed.
func decodeRecord(rec, sig string) ([]byte, []byte, error) {
	if rec == "" && sig == "" {
		return nil, nil, nil
	}
	if len(rec) > 2048 || len(sig) > 128 {
		return nil, nil, domain.E(domain.CodeInvalid, "malformed version record")
	}
	raw, err1 := base64.RawURLEncoding.Strict().DecodeString(rec)
	rs, err2 := base64.RawURLEncoding.Strict().DecodeString(sig)
	if err1 != nil || err2 != nil {
		return nil, nil, domain.E(domain.CodeInvalid, "malformed version record")
	}
	return raw, rs, nil
}

func (s *Server) handleRestoreVersion(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req struct {
		Record    string `json:"record"`
		RecordSig string `json:"recordSig"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	rec, sig, err := decodeRecord(req.Record, req.RecordSig)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	n, err := s.svc.RestoreVersion(r.Context(), p, r.PathValue("id"), r.PathValue("vid"), rec, sig)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, viewNode(n))
}

// ---- trash ---------------------------------------------------------------------------

func (s *Server) handleListTrash(w http.ResponseWriter, r *http.Request, p service.Principal) {
	entries, err := s.svc.ListTrash(r.Context(), p, r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	type item struct {
		nodeView
		ExpiresAt time.Time `json:"expiresAt"`
	}
	out := make([]item, len(entries))
	for i, e := range entries {
		out[i] = item{viewNode(e.Node), time.Unix(e.ExpiresAt, 0).UTC()}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) handleRestoreTrash(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req struct {
		ParentID string `json:"parentId"`
		entryReq
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	n, err := s.svc.Restore(r.Context(), p, r.PathValue("id"), service.RestoreRequest{ParentID: req.ParentID, Entry: req.entryReq.toService()})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, viewNode(n))
}

func (s *Server) handleDeleteTrash(w http.ResponseWriter, r *http.Request, p service.Principal) {
	if err := s.svc.DeletePermanently(r.Context(), p, r.PathValue("id")); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleEmptyTrash(w http.ResponseWriter, r *http.Request, p service.Principal) {
	n, err := s.svc.EmptyTrash(r.Context(), p, r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]int{"scheduled": n})
}

// ---- content delivery ------------------------------------------------------------------

// idleWriter extends the write deadline as data is sent to the client.
type idleWriter struct {
	http.ResponseWriter
	rc *http.ResponseController
	d  time.Duration
}

func (i *idleWriter) Write(p []byte) (int, error) {
	_ = i.rc.SetWriteDeadline(time.Now().Add(i.d))
	return i.ResponseWriter.Write(p)
}

// serveContainer sends an encrypted container. It is opaque bytes to the
// server and the browser alike (the web client decrypts it in script), so it
// is always an octet-stream attachment in a sandbox: nothing on our origin
// ever renders user-supplied content. Range requests are supported, which
// lets clients fetch individual 64 KiB chunks (e.g. to stream video).
func (s *Server) serveContainer(w http.ResponseWriter, r *http.Request, c *service.Content) {
	defer c.Close()
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	h.Set("Cache-Control", "private, no-cache")
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", `attachment; filename="`+c.Node.ID+`.fdenc"`)
	h.Set("ETag", `"`+c.Version.SHA256+`"`)
	h.Set("X-FrontDir-Version", c.Version.ID)
	if len(c.Version.Record) > 0 { // so a client can check freshness (docs/E2EE.md §5c)
		h.Set("X-FrontDir-Record", b64(c.Version.Record))
		h.Set("X-FrontDir-Record-Sig", b64(c.Version.RecordSig))
	}
	iw := &idleWriter{ResponseWriter: w, rc: http.NewResponseController(w), d: time.Minute}
	http.ServeContent(iw, r, "", c.Version.CreatedAt, c)
}

// ---- thumbnails (docs/E2EE.md §5a) ------------------------------------------------------

func (s *Server) handleGetThumbnails(w http.ResponseWriter, r *http.Request, p service.Principal) {
	set, err := s.svc.Thumbnails(r.Context(), p, r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	type thumbView struct {
		Maker string `json:"maker"`
		Enc   string `json:"enc"`
		Sig   string `json:"sig"`
	}
	out := make([]thumbView, len(set.Thumbnails))
	for i, t := range set.Thumbnails {
		out[i] = thumbView{Maker: t.MakerID, Enc: t.Enc, Sig: t.Sig}
	}
	// The version's prefix (always: the thumbnail key comes from its salt)
	// and, once known, the rest of its digest, so the client can verify
	// who the author is before showing their thumbnail (docs/E2EE.md §5b).
	v := viewVersion(set.Version)
	writeJSON(w, http.StatusOK, map[string]any{"versionId": v.ID, "prefix": b64(set.Version.Header),
		"bodyHash": v.BodyHash, "trailer": v.Trailer, "thumbnails": out})
}

func (s *Server) handlePutThumbnail(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req struct {
		VersionID string `json:"versionId"`
		Enc       string `json:"enc"`
		Sig       string `json:"sig"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.svc.AttachThumbnail(r.Context(), p, r.PathValue("id"), req.VersionID, req.Enc, req.Sig); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
