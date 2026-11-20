package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/woah-buddy/FrontDir/internal/domain"
	"github.com/woah-buddy/FrontDir/internal/service"
)

// File mailboxes (docs/E2EE.md §6a).

type mailboxView struct {
	ID           string     `json:"id"`
	NodeID       string     `json:"nodeId"`
	SpaceID      string     `json:"spaceId"`
	CreatedBy    string     `json:"createdBy"`
	CreatedAt    time.Time  `json:"createdAt"`
	BoxKey       string     `json:"boxKey"`
	Info         string     `json:"info"`
	HasPassword  bool       `json:"hasPassword"`
	ExpiresAt    time.Time  `json:"expiresAt"`
	MaxBytes     int64      `json:"maxBytes"`
	MaxFiles     int64      `json:"maxFiles"`
	AutoFile     bool       `json:"autoFile"`
	ClosedAt     *time.Time `json:"closedAt,omitempty"`
	Accepting    bool       `json:"accepting"`
	UsedBytes    int64      `json:"usedBytes"`
	UsedFiles    int64      `json:"usedFiles"`
	PendingFiles int64      `json:"pendingFiles"`
	PendingBytes int64      `json:"pendingBytes"`
}

func viewMailbox(m *domain.Mailbox) mailboxView {
	return mailboxView{ID: m.ID, NodeID: m.NodeID, SpaceID: m.SpaceID, CreatedBy: m.CreatedBy, CreatedAt: m.CreatedAt,
		BoxKey: m.BoxKey, Info: m.Info, HasPassword: m.PasswordHash != "", ExpiresAt: m.ExpiresAt, MaxBytes: m.MaxBytes,
		MaxFiles: m.MaxFiles, AutoFile: m.AutoFile, ClosedAt: m.ClosedAt, Accepting: m.Accepting(time.Now()),
		UsedBytes: m.UsedBytes, UsedFiles: m.UsedFiles, PendingFiles: m.PendingFiles, PendingBytes: m.PendingBytes}
}

func viewMailboxes(ms []*domain.Mailbox) []mailboxView {
	out := make([]mailboxView, len(ms))
	for i, m := range ms {
		out[i] = viewMailbox(m)
	}
	return out
}

func (s *Server) handleCreateMailbox(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req struct {
		ID        string    `json:"id"`
		BoxKey    string    `json:"boxKey"`
		Info      string    `json:"info"`
		Password  string    `json:"password"`
		ExpiresAt time.Time `json:"expiresAt"`
		MaxBytes  int64     `json:"maxBytes"`
		MaxFiles  int64     `json:"maxFiles"`
		AutoFile  bool      `json:"autoFile"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	m, token, err := s.svc.CreateMailbox(r.Context(), p, r.PathValue("id"), service.MailboxOptions{ID: req.ID, BoxKey: req.BoxKey,
		Info: req.Info, Password: req.Password, ExpiresAt: req.ExpiresAt, MaxBytes: req.MaxBytes, MaxFiles: req.MaxFiles, AutoFile: req.AutoFile})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	// The token is shown once; the client puts it in the link's fragment
	// next to the mailbox's public key.
	writeJSON(w, http.StatusCreated, map[string]any{"mailbox": viewMailbox(m), "token": token})
}

func (s *Server) handleFolderMailboxes(w http.ResponseWriter, r *http.Request, p service.Principal) {
	ms, err := s.svc.FolderMailboxes(r.Context(), p, r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mailboxes": viewMailboxes(ms)})
}

func (s *Server) handleMyMailboxes(w http.ResponseWriter, r *http.Request, p service.Principal) {
	ms, err := s.svc.MyMailboxes(r.Context(), p)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mailboxes": viewMailboxes(ms)})
}

type dropView struct {
	ID        string          `json:"id"`
	Header    json.RawMessage `json:"header"`
	Size      int64           `json:"size"`
	PlainSize int64           `json:"plainSize"`
	BodyHash  string          `json:"bodyHash"`
	CreatedAt time.Time       `json:"createdAt"`
}

func (s *Server) handleInbox(w http.ResponseWriter, r *http.Request, p service.Principal) {
	m, ds, err := s.svc.Inbox(r.Context(), p, r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	out := make([]dropView, len(ds))
	for i, d := range ds {
		out[i] = dropView{ID: d.ID, Header: d.Header, Size: d.Size, PlainSize: d.PlainSize, BodyHash: b64(d.BodyHash), CreatedAt: d.CreatedAt}
	}
	writeJSON(w, http.StatusOK, map[string]any{"mailbox": viewMailbox(m), "drops": out})
}

func (s *Server) handleCloseMailbox(w http.ResponseWriter, r *http.Request, p service.Principal) {
	if err := s.svc.CloseMailbox(r.Context(), p, r.PathValue("id")); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleDropContent sends a pending drop's encrypted body, for review. Like
// every container it is an inert, sandboxed octet-stream attachment.
func (s *Server) handleDropContent(w http.ResponseWriter, r *http.Request, p service.Principal) {
	d, rc, err := s.svc.DropContent(r.Context(), p, r.PathValue("id"), r.PathValue("did"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	defer rc.Close()
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	h.Set("Cache-Control", "private, no-store")
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", `attachment; filename="`+d.ID+`.drop"`)
	http.ServeContent(w, r, "", d.CreatedAt, rc)
}

func (s *Server) handleDiscardDrop(w http.ResponseWriter, r *http.Request, p service.Principal) {
	if err := s.svc.DiscardDrop(r.Context(), p, r.PathValue("id"), r.PathValue("did")); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleFileDrop(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req struct {
		ID string `json:"id"`
		entryReq
		Prefix    string `json:"prefix"`
		Trailer   string `json:"trailer"`
		Record    string `json:"record"`
		RecordSig string `json:"recordSig"`
	}
	if err := decodeJSONLimit(w, r, &req, 256<<10); err != nil {
		s.writeError(w, r, err)
		return
	}
	prefix, err1 := base64.RawURLEncoding.Strict().DecodeString(req.Prefix)
	trailer, err2 := base64.RawURLEncoding.Strict().DecodeString(req.Trailer)
	rec, sig, err3 := decodeRecord(req.Record, req.RecordSig)
	if err1 != nil || err2 != nil {
		s.writeError(w, r, domain.E(domain.CodeInvalid, "malformed container prefix or trailer"))
		return
	}
	if err3 != nil {
		s.writeError(w, r, err3)
		return
	}
	n, err := s.svc.FileDrop(r.Context(), p, r.PathValue("id"), r.PathValue("did"), service.FileDropRequest{
		NewID: req.ID, Entry: req.entryReq.toService(), Prefix: prefix, Trailer: trailer, Record: rec, RecordSig: sig})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, viewNode(n))
}

// ---- anonymous senders ----------------------------------------------------------------
// The token travels in a request body or header, never in a URL; the
// mailbox's public key never reaches the server at all.

func (s *Server) handlePublicMailbox(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	v, err := s.svc.MailboxForSender(r.Context(), service.MailboxCredential{Token: req.Token, Password: req.Password})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": v.ID, "info": v.Info, "expiresAt": v.ExpiresAt,
		"maxFileSize": v.MaxFileSize, "remainingBytes": v.Remaining, "filesLeft": v.FilesLeft})
}

// handleDrop takes one drop: the header in X-FrontDir-Drop, the body as
// the request body. The response says only that it was accepted.
func (s *Server) handleDrop(w http.ResponseWriter, r *http.Request) {
	cred := service.MailboxCredential{Token: r.Header.Get("X-FrontDir-Mailbox"), Password: r.Header.Get("X-FrontDir-Mailbox-Password")}
	header := []byte(r.Header.Get("X-FrontDir-Drop"))
	body := &idleReader{r: r.Body, rc: http.NewResponseController(w), d: time.Minute}
	if err := s.svc.Drop(r.Context(), cred, header, r.ContentLength, body); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
