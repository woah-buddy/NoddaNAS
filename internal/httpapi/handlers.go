package httpapi

import (
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/woah-buddy/NoddaNAS/internal/auth"
	"github.com/woah-buddy/NoddaNAS/internal/domain"
	"github.com/woah-buddy/NoddaNAS/internal/service"
)

// ---- browser sign-in -----------------------------------------------------------

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	u, cookie, err := s.auth.BeginLogin(r.Context(), r.URL.Query().Get("return_to"))
	if err != nil {
		s.log.ErrorContext(r.Context(), "login unavailable", "err", err, "request_id", requestID(r.Context()))
		http.Error(w, "Sign-in is temporarily unavailable.", http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, u, http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, auth.ClearLoginCookie())
	user, returnTo, err := s.auth.CompleteLogin(r)
	if err != nil {
		s.log.WarnContext(r.Context(), "audit", "event", "login.failed", "err", err, "request_id", requestID(r.Context()),
			"ip", s.clientIP(r).String())
		reason := "signin"
		if errors.Is(err, auth.ErrNotAllowed) {
			reason = "not_allowed"
		}
		http.Redirect(w, r, "/?error="+reason, http.StatusSeeOther)
		return
	}
	// Discard any session the browser already had, then mint a new one.
	_ = s.auth.EndSession(r)
	cookie, err := s.auth.StartSession(r.Context(), user.ID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.log.InfoContext(r.Context(), "audit", "event", "login.success", "user", user.ID, "ip", s.clientIP(r).String())
	http.SetCookie(w, cookie)
	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, s.auth.EndSession(r))
	writeJSON(w, http.StatusOK, map[string]string{"logoutUrl": s.auth.LogoutURL(r.Context())})
}

// ---- account -------------------------------------------------------------------

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, p service.Principal) {
	u, err := s.svc.Me(r.Context(), p)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user": userView{ID: u.ID, Email: u.Email, DisplayName: u.DisplayName, RootID: u.RootID,
			QuotaBytes: u.QuotaBytes, UsedBytes: u.UsedBytes},
		"readOnly": p.ReadOnly,
	})
}

type appPasswordView struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	ReadOnly   bool       `json:"readOnly"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
}

func viewAppPassword(a *domain.AppPassword) appPasswordView {
	return appPasswordView{ID: a.ID, Name: a.Name, ReadOnly: a.ReadOnly, CreatedAt: a.CreatedAt, LastUsedAt: a.LastUsedAt, ExpiresAt: a.ExpiresAt}
}

func (s *Server) handleListAppPasswords(w http.ResponseWriter, r *http.Request, p service.Principal) {
	aps, err := s.auth.ListAppPasswords(r.Context(), p.UserID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	out := make([]appPasswordView, len(aps))
	for i, a := range aps {
		out[i] = viewAppPassword(a)
	}
	writeJSON(w, http.StatusOK, map[string]any{"appPasswords": out})
}

func (s *Server) handleCreateAppPassword(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req struct {
		Name          string `json:"name"`
		ReadOnly      bool   `json:"readOnly"`
		ExpiresInDays int    `json:"expiresInDays"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	ap, token, err := s.auth.CreateAppPassword(r.Context(), p.UserID, req.Name, req.ReadOnly,
		time.Duration(req.ExpiresInDays)*24*time.Hour)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.log.InfoContext(r.Context(), "audit", "event", "app_password.create", "user", p.UserID, "id", ap.ID, "read_only", ap.ReadOnly)
	writeJSON(w, http.StatusCreated, map[string]any{"appPassword": viewAppPassword(ap), "token": token})
}

func (s *Server) handleRevokeAppPassword(w http.ResponseWriter, r *http.Request, p service.Principal) {
	if err := s.auth.RevokeAppPassword(r.Context(), p.UserID, r.PathValue("id")); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.log.InfoContext(r.Context(), "audit", "event", "app_password.revoke", "user", p.UserID, "id", r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRevokeAllSessions(w http.ResponseWriter, r *http.Request, p service.Principal) {
	if err := s.auth.EndAllSessions(r.Context(), p.UserID); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.log.InfoContext(r.Context(), "audit", "event", "sessions.revoke_all", "user", p.UserID)
	http.SetCookie(w, s.auth.EndSession(r))
	w.WriteHeader(http.StatusNoContent)
}

// ---- files and folders -----------------------------------------------------------

func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request, p service.Principal) {
	info, err := s.svc.GetNode(r.Context(), p, r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, viewInfo(info))
}

// Cursors are opaque to clients. They are only ever used as a sort-key
// lower bound inside an already-authorized folder, so a forged cursor can
// at most skip entries the caller could see anyway.
func decodeCursor(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) > 1024 {
		return "", domain.E(domain.CodeInvalid, "invalid cursor")
	}
	return string(b), nil
}

func encodeCursor(s string) string {
	if s == "" {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func queryInt(r *http.Request, key string) int64 {
	n, _ := strconv.ParseInt(r.URL.Query().Get(key), 10, 64)
	return n
}

func (s *Server) handleListChildren(w http.ResponseWriter, r *http.Request, p service.Principal) {
	cursor, err := decodeCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	info, children, next, err := s.svc.ListChildren(r.Context(), p, r.PathValue("id"), cursor, int(queryInt(r, "limit")))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"node": viewInfo(info), "children": viewNodes(children), "nextCursor": encodeCursor(next)})
}

func (s *Server) handleCreateFolder(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	n, err := s.svc.CreateFolder(r.Context(), p, r.PathValue("id"), req.Name)
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

func (s *Server) upload(w http.ResponseWriter, r *http.Request, p service.Principal, req service.UploadRequest, status int) {
	req.Size = r.ContentLength
	req.SHA256 = r.Header.Get("X-Content-SHA256")
	req.ContentType = r.Header.Get("Content-Type")
	body := &idleReader{r: r.Body, rc: http.NewResponseController(w), d: time.Minute}
	n, err := s.svc.Upload(r.Context(), p, req, body)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, status, viewNode(n))
}

// handleUploadNew stores a new file in folder {id}: POST ...?name=x[&overwrite=true]
func (s *Server) handleUploadNew(w http.ResponseWriter, r *http.Request, p service.Principal) {
	q := r.URL.Query()
	s.upload(w, r, p, service.UploadRequest{ParentID: r.PathValue("id"), Name: q.Get("name"),
		Overwrite: q.Get("overwrite") == "true"}, http.StatusCreated)
}

// handleUploadVersion stores a new version of file {id}: PUT ...[?revision=n]
func (s *Server) handleUploadVersion(w http.ResponseWriter, r *http.Request, p service.Principal) {
	s.upload(w, r, p, service.UploadRequest{NodeID: r.PathValue("id"), Revision: queryInt(r, "revision")}, http.StatusOK)
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request, p service.Principal) {
	c, err := s.svc.OpenContent(r.Context(), p, r.PathValue("id"), r.URL.Query().Get("version"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.serveContent(w, r, c, r.URL.Query().Get("inline") == "1")
}

func (s *Server) handleUpdateNode(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req struct {
		Name     *string `json:"name"`
		ParentID *string `json:"parentId"`
		Revision int64   `json:"revision"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	n, err := s.svc.Update(r.Context(), p, r.PathValue("id"), service.UpdateRequest{Name: req.Name, ParentID: req.ParentID, Revision: req.Revision})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, viewNode(n))
}

func (s *Server) handleTrashNode(w http.ResponseWriter, r *http.Request, p service.Principal) {
	if err := s.svc.Trash(r.Context(), p, r.PathValue("id"), queryInt(r, "revision")); err != nil {
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
		out[i] = versionView{ID: v.ID, Size: v.Size, SHA256: v.SHA256, CreatedAt: v.CreatedAt, CreatedBy: v.CreatedBy}
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": out})
}

func (s *Server) handleRestoreVersion(w http.ResponseWriter, r *http.Request, p service.Principal) {
	n, err := s.svc.RestoreVersion(r.Context(), p, r.PathValue("id"), r.PathValue("vid"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, viewNode(n))
}

// ---- trash ---------------------------------------------------------------------------

func (s *Server) handleListTrash(w http.ResponseWriter, r *http.Request, p service.Principal) {
	entries, err := s.svc.ListTrash(r.Context(), p)
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
		out[i] = item{viewNode(e.Node), e.ExpiresAt}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) handleRestoreTrash(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req struct {
		Name *string `json:"name"`
	}
	if r.ContentLength != 0 {
		if err := decodeJSON(w, r, &req); err != nil {
			s.writeError(w, r, err)
			return
		}
	}
	n, err := s.svc.Restore(r.Context(), p, r.PathValue("id"), req.Name)
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
	n, err := s.svc.EmptyTrash(r.Context(), p)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]int{"scheduled": n})
}

// ---- sharing ---------------------------------------------------------------------------

func (s *Server) handleListShares(w http.ResponseWriter, r *http.Request, p service.Principal) {
	shares, err := s.svc.ListShares(r.Context(), p, r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	out := make([]shareView, len(shares))
	for i, sh := range shares {
		out[i] = viewShare(sh)
	}
	writeJSON(w, http.StatusOK, map[string]any{"shares": out})
}

func (s *Server) handleCreateShare(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req struct {
		Type         string     `json:"type"`
		Email        string     `json:"email"`
		Permission   string     `json:"permission"`
		Password     string     `json:"password"`
		ExpiresAt    *time.Time `json:"expiresAt"`
		MaxDownloads int64      `json:"maxDownloads"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	switch req.Type {
	case "user":
		sh, err := s.svc.ShareWithUser(r.Context(), p, r.PathValue("id"), req.Email, domain.Permission(req.Permission))
		if err != nil {
			s.writeError(w, r, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"share": viewShare(sh)})
	case "link":
		sh, token, err := s.svc.CreateLink(r.Context(), p, r.PathValue("id"), service.LinkOptions{
			Password: req.Password, ExpiresAt: req.ExpiresAt, MaxDownloads: req.MaxDownloads})
		if err != nil {
			s.writeError(w, r, err)
			return
		}
		// The token lives in the URL fragment (#...), which browsers never
		// send to servers: it stays out of access logs and Referer headers.
		link := s.cfg.PublicURL.Scheme + "://" + s.cfg.PublicURL.Host + "/s#" + token
		writeJSON(w, http.StatusCreated, map[string]any{"share": viewShare(sh), "token": token, "url": link})
	default:
		s.writeError(w, r, domain.E(domain.CodeInvalid, `type must be "user" or "link"`))
	}
}

func (s *Server) handleDeleteShare(w http.ResponseWriter, r *http.Request, p service.Principal) {
	if err := s.svc.DeleteShare(r.Context(), p, r.PathValue("id")); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSharedWithMe(w http.ResponseWriter, r *http.Request, p service.Principal) {
	items, err := s.svc.SharedWithMe(r.Context(), p)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	type item struct {
		Share shareView `json:"share"`
		Node  nodeView  `json:"node"`
	}
	out := make([]item, len(items))
	for i, it := range items {
		out[i] = item{viewShare(it.Share), viewInfo(it.Node)}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// ---- public links ------------------------------------------------------------------------

func (s *Server) handlePublicNode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
		NodeID   string `json:"nodeId"`
		Cursor   string `json:"cursor"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	cred := service.LinkCredential{Token: req.Token, Password: req.Password}
	sh, n, err := s.svc.LinkNode(r.Context(), cred, req.NodeID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	resp := map[string]any{
		"node":      viewPublic(n),
		"rootId":    sh.NodeID,
		"expiresAt": sh.ExpiresAt,
	}
	if n.Kind == domain.KindFolder {
		cursor, err := decodeCursor(req.Cursor)
		if err != nil {
			s.writeError(w, r, err)
			return
		}
		_, children, next, err := s.svc.LinkChildren(r.Context(), cred, n.ID, cursor, 0)
		if err != nil {
			s.writeError(w, r, err)
			return
		}
		pub := make([]publicNodeView, len(children))
		for i, c := range children {
			pub[i] = viewPublic(c)
		}
		resp["children"], resp["nextCursor"] = pub, encodeCursor(next)
	}
	writeJSON(w, http.StatusOK, resp)
}

// handlePublicDownload accepts a same-origin form POST, so the browser can
// save the response as a file while the token stays out of the URL.
func (s *Server) handlePublicDownload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		s.writeError(w, r, domain.E(domain.CodeInvalid, "malformed form"))
		return
	}
	cred := service.LinkCredential{Token: r.PostForm.Get("token"), Password: r.PostForm.Get("password")}
	c, err := s.svc.LinkOpen(r.Context(), cred, r.PostForm.Get("nodeId"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.serveContent(w, r, c, false)
}

// ---- content delivery ----------------------------------------------------------------------

// Only passive media may be displayed inline. Everything else (HTML, SVG,
// PDF, scripts, unknown types) is forced to download, because rendering
// user-supplied active content on our origin is a stored-XSS vulnerability.
var inlineSafe = map[string]bool{
	"image/png": true, "image/jpeg": true, "image/gif": true, "image/webp": true, "image/avif": true,
	"video/mp4": true, "video/webm": true, "audio/mpeg": true, "audio/ogg": true, "audio/wav": true,
	"audio/flac": true, "audio/mp4": true,
}

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

func (s *Server) serveContent(w http.ResponseWriter, r *http.Request, c *service.Content, inline bool) {
	defer c.Close()
	h := w.Header()
	// Even if a browser were tricked into rendering this response, the
	// sandbox CSP gives it a unique opaque origin with scripts disabled.
	h.Set("Content-Security-Policy", "default-src 'none'; img-src 'self'; media-src 'self'; style-src 'unsafe-inline'; sandbox")
	h.Set("Cache-Control", "private, no-cache")
	h.Set("ETag", `"`+c.Version.SHA256+`"`)
	ctype, disp := "application/octet-stream", "attachment"
	if inline && inlineSafe[c.Node.ContentType] {
		ctype, disp = c.Node.ContentType, "inline"
	}
	h.Set("Content-Type", ctype)
	if cd := mime.FormatMediaType(disp, map[string]string{"filename": c.Node.Name}); cd != "" {
		h.Set("Content-Disposition", cd)
	} else {
		h.Set("Content-Disposition", disp)
	}
	iw := &idleWriter{ResponseWriter: w, rc: http.NewResponseController(w), d: time.Minute}
	http.ServeContent(iw, r, "", c.Version.CreatedAt, c)
}
