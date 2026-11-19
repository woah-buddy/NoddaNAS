package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/woah-buddy/NoddaNAS/internal/domain"
	"github.com/woah-buddy/NoddaNAS/internal/service"
)

const maxJSONBody = 64 << 10

// decodeJSON parses a small JSON object strictly: bounded size, unknown
// fields rejected, exactly one value. Strict parsing turns client mistakes
// (and probing) into clear 400s instead of silently ignored input.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return domain.E(domain.CodeTooLarge, "request body too large")
		}
		return domain.E(domain.CodeInvalid, "malformed JSON body")
	}
	if dec.More() {
		return domain.E(domain.CodeInvalid, "request body must contain a single JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return domain.E(domain.CodeInvalid, "request body must contain a single JSON object")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

var statusOf = map[domain.Code]int{
	domain.CodeInvalid:      http.StatusBadRequest,
	domain.CodeUnauthorized: http.StatusUnauthorized,
	domain.CodeForbidden:    http.StatusForbidden,
	domain.CodeNotFound:     http.StatusNotFound,
	domain.CodeConflict:     http.StatusConflict,
	domain.CodeGone:         http.StatusGone,
	domain.CodePrecondition: http.StatusPreconditionFailed,
	domain.CodeTooLarge:     http.StatusRequestEntityTooLarge,
	domain.CodeRateLimited:  http.StatusTooManyRequests,
	domain.CodeQuota:        http.StatusInsufficientStorage,
}

type errorBody struct {
	Code      domain.Code       `json:"code"`
	Message   string            `json:"message"`
	Detail    map[string]string `json:"detail,omitempty"`
	RequestID string            `json:"requestId,omitempty"`
}

// writeError sends a client-safe error. Only *domain.Error messages are ever
// shown to clients; anything else becomes a generic 500 and its details go
// to the log, tagged with the request ID the client sees.
func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	rid := requestID(r.Context())
	var de *domain.Error
	if errors.As(err, &de) {
		status := statusOf[de.Code]
		if status == 0 {
			status = http.StatusInternalServerError
		}
		if status == http.StatusUnauthorized && r.Header.Get("Authorization") != "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="NoddaNAS", charset="UTF-8"`)
		}
		msg := de.Message
		if msg == "" {
			msg = http.StatusText(status)
		}
		writeJSON(w, status, map[string]errorBody{"error": {Code: de.Code, Message: msg, Detail: de.Detail, RequestID: rid}})
		return
	}
	s.log.ErrorContext(r.Context(), "internal error", "err", err, "request_id", rid)
	writeJSON(w, http.StatusInternalServerError, map[string]errorBody{"error": {
		Code: "internal", Message: "internal server error", RequestID: rid}})
}

// ---- JSON views ------------------------------------------------------------
// Views are explicit allowlists of fields. Domain structs are never encoded
// directly, so adding a sensitive field to one (a key, a hash) can never leak
// it through the API by accident.

type nodeView struct {
	ID          string     `json:"id"`
	ParentID    string     `json:"parentId,omitempty"`
	OwnerID     string     `json:"ownerId"`
	Name        string     `json:"name"`
	Kind        string     `json:"kind"`
	Size        int64      `json:"size"`
	ContentType string     `json:"contentType,omitempty"`
	SHA256      string     `json:"sha256,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
	ModifiedAt  time.Time  `json:"modifiedAt"`
	Revision    int64      `json:"revision"`
	TrashedAt   *time.Time `json:"trashedAt,omitempty"`
	Permission  string     `json:"permission,omitempty"`
	CanModify   *bool      `json:"canModify,omitempty"`
}

func viewNode(n *domain.Node) nodeView {
	return nodeView{
		ID: n.ID, ParentID: n.ParentID, OwnerID: n.OwnerID, Name: n.Name, Kind: string(n.Kind), Size: n.Size,
		ContentType: n.ContentType, SHA256: n.SHA256, CreatedAt: n.CreatedAt, ModifiedAt: n.ModifiedAt,
		Revision: n.Revision, TrashedAt: n.TrashedAt,
	}
}

func viewInfo(i *service.NodeInfo) nodeView {
	v := viewNode(i.Node)
	v.Permission = string(i.Permission)
	v.CanModify = &i.CanModifyEntry
	return v
}

func viewNodes(ns []*domain.Node) []nodeView {
	out := make([]nodeView, len(ns))
	for i, n := range ns {
		out[i] = viewNode(n)
	}
	return out
}

// publicNodeView omits owner and internal metadata for anonymous visitors.
type publicNodeView struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Kind        string    `json:"kind"`
	Size        int64     `json:"size"`
	ContentType string    `json:"contentType,omitempty"`
	ModifiedAt  time.Time `json:"modifiedAt"`
}

func viewPublic(n *domain.Node) publicNodeView {
	return publicNodeView{ID: n.ID, Name: n.Name, Kind: string(n.Kind), Size: n.Size, ContentType: n.ContentType, ModifiedAt: n.ModifiedAt}
}

type versionView struct {
	ID        string    `json:"id"`
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256"`
	CreatedAt time.Time `json:"createdAt"`
	CreatedBy string    `json:"createdBy"`
}

type shareView struct {
	ID           string     `json:"id"`
	Type         string     `json:"type"`
	NodeID       string     `json:"nodeId"`
	Permission   string     `json:"permission"`
	CreatedAt    time.Time  `json:"createdAt"`
	RecipientID  string     `json:"recipientId,omitempty"`
	HasPassword  bool       `json:"hasPassword,omitempty"`
	ExpiresAt    *time.Time `json:"expiresAt,omitempty"`
	MaxDownloads int64      `json:"maxDownloads,omitempty"`
	Downloads    int64      `json:"downloads,omitempty"`
}

func viewShare(s *domain.Share) shareView {
	return shareView{
		ID: s.ID, Type: string(s.Kind), NodeID: s.NodeID, Permission: string(s.Permission), CreatedAt: s.CreatedAt,
		RecipientID: s.RecipientID, HasPassword: s.PasswordHash != "", ExpiresAt: s.ExpiresAt,
		MaxDownloads: s.MaxDownloads, Downloads: s.Downloads,
	}
}

type userView struct {
	ID          string `json:"id"`
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"displayName"`
	RootID      string `json:"rootId"`
	QuotaBytes  int64  `json:"quotaBytes"`
	UsedBytes   int64  `json:"usedBytes"`
}

func (s *Server) logAttrs(r *http.Request) []any {
	return []any{slog.String("request_id", requestID(r.Context()))}
}
