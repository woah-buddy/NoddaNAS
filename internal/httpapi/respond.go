package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/woah-buddy/NoddaNAS/internal/domain"
	"github.com/woah-buddy/NoddaNAS/internal/service"
)

const maxJSONBody = 64 << 10

// decodeJSON parses a small JSON object strictly: bounded size, unknown
// fields rejected, exactly one value.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	return decodeJSONLimit(w, r, dst, maxJSONBody)
}

// decodeJSONLimit is decodeJSON with a different size bound.
func decodeJSONLimit(w http.ResponseWriter, r *http.Request, dst any, limit int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return domain.E(domain.CodeTooLarge, "request body too large")
		}
		return domain.E(domain.CodeInvalid, "malformed JSON body")
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
	domain.CodeReauth:       http.StatusForbidden,
	domain.CodeNotFound:     http.StatusNotFound,
	domain.CodeConflict:     http.StatusConflict,
	domain.CodeConfirm:      http.StatusConflict,
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

// writeError sends a client-safe error. Only *domain.Error messages reach
// clients; anything else becomes a generic 500 logged with a request ID.
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
// Views are explicit allowlists of fields: domain structs are never encoded
// directly. With E2EE, every name and key field here is client ciphertext.

type nodeView struct {
	ID         string     `json:"id"`
	ParentID   string     `json:"parentId,omitempty"`
	SpaceID    string     `json:"spaceId"`
	Kind       string     `json:"kind"`
	NameEnc    string     `json:"nameEnc,omitempty"`
	NameHash   string     `json:"nameHash,omitempty"`
	WrappedKey string     `json:"wrappedKey,omitempty"`
	Size       int64      `json:"size"`
	PlainSize  int64      `json:"plainSize"`
	SHA256     string     `json:"sha256,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
	CreatedBy  string     `json:"createdBy"`
	ModifiedAt time.Time  `json:"modifiedAt"`
	ModifiedBy string     `json:"modifiedBy"`
	Revision   int64      `json:"revision"`
	TrashedAt  *time.Time `json:"trashedAt,omitempty"`
	TrashedBy  string     `json:"trashedBy,omitempty"`
	RestoreKey string     `json:"restoreKey,omitempty"`
	RestoreSig string     `json:"restoreSig,omitempty"`
	Permission string     `json:"permission,omitempty"`
	CanModify  *bool      `json:"canModify,omitempty"`
}

func viewNode(n *domain.Node) nodeView {
	return nodeView{
		ID: n.ID, ParentID: n.ParentID, SpaceID: n.SpaceID, Kind: string(n.Kind), NameEnc: n.NameEnc,
		NameHash: n.NameHash, WrappedKey: n.WrappedKey, Size: n.Size, PlainSize: n.PlainSize, SHA256: n.SHA256, CreatedAt: n.CreatedAt,
		CreatedBy: n.CreatedBy, ModifiedAt: n.ModifiedAt, ModifiedBy: n.ModifiedBy, Revision: n.Revision,
		TrashedAt: n.TrashedAt, TrashedBy: n.TrashedBy, RestoreKey: n.RestoreKey, RestoreSig: n.RestoreSig,
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

// publicNodeView is what anonymous link visitors see: no user IDs.
type publicNodeView struct {
	ID         string    `json:"id"`
	ParentID   string    `json:"parentId,omitempty"`
	Kind       string    `json:"kind"`
	NameEnc    string    `json:"nameEnc,omitempty"`
	WrappedKey string    `json:"wrappedKey,omitempty"`
	Size       int64     `json:"size"`
	PlainSize  int64     `json:"plainSize"`
	ModifiedAt time.Time `json:"modifiedAt"`
}

func viewPublic(n *domain.Node) publicNodeView {
	return publicNodeView{ID: n.ID, ParentID: n.ParentID, Kind: string(n.Kind), NameEnc: n.NameEnc,
		WrappedKey: n.WrappedKey, Size: n.Size, PlainSize: n.PlainSize, ModifiedAt: n.ModifiedAt}
}

type keysView struct {
	Enc     string `json:"enc"`
	Sig     string `json:"sig"`
	SelfSig string `json:"selfSig"`
}

func viewKeys(k *domain.PublicKeys) *keysView {
	if k == nil {
		return nil
	}
	return &keysView{Enc: k.Enc, Sig: k.Sig, SelfSig: k.SelfSig}
}

type grantView struct {
	Grant     string `json:"grant"`
	GrantSig  string `json:"grantSig"`
	GrantedBy string `json:"grantedBy"`
}

type spaceView struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind"`
	RootID     string     `json:"rootId"`
	NameEnc    string     `json:"nameEnc,omitempty"`
	PublicKey  string     `json:"publicKey,omitempty"`
	KeySig     string     `json:"keySig,omitempty"`
	KeySigner  string     `json:"keySigner,omitempty"`
	RootKey    string     `json:"rootKey,omitempty"`
	QuotaBytes int64      `json:"quotaBytes"`
	UsedBytes  int64      `json:"usedBytes"`
	CreatedAt  time.Time  `json:"createdAt"`
	CreatedBy  string     `json:"createdBy"`
	Role       string     `json:"role,omitempty"`
	MyGrant    *grantView `json:"myGrant,omitempty"`
}

func viewSpace(sp *domain.Space, role domain.Role, m *domain.Membership) spaceView {
	v := spaceView{ID: sp.ID, Kind: string(sp.Kind), RootID: sp.RootID, NameEnc: sp.NameEnc, PublicKey: sp.PublicKey,
		KeySig: sp.KeySig, KeySigner: sp.KeySigner, QuotaBytes: sp.QuotaBytes, UsedBytes: sp.UsedBytes,
		CreatedAt: sp.CreatedAt, CreatedBy: sp.CreatedBy, Role: string(role)}
	if role != domain.RoleNone {
		v.RootKey = sp.RootKey // useless without the space secret, so only members need it
	}
	if m != nil && m.Grant != "" {
		v.MyGrant = &grantView{Grant: m.Grant, GrantSig: m.GrantSig, GrantedBy: m.GrantedBy}
	}
	return v
}

func viewSpaceInfo(i *service.SpaceInfo) spaceView { return viewSpace(i.Space, i.Role, i.Membership) }

type memberView struct {
	UserID      string    `json:"userId"`
	DisplayName string    `json:"displayName"`
	Email       string    `json:"email,omitempty"`
	Keys        *keysView `json:"keys,omitempty"`
	DirectRole  string    `json:"directRole,omitempty"`
	GroupRoles  []string  `json:"groupRoles,omitempty"`
	Role        string    `json:"role"`
	HasGrant    bool      `json:"hasGrant"`
	GrantedBy   string    `json:"grantedBy,omitempty"`
}

func viewMember(m *domain.Member) memberView {
	v := memberView{UserID: m.UserID, DisplayName: m.DisplayName, Email: m.Email, Keys: viewKeys(m.Keys),
		DirectRole: string(m.DirectRole), Role: string(m.Role()), HasGrant: m.Grant != "", GrantedBy: m.GrantedBy}
	for _, r := range m.GroupRoles {
		v.GroupRoles = append(v.GroupRoles, string(r))
	}
	return v
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
	SpaceID      string     `json:"spaceId"`
	Permission   string     `json:"permission"`
	CreatedAt    time.Time  `json:"createdAt"`
	CreatedBy    string     `json:"createdBy"`
	RecipientID  string     `json:"recipientId,omitempty"`
	SealedKey    string     `json:"sealedKey,omitempty"`
	Sig          string     `json:"sig,omitempty"`
	LinkKey      string     `json:"linkKey,omitempty"`
	HasPassword  bool       `json:"hasPassword,omitempty"`
	ExpiresAt    *time.Time `json:"expiresAt,omitempty"`
	MaxDownloads int64      `json:"maxDownloads,omitempty"`
	Downloads    int64      `json:"downloads,omitempty"`
}

func viewShare(s *domain.Share) shareView {
	return shareView{
		ID: s.ID, Type: string(s.Kind), NodeID: s.NodeID, SpaceID: s.SpaceID, Permission: string(s.Permission),
		CreatedAt: s.CreatedAt, CreatedBy: s.CreatedBy, RecipientID: s.RecipientID, SealedKey: s.SealedKey,
		Sig: s.ShareSig, LinkKey: s.LinkKey, HasPassword: s.PasswordHash != "", ExpiresAt: s.ExpiresAt,
		MaxDownloads: s.MaxDownloads, Downloads: s.Downloads,
	}
}

type userView struct {
	ID          string    `json:"id"`
	Email       string    `json:"email,omitempty"`
	DisplayName string    `json:"displayName"`
	Admin       bool      `json:"admin,omitempty"`
	Keys        *keysView `json:"keys,omitempty"`
}
