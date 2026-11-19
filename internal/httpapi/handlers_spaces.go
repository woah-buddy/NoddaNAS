package httpapi

import (
	"net/http"
	"time"

	"github.com/woah-buddy/NoddaNAS/internal/domain"
	"github.com/woah-buddy/NoddaNAS/internal/service"
)

// ---- spaces and team folders ------------------------------------------------------

func (s *Server) handleListSpaces(w http.ResponseWriter, r *http.Request, p service.Principal) {
	spaces, err := s.svc.ListSpaces(r.Context(), p)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	out := make([]spaceView, len(spaces))
	for i := range spaces {
		out[i] = viewSpaceInfo(&spaces[i])
	}
	writeJSON(w, http.StatusOK, map[string]any{"spaces": out})
}

func (s *Server) handleGetSpace(w http.ResponseWriter, r *http.Request, p service.Principal) {
	info, err := s.svc.GetSpace(r.Context(), p, r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, viewSpaceInfo(info))
}

func (s *Server) handleCreateTeam(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req struct {
		ID       string       `json:"id"`
		RootID   string       `json:"rootId"`
		NameEnc  string       `json:"nameEnc"`
		Keys     spaceKeysReq `json:"keys"`
		Grant    string       `json:"grant"`
		GrantSig string       `json:"grantSig"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	sp, err := s.svc.CreateTeam(r.Context(), p, service.NewTeam{ID: req.ID, RootID: req.RootID, NameEnc: req.NameEnc,
		Keys: req.Keys.toService(), Grant: req.Grant, GrantSig: req.GrantSig})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, viewSpace(sp, domain.RoleManage, nil))
}

func (s *Server) handleRenameTeam(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req struct {
		NameEnc string `json:"nameEnc"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.svc.RenameTeam(r.Context(), p, r.PathValue("id"), req.NameEnc); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteTeam(w http.ResponseWriter, r *http.Request, p service.Principal) {
	if err := s.svc.DeleteTeam(r.Context(), p, r.PathValue("id")); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleListMembers(w http.ResponseWriter, r *http.Request, p service.Principal) {
	members, err := s.svc.ListMembers(r.Context(), p, r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	out := make([]memberView, len(members))
	for i, m := range members {
		out[i] = viewMember(m)
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": out})
}

func (s *Server) handleUpdateMember(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req struct {
		Role     *string `json:"role"`
		Grant    string  `json:"grant"`
		GrantSig string  `json:"grantSig"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	u := service.MemberUpdate{Grant: req.Grant, GrantSig: req.GrantSig}
	if req.Role != nil {
		role := domain.Role(*req.Role)
		u.Role = &role
	}
	if err := s.svc.UpdateMember(r.Context(), p, r.PathValue("id"), r.PathValue("user"), u); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRemoveMember(w http.ResponseWriter, r *http.Request, p service.Principal) {
	if err := s.svc.RemoveMember(r.Context(), p, r.PathValue("id"), r.PathValue("user")); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request, p service.Principal) {
	ms, err := s.svc.ListGroupMappings(r.Context(), p, r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	type gv struct {
		Group string `json:"group"`
		Role  string `json:"role"`
	}
	out := make([]gv, len(ms))
	for i, m := range ms {
		out[i] = gv{m.Group, string(m.Role)}
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": out})
}

func (s *Server) handleSetGroup(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req struct {
		Role string `json:"role"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.svc.SetGroupMapping(r.Context(), p, r.PathValue("id"), r.PathValue("group"), domain.Role(req.Role)); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request, p service.Principal) {
	if err := s.svc.DeleteGroupMapping(r.Context(), p, r.PathValue("id"), r.PathValue("group")); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSetQuota(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req struct {
		Bytes int64 `json:"bytes"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.svc.AdminSetQuota(r.Context(), p, r.PathValue("id"), req.Bytes); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdminListTeams(w http.ResponseWriter, r *http.Request, p service.Principal) {
	spaces, err := s.svc.AdminListTeams(r.Context(), p)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	out := make([]spaceView, len(spaces))
	for i, sp := range spaces {
		out[i] = viewSpace(sp, domain.RoleNone, nil)
	}
	writeJSON(w, http.StatusOK, map[string]any{"spaces": out})
}

// ---- sharing --------------------------------------------------------------------------

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
		ShareID      string     `json:"shareId"`
		RecipientID  string     `json:"recipientId"`
		Permission   string     `json:"permission"`
		SealedKey    string     `json:"sealedKey"`
		Sig          string     `json:"sig"`
		LinkKey      string     `json:"linkKey"`
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
		sh, err := s.svc.ShareWithUser(r.Context(), p, r.PathValue("id"), service.NewUserShare{ShareID: req.ShareID,
			RecipientID: req.RecipientID, Permission: domain.Permission(req.Permission), SealedKey: req.SealedKey, Sig: req.Sig})
		if err != nil {
			s.writeError(w, r, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"share": viewShare(sh)})
	case "link":
		sh, token, err := s.svc.CreateLink(r.Context(), p, r.PathValue("id"), service.LinkOptions{ShareID: req.ShareID,
			LinkKey: req.LinkKey, Password: req.Password, ExpiresAt: req.ExpiresAt, MaxDownloads: req.MaxDownloads})
		if err != nil {
			s.writeError(w, r, err)
			return
		}
		// The client appends ".<link secret>" to the fragment; the server
		// never learns the secret that decrypts.
		writeJSON(w, http.StatusCreated, map[string]any{"share": viewShare(sh), "token": token,
			"urlPrefix": s.cfg.PublicURL.Scheme + "://" + s.cfg.PublicURL.Host + "/s#" + token})
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

// ---- public links -----------------------------------------------------------------------

type linkReq struct {
	Token    string `json:"token"`
	Password string `json:"password"`
	NodeID   string `json:"nodeId"`
	Cursor   string `json:"cursor"`
}

// handlePublicNode returns a node inside a link, the key-derivation path
// from the link's node to it, and (for folders) its children.
func (s *Server) handlePublicNode(w http.ResponseWriter, r *http.Request) {
	var req linkReq
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	cred := service.LinkCredential{Token: req.Token, Password: req.Password}
	view, err := s.svc.LinkNode(r.Context(), cred, req.NodeID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	path := make([]publicNodeView, len(view.Path))
	for i, n := range view.Path {
		path[i] = viewPublic(n)
	}
	resp := map[string]any{
		"link": map[string]any{"id": view.Share.ID, "nodeId": view.Share.NodeID, "linkKey": view.Share.LinkKey,
			"expiresAt": view.Share.ExpiresAt, "createdBy": view.Share.CreatedBy},
		"path": path,
	}
	target := view.Path[len(view.Path)-1]
	if target.Kind == domain.KindFolder {
		children, next, err := s.svc.LinkChildren(r.Context(), cred, target.ID, req.Cursor, 0)
		if err != nil {
			s.writeError(w, r, err)
			return
		}
		pub := make([]publicNodeView, len(children))
		for i, c := range children {
			pub[i] = viewPublic(c)
		}
		resp["children"], resp["nextCursor"] = pub, next
	}
	writeJSON(w, http.StatusOK, resp)
}

// handlePublicDownload returns a file's encrypted container; the visitor's
// browser decrypts it with the key from the link's URL fragment.
func (s *Server) handlePublicDownload(w http.ResponseWriter, r *http.Request) {
	var req linkReq
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	c, err := s.svc.LinkOpen(r.Context(), service.LinkCredential{Token: req.Token, Password: req.Password}, req.NodeID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.serveContainer(w, r, c)
}

// handlePublicSigner lets a link visitor verify who signed a container.
func (s *Server) handlePublicSigner(w http.ResponseWriter, r *http.Request) {
	var req struct {
		linkReq
		UserID string `json:"userId"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	u, err := s.svc.LinkSigner(r.Context(), service.LinkCredential{Token: req.Token, Password: req.Password}, req.UserID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, userView{ID: u.ID, Keys: viewKeys(u.Keys)})
}
