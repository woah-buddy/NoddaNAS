package service

import (
	"context"

	"github.com/woah-buddy/FrontDir/internal/domain"
	"github.com/woah-buddy/FrontDir/internal/e2ee"
	"github.com/woah-buddy/FrontDir/internal/validate"
)

// Team folders ("team spaces") are owned by no single user: they have their
// own quota and a member list. Members are added directly by a manager
// (any user can create a team folder and invite people), or arrive through
// an identity-provider group mapped to the folder by an administrator.
//
// Because content is end-to-end encrypted, joining has two halves: the
// server records the membership (and so authorizes access immediately),
// and a manager's client grants the new member the team's key. Until then
// the member can see that the folder exists but cannot decrypt it.

// SpaceInfo is a space together with the caller's relationship to it.
type SpaceInfo struct {
	Space      *domain.Space
	Role       domain.Role
	Membership *domain.Membership // team spaces only
}

// ListSpaces returns the caller's personal space and team folders.
func (s *Service) ListSpaces(ctx context.Context, p Principal) ([]SpaceInfo, error) {
	if p.UserID == "" {
		return nil, domain.ErrUnauthorized
	}
	spaces, err := s.store.ListUserSpaces(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	var out []SpaceInfo
	for _, sp := range spaces {
		role, m, err := s.spaceRole(ctx, p, sp)
		if err != nil {
			return nil, err
		}
		if role == domain.RoleNone {
			continue
		}
		if p.ReadOnly {
			role = domain.RoleRead
		}
		out = append(out, SpaceInfo{Space: sp, Role: role, Membership: m})
	}
	return out, nil
}

// GetSpace returns one space the caller belongs to.
func (s *Service) GetSpace(ctx context.Context, p Principal, id string) (*SpaceInfo, error) {
	sp, role, m, err := s.spaceAccess(ctx, p, id, domain.RoleRead)
	if err != nil {
		return nil, err
	}
	return &SpaceInfo{Space: sp, Role: role, Membership: m}, nil
}

// NewTeam describes a team folder created by a client: the client chose
// the IDs and generated all key material.
type NewTeam struct {
	ID       string
	RootID   string
	NameEnc  string
	Keys     SpaceKeys
	Grant    string // the team secret sealed to the creator
	GrantSig string
}

// CreateTeam creates a team folder with the caller as its manager.
func (s *Service) CreateTeam(ctx context.Context, p Principal, t NewTeam) (*domain.Space, error) {
	if p.ReadOnly {
		return nil, domain.E(domain.CodeForbidden, "this credential is read-only")
	}
	me, err := s.store.GetUser(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	if !s.conf().TeamCreation && !me.Admin {
		return nil, domain.E(domain.CodeForbidden, "only administrators can create team folders here")
	}
	if me.Keys == nil {
		return nil, domain.E(domain.CodePrecondition, "set up encryption before creating a team folder")
	}
	if err := firstErr(validate.ID(t.ID), validate.ID(t.RootID),
		validate.Opaque("nameEnc", t.NameEnc, validate.EncNameMin, validate.EncNameMax),
		validate.Opaque("grant", t.Grant, validate.GrantLen, validate.GrantLen),
		validate.Opaque("grantSig", t.GrantSig, validate.SignatureLen, validate.SignatureLen)); err != nil {
		return nil, err
	}
	pub, err := e2ee.VerifyPublicKeys(me.ID, e2ee.PublicKeys{Enc: me.Keys.Enc, Sig: me.Keys.Sig}, me.Keys.SelfSig)
	if err != nil {
		return nil, err
	}
	t.Keys.KeySigner = me.ID
	if err := checkSpaceKeys(t.ID, t.Keys, pub); err != nil {
		return nil, err
	}
	now := s.now()
	sp := &domain.Space{
		ID: t.ID, Kind: domain.SpaceTeam, RootID: t.RootID, NameEnc: t.NameEnc,
		PublicKey: t.Keys.PublicKey, KeySig: t.Keys.KeySig, KeySigner: me.ID, RootKey: t.Keys.RootKey,
		QuotaBytes: s.conf().DefaultTeamQuota, CreatedAt: now, CreatedBy: me.ID,
	}
	root := &domain.Node{ID: t.RootID, SpaceID: t.ID, Kind: domain.KindFolder,
		CreatedAt: now, CreatedBy: me.ID, ModifiedAt: now, ModifiedBy: me.ID, Revision: 1}
	m := &domain.Membership{SpaceID: t.ID, UserID: me.ID, DirectRole: domain.RoleManage,
		Grant: t.Grant, GrantSig: t.GrantSig, GrantedBy: me.ID, AddedAt: now}
	if err := s.store.CreateTeamSpace(ctx, sp, root, m); err != nil {
		return nil, err
	}
	s.audit(ctx, "team.create", p, "space", t.ID)
	return sp, nil
}

// RenameTeam sets a team folder's (encrypted) name.
func (s *Service) RenameTeam(ctx context.Context, p Principal, spaceID, nameEnc string) error {
	sp, _, _, err := s.spaceAccess(ctx, p, spaceID, domain.RoleManage)
	if err != nil {
		return err
	}
	if sp.Kind != domain.SpaceTeam {
		return domain.E(domain.CodeInvalid, "personal spaces have no name")
	}
	if err := validate.Opaque("nameEnc", nameEnc, validate.EncNameMin, validate.EncNameMax); err != nil {
		return err
	}
	return s.store.UpdateSpaceName(ctx, spaceID, nameEnc)
}

// DeleteTeam permanently deletes a team folder and everything in it.
func (s *Service) DeleteTeam(ctx context.Context, p Principal, spaceID string) error {
	sp, _, _, err := s.spaceAccess(ctx, p, spaceID, domain.RoleManage)
	if err != nil {
		return err
	}
	if sp.Kind != domain.SpaceTeam {
		return domain.E(domain.CodeInvalid, "personal spaces cannot be deleted")
	}
	if err := s.store.MarkSpaceDeleted(ctx, spaceID, s.now()); err != nil {
		return err
	}
	s.audit(ctx, "team.delete", p, "space", spaceID)
	return nil
}

// ListMembers lists a team folder's members (any member may see them).
func (s *Service) ListMembers(ctx context.Context, p Principal, spaceID string) ([]*domain.Member, error) {
	sp, _, _, err := s.spaceAccess(ctx, p, spaceID, domain.RoleRead)
	if err != nil {
		return nil, err
	}
	if sp.Kind != domain.SpaceTeam {
		return nil, domain.E(domain.CodeInvalid, "personal spaces have no members")
	}
	return s.store.ListMembers(ctx, spaceID)
}

// MemberUpdate changes a member: their direct role and/or their key grant.
type MemberUpdate struct {
	Role     *domain.Role // nil = unchanged; RoleNone removes the direct role
	Grant    string
	GrantSig string
}

// UpdateMember adds or changes a team member (managers only).
func (s *Service) UpdateMember(ctx context.Context, p Principal, spaceID, userID string, u MemberUpdate) error {
	sp, _, _, err := s.spaceAccess(ctx, p, spaceID, domain.RoleManage)
	if err != nil {
		return err
	}
	if sp.Kind != domain.SpaceTeam {
		return domain.E(domain.CodeInvalid, "personal spaces have no members")
	}
	if err := validate.ID(userID); err != nil {
		return domain.ErrNotFound
	}
	target, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	now := s.now()
	if u.Role != nil {
		if *u.Role != domain.RoleNone && !u.Role.Valid() {
			return domain.E(domain.CodeInvalid, "role must be read, write or manage")
		}
		if err := s.keepAManager(ctx, spaceID, userID, *u.Role); err != nil {
			return err
		}
		if err := s.store.SetMemberRole(ctx, spaceID, userID, *u.Role, now); err != nil {
			return err
		}
		s.audit(ctx, "team.member_role", p, "space", spaceID, "member", userID, "role", string(*u.Role))
	}
	if u.Grant != "" {
		if target.Keys == nil {
			return domain.E(domain.CodePrecondition, "that user has not set up encryption yet")
		}
		if err := firstErr(validate.Opaque("grant", u.Grant, validate.GrantLen, validate.GrantLen),
			validate.Opaque("grantSig", u.GrantSig, validate.SignatureLen, validate.SignatureLen)); err != nil {
			return err
		}
		// Only grant keys to people who actually have access.
		m, err := s.store.GetMembership(ctx, spaceID, userID)
		if err != nil || m.Role() == domain.RoleNone {
			return domain.E(domain.CodePrecondition, "add the user as a member before granting the key")
		}
		if err := s.store.SetMemberGrant(ctx, spaceID, userID, u.Grant, u.GrantSig, p.UserID, now); err != nil {
			return err
		}
		s.audit(ctx, "team.key_grant", p, "space", spaceID, "member", userID)
	}
	return nil
}

// RemoveMember removes a member's direct membership and key grant.
// Managers may remove anyone; members may remove themselves (leave).
func (s *Service) RemoveMember(ctx context.Context, p Principal, spaceID, userID string) error {
	want := domain.RoleManage
	if userID == p.UserID {
		want = domain.RoleRead
	}
	sp, _, _, err := s.spaceAccess(ctx, p, spaceID, want)
	if err != nil {
		return err
	}
	if sp.Kind != domain.SpaceTeam {
		return domain.E(domain.CodeInvalid, "personal spaces have no members")
	}
	if err := s.keepAManager(ctx, spaceID, userID, domain.RoleNone); err != nil {
		return err
	}
	if err := s.store.RemoveMember(ctx, spaceID, userID); err != nil {
		return err
	}
	s.audit(ctx, "team.member_remove", p, "space", spaceID, "member", userID)
	return nil
}

// keepAManager refuses a change that would leave a team with no manager
// holding the key (nobody could then grant keys to new members).
func (s *Service) keepAManager(ctx context.Context, spaceID, userID string, newDirect domain.Role) error {
	members, err := s.store.ListMembers(ctx, spaceID)
	if err != nil {
		return err
	}
	for _, m := range members {
		role := m.Role()
		if m.UserID == userID {
			mm := m.Membership
			mm.DirectRole = newDirect
			role = mm.Role()
		}
		if role == domain.RoleManage && m.Grant != "" {
			return nil
		}
	}
	return domain.E(domain.CodeConflict, "a team folder must keep at least one manager who holds its key")
}

// ---- group mappings (administrators) ------------------------------------------------

func (s *Service) requireAdmin(ctx context.Context, p Principal) error {
	if p.UserID == "" {
		return domain.ErrUnauthorized
	}
	u, err := s.store.GetUser(ctx, p.UserID)
	if err != nil {
		return err
	}
	if !s.IsAdmin(u) || p.ReadOnly {
		return domain.E(domain.CodeForbidden, "administrators only")
	}
	return nil
}

// IsAdmin reports whether an account currently has administrator rights. A
// local account's appointment counts only while local administrators are
// allowed (always, without an identity provider).
func (s *Service) IsAdmin(u *domain.User) bool {
	return u.Admin && (u.Issuer != domain.IssuerLocal || s.conf().LocalAdmins)
}

func (s *Service) teamForAdmin(ctx context.Context, p Principal, spaceID string) (*domain.Space, error) {
	if err := s.requireAdmin(ctx, p); err != nil {
		return nil, err
	}
	if err := validate.ID(spaceID); err != nil {
		return nil, domain.ErrNotFound
	}
	sp, err := s.store.GetSpace(ctx, spaceID)
	if err != nil {
		return nil, err
	}
	if sp.Kind != domain.SpaceTeam || sp.DeletedAt != nil {
		return nil, domain.ErrNotFound
	}
	return sp, nil
}

// ListGroupMappings lists a team folder's group mappings. Members and
// administrators may see them.
func (s *Service) ListGroupMappings(ctx context.Context, p Principal, spaceID string) ([]domain.GroupMapping, error) {
	if _, _, _, err := s.spaceAccess(ctx, p, spaceID, domain.RoleRead); err != nil {
		if _, aerr := s.teamForAdmin(ctx, p, spaceID); aerr != nil {
			return nil, err
		}
	}
	return s.store.ListGroupMappings(ctx, spaceID)
}

// SetGroupMapping maps an IdP group to a team folder role (administrators).
func (s *Service) SetGroupMapping(ctx context.Context, p Principal, spaceID, group string, role domain.Role) error {
	if _, err := s.teamForAdmin(ctx, p, spaceID); err != nil {
		return err
	}
	if err := validate.Group(group); err != nil {
		return err
	}
	if !role.Valid() {
		return domain.E(domain.CodeInvalid, "role must be read, write or manage")
	}
	if err := s.store.SetGroupMapping(ctx, domain.GroupMapping{SpaceID: spaceID, Group: group, Role: role}); err != nil {
		return err
	}
	s.audit(ctx, "team.group_map", p, "space", spaceID, "group", group, "role", string(role))
	return nil
}

// DeleteGroupMapping removes a group mapping (administrators). Members who
// were in the folder only through that group lose access and their key grant.
func (s *Service) DeleteGroupMapping(ctx context.Context, p Principal, spaceID, group string) error {
	if _, err := s.teamForAdmin(ctx, p, spaceID); err != nil {
		return err
	}
	if err := s.store.DeleteGroupMapping(ctx, spaceID, group); err != nil {
		return err
	}
	s.audit(ctx, "team.group_unmap", p, "space", spaceID, "group", group)
	return nil
}

// AdminListTeams lists all team folders (names stay encrypted unless the
// administrator is a member).
func (s *Service) AdminListTeams(ctx context.Context, p Principal) ([]*domain.Space, error) {
	if err := s.requireAdmin(ctx, p); err != nil {
		return nil, err
	}
	return s.store.ListTeamSpaces(ctx)
}

// AdminSetQuota sets any space's quota (administrators).
func (s *Service) AdminSetQuota(ctx context.Context, p Principal, spaceID string, quota int64) error {
	if err := s.RequireFreshAdmin(ctx, p); err != nil {
		return err
	}
	if err := validate.ID(spaceID); err != nil {
		return domain.ErrNotFound
	}
	if err := s.SetQuota(ctx, spaceID, quota); err != nil {
		return err
	}
	s.audit(ctx, "space.quota", p, "space", spaceID, "bytes", quota)
	return nil
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
