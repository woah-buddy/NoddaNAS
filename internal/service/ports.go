package service

import (
	"context"
	"io"
	"time"

	"github.com/woah-buddy/NoddaNAS/internal/domain"
)

// The interfaces below are the service's "ports": what it needs from the
// outside world, defined by the code that consumes them. Business rules, and
// above all authorization, live only in this package; storage adapters just
// persist what they are told, so swapping one cannot weaken a security rule.

// SpaceKeys are a space's public key material, set when encryption is set up.
type SpaceKeys struct {
	PublicKey string
	KeySig    string
	KeySigner string
	RootKey   string
}

// Store persists metadata. Every method that changes more than one row must
// be atomic, and every condition described below must be enforced by the
// store in the same statement or transaction as the write.
type Store interface {
	// ---- users ----
	GetUser(ctx context.Context, id string) (*domain.User, error)
	GetUserByIdentity(ctx context.Context, issuer, subject string) (*domain.User, error)
	// CreateUser creates the user with their personal space and its root
	// folder. An email already claimed by another account is stored empty.
	// ErrConflict if the identity already exists.
	CreateUser(ctx context.Context, u *domain.User, space *domain.Space, root *domain.Node) error
	// UpdateUserProfile refreshes IdP-asserted attributes (same email rule).
	UpdateUserProfile(ctx context.Context, id, email, displayName string, admin bool) error
	// SyncGroups replaces the user's IdP groups and drops key grants for
	// team spaces the user no longer belongs to.
	SyncGroups(ctx context.Context, userID string, groups []string) error
	GetUserIDByEmail(ctx context.Context, email string) (string, error)
	// SetKeys stores a user's public keys and key bundle and their personal
	// space's keys, atomically. ErrConflict if keys were already set.
	SetKeys(ctx context.Context, userID string, keys domain.PublicKeys, bundle string, personal SpaceKeys) error
	// UpdateKeyBundle replaces the bundle; the caller has checked that the
	// public keys inside are unchanged.
	UpdateKeyBundle(ctx context.Context, userID, bundle string) error

	// ---- spaces ----
	GetSpace(ctx context.Context, id string) (*domain.Space, error)
	// CreateTeamSpace creates a team space, its root folder and the
	// creator's membership. ErrConflict if an ID is taken.
	CreateTeamSpace(ctx context.Context, s *domain.Space, root *domain.Node, creator *domain.Membership) error
	UpdateSpaceName(ctx context.Context, id, nameEnc string) error
	SetSpaceQuota(ctx context.Context, id string, quota int64) error
	// MarkSpaceDeleted schedules a team space for purging.
	MarkSpaceDeleted(ctx context.Context, id string, at time.Time) error
	// ListUserSpaces returns the user's personal space and every live team
	// space they belong to directly, through a group, or hold a grant for.
	ListUserSpaces(ctx context.Context, userID string) ([]*domain.Space, error)
	ListTeamSpaces(ctx context.Context) ([]*domain.Space, error)
	// GetMembership computes a user's membership including group roles.
	// ErrNotFound if the user has no direct role, group role or grant.
	GetMembership(ctx context.Context, spaceID, userID string) (*domain.Membership, error)
	ListMembers(ctx context.Context, spaceID string) ([]*domain.Member, error)
	// SetMemberRole sets (or with RoleNone clears) a user's direct role.
	SetMemberRole(ctx context.Context, spaceID, userID string, role domain.Role, at time.Time) error
	SetMemberGrant(ctx context.Context, spaceID, userID, grant, sig, grantedBy string, at time.Time) error
	RemoveMember(ctx context.Context, spaceID, userID string) error
	ListGroupMappings(ctx context.Context, spaceID string) ([]domain.GroupMapping, error)
	SetGroupMapping(ctx context.Context, m domain.GroupMapping) error
	// DeleteGroupMapping removes a mapping and the key grants of users who
	// thereby lose access.
	DeleteGroupMapping(ctx context.Context, spaceID, group string) error
	ClaimDeletedSpace(ctx context.Context, lease time.Duration) (*domain.Space, error)
	SpaceVersions(ctx context.Context, spaceID string, limit int) ([]*domain.Version, error)
	// DeleteSpace removes a deleted space whose versions are all gone.
	DeleteSpace(ctx context.Context, spaceID string) error

	// ---- nodes ----
	GetNode(ctx context.Context, id string) (*domain.Node, error)
	// GetAncestry returns [node, parent, ..., root] (at most max entries).
	GetAncestry(ctx context.Context, id string, max int) ([]*domain.Node, error)
	// GetChildByHash returns the live child with the given name hash.
	GetChildByHash(ctx context.Context, parentID, nameHash string) (*domain.Node, error)
	// ListChildren returns live children ordered by ID, after cursor.
	ListChildren(ctx context.Context, parentID, cursor string, limit int) ([]*domain.Node, string, error)
	// CreateFolder: ErrConflict if the ID or the name hash is taken.
	CreateFolder(ctx context.Context, n *domain.Node) error
	// UpdateNodeLocation persists ParentID/NameEnc/NameHash/WrappedKey.
	// Conditions: revision == expectedRev and live (ErrPrecondition); name
	// hash free in the destination (ErrConflict). Increments n.Revision.
	UpdateNodeLocation(ctx context.Context, n *domain.Node, expectedRev int64) error
	// TrashNode marks n trashed with its restore key. Condition: revision ==
	// expectedRev, live, not a root (ErrPrecondition).
	TrashNode(ctx context.Context, n *domain.Node, expectedRev int64) error
	// RestoreNode un-trashes n at its new location. ErrNotFound if not
	// trashed or being purged; ErrConflict if the name hash is taken.
	RestoreNode(ctx context.Context, n *domain.Node) error
	ListTrash(ctx context.Context, spaceID string) ([]*domain.Node, error)
	MarkPurging(ctx context.Context, nodeID string) error
	ExpireTrash(ctx context.Context, cutoff time.Time) (int64, error)
	ClaimPurge(ctx context.Context, lease time.Duration) (*domain.Node, error)
	SubtreeVersions(ctx context.Context, rootID string, limit int) ([]*domain.Version, error)
	// DeleteVersions removes versions and refunds their size to their
	// space's quota, exactly once.
	DeleteVersions(ctx context.Context, versions []*domain.Version) error
	DeleteSubtree(ctx context.Context, rootID string) error

	// CommitContent atomically charges v.Size to the space quota (ErrQuota),
	// creates (isNew) or updates the node, and records the version.
	CommitContent(ctx context.Context, n *domain.Node, v *domain.Version, isNew bool, expectedRev int64) error
	ListVersions(ctx context.Context, nodeID string) ([]*domain.Version, error)
	GetVersion(ctx context.Context, nodeID, versionID string) (*domain.Version, error)

	// ---- shares ----
	CreateShare(ctx context.Context, s *domain.Share) error
	GetShare(ctx context.Context, id string) (*domain.Share, error)
	GetShareByTokenHash(ctx context.Context, tokenHash string) (*domain.Share, error)
	DeleteShare(ctx context.Context, id string) error
	ListSharesByNode(ctx context.Context, nodeID string) ([]*domain.Share, error)
	ListSharesByRecipient(ctx context.Context, userID string) ([]*domain.Share, error)
	ListSharesByCreator(ctx context.Context, userID string, limit int) ([]*domain.Share, error)
	DeleteLinksByCreator(ctx context.Context, userID string) (int64, error)
	DeleteAllLinks(ctx context.Context) (int64, error)
	GetGrants(ctx context.Context, userID string, nodeIDs []string) ([]*domain.Share, error)
	RecordLinkDownload(ctx context.Context, id string) error
	RecordLinkFailure(ctx context.Context, id string, threshold int64, until time.Time) error
	ResetLinkFailures(ctx context.Context, id string) error
}

// BlobStore stores opaque blobs: client-encrypted containers under random
// keys. It never sees plaintext, names or folder structure.
type BlobStore interface {
	Create(ctx context.Context, key string, r io.Reader) (int64, error)
	Open(ctx context.Context, key string) (io.ReadSeekCloser, error)
	Delete(ctx context.Context, key string) error
}
