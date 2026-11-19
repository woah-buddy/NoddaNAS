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

// Store persists metadata. Every method that changes more than one row must
// be atomic, and every condition described below must be enforced by the
// store in the same statement or transaction as the write (never "check,
// then write"), so concurrent requests cannot race past it.
type Store interface {
	GetUser(ctx context.Context, id string) (*domain.User, error)
	GetUserByIdentity(ctx context.Context, issuer, subject string) (*domain.User, error)
	// CreateUser creates the user and their root folder together. If the
	// email is already claimed by another account it is stored as empty.
	// ErrConflict if the identity already exists.
	CreateUser(ctx context.Context, u *domain.User, root *domain.Node) error
	// UpdateUserProfile refreshes IdP-asserted attributes. As with
	// CreateUser, an email claimed by another account is stored as empty.
	UpdateUserProfile(ctx context.Context, id, email, displayName string) error
	GetUserIDByEmail(ctx context.Context, email string) (string, error)
	SetQuota(ctx context.Context, userID string, quotaBytes int64) error

	GetNode(ctx context.Context, id string) (*domain.Node, error)
	// GetAncestry returns [node, parent, ..., root] (at most max entries),
	// including trashed nodes, or ErrNotFound if id does not exist.
	GetAncestry(ctx context.Context, id string, max int) ([]*domain.Node, error)
	// GetChildByName returns the live child with the given name key.
	GetChildByName(ctx context.Context, parentID, nameKey string) (*domain.Node, error)
	// ListChildren returns live children ordered by name key, after cursor
	// (the last name key of the previous page, "" for the first page).
	ListChildren(ctx context.Context, parentID, cursor string, limit int) ([]*domain.Node, string, error)
	// CreateFolder: ErrConflict if the name is taken in the parent.
	CreateFolder(ctx context.Context, n *domain.Node, nameKey string) error
	// UpdateNodeLocation persists n's ParentID/Name. Conditions: stored
	// revision == expectedRev and not trashed (ErrPrecondition); name free
	// in the destination (ErrConflict). Increments n.Revision on success.
	UpdateNodeLocation(ctx context.Context, n *domain.Node, nameKey string, expectedRev int64) error
	// TrashNode marks n trashed. Condition: revision == expectedRev, live,
	// and not a root (ErrPrecondition).
	TrashNode(ctx context.Context, n *domain.Node, at time.Time, expectedRev int64) error
	// RestoreNode un-trashes n at its (possibly updated) ParentID/Name.
	// ErrNotFound if not trashed or already being purged; ErrConflict if
	// the name is taken.
	RestoreNode(ctx context.Context, n *domain.Node, nameKey string) error
	ListTrash(ctx context.Context, ownerID string) ([]*domain.Node, error)
	// MarkPurging schedules a trashed node for permanent deletion.
	// ErrNotFound if it is not trashed or is already scheduled.
	MarkPurging(ctx context.Context, nodeID string) error
	// ExpireTrash schedules every node trashed before cutoff for purging.
	ExpireTrash(ctx context.Context, cutoff time.Time) (int64, error)
	// ClaimPurge leases one scheduled node for purging so that only one
	// worker processes it; ErrNotFound if there is no work.
	ClaimPurge(ctx context.Context, lease time.Duration) (*domain.Node, error)
	// SubtreeVersions returns up to limit versions stored under rootID,
	// not descending into separately trashed nodes.
	SubtreeVersions(ctx context.Context, rootID string, limit int) ([]*domain.Version, error)
	// DeleteVersions removes versions and refunds their size to the
	// owner's quota. Idempotent: already-deleted versions refund nothing.
	DeleteVersions(ctx context.Context, versions []*domain.Version) error
	// DeleteSubtree deletes a purging node and its live descendants (which
	// must have no versions left). Separately trashed descendants are moved
	// to the owner's root so they stay restorable.
	DeleteSubtree(ctx context.Context, rootID string) error

	// CommitContent atomically charges v.Size to the owner's quota
	// (ErrQuota if it would exceed), creates (isNew) or updates the node,
	// and records the version. For an existing node: stored revision must
	// equal expectedRev and it must be live (ErrPrecondition). New node:
	// ErrConflict if the name is taken.
	CommitContent(ctx context.Context, n *domain.Node, nameKey string, v *domain.Version, isNew bool, expectedRev int64) error
	ListVersions(ctx context.Context, nodeID string) ([]*domain.Version, error)
	GetVersion(ctx context.Context, nodeID, versionID string) (*domain.Version, error)

	// CreateShare: ErrConflict if the node is already shared with that user.
	CreateShare(ctx context.Context, s *domain.Share) error
	GetShare(ctx context.Context, id string) (*domain.Share, error)
	GetShareByTokenHash(ctx context.Context, tokenHash string) (*domain.Share, error)
	DeleteShare(ctx context.Context, id string) error
	ListSharesByNode(ctx context.Context, nodeID string) ([]*domain.Share, error)
	ListSharesByRecipient(ctx context.Context, userID string) ([]*domain.Share, error)
	// GetGrants returns user shares to userID on any of nodeIDs.
	GetGrants(ctx context.Context, userID string, nodeIDs []string) ([]*domain.Share, error)
	// RecordLinkDownload counts one download; ErrGone if the link's
	// download limit has been reached.
	RecordLinkDownload(ctx context.Context, id string) error
	// RecordLinkFailure counts a failed password attempt; on reaching
	// threshold the counter resets and the link locks until `until`.
	RecordLinkFailure(ctx context.Context, id string, threshold int64, until time.Time) error
	ResetLinkFailures(ctx context.Context, id string) error
}

// BlobStore stores opaque encrypted blobs. It never sees plaintext, names,
// owners or folder structure: only random keys and ciphertext.
type BlobStore interface {
	// Create writes a new blob; it must not overwrite an existing key.
	Create(ctx context.Context, key string, r io.Reader) (int64, error)
	// Open returns the blob for random-access reading (ErrNotFound if absent).
	Open(ctx context.Context, key string) (io.ReadSeekCloser, error)
	// Delete removes a blob; deleting a missing blob is not an error.
	Delete(ctx context.Context, key string) error
}

// Keyring wraps and unwraps per-blob data keys (see internal/blobcrypt).
type Keyring interface {
	NewDataKey(binding string) (dek []byte, wrapped string, err error)
	Unwrap(wrapped, binding string) ([]byte, error)
}
