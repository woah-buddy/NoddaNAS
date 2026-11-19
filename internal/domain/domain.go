// Package domain holds NoddaNAS's core types. It has no dependencies on
// HTTP, databases or storage backends, so the security rules built on top of
// it can be read and tested on their own.
package domain

import "time"

// Kind distinguishes files from folders.
type Kind string

const (
	KindFile   Kind = "file"
	KindFolder Kind = "folder"
)

// Node is a file or folder. The tree lives in the metadata store; blob
// storage only ever sees opaque random keys, never user-supplied names.
type Node struct {
	ID          string
	OwnerID     string // tenant boundary: the user whose quota pays for this node
	ParentID    string // empty for a user's root folder
	Name        string
	Kind        Kind
	Size        int64
	ContentType string
	SHA256      string // lowercase hex of the current content (files only)
	VersionID   string // current version (files only)
	CreatedAt   time.Time
	ModifiedAt  time.Time
	ModifiedBy  string
	Revision    int64 // incremented on every change; used for optimistic concurrency
	TrashedAt   *time.Time
}

// IsRoot reports whether the node is a user's root folder.
func (n *Node) IsRoot() bool { return n.ParentID == "" }

// Version is one stored revision of a file's content.
type Version struct {
	ID         string
	NodeID     string
	OwnerID    string
	BlobKey    string
	WrappedKey string // the content's data key, encrypted under the server's key-encryption key
	Size       int64
	SHA256     string
	CreatedAt  time.Time
	CreatedBy  string
}

// User is a NoddaNAS account, provisioned just-in-time on first login.
type User struct {
	ID          string // internal random ID; never the IdP subject
	Issuer      string // OIDC issuer
	Subject     string // OIDC subject, unique per issuer
	Email       string // set only if the IdP asserted it as verified
	DisplayName string
	RootID      string
	QuotaBytes  int64
	UsedBytes   int64
	CreatedAt   time.Time
}

// Permission is what a share grants. Owners implicitly hold every permission.
type Permission string

const (
	PermNone  Permission = ""
	PermRead  Permission = "read"
	PermWrite Permission = "write" // implies read
	PermOwner Permission = "owner" // never stored on a share
)

// Allows reports whether p is at least as strong as want.
func (p Permission) Allows(want Permission) bool {
	return want != PermNone && p.Rank() >= want.Rank()
}

// Rank orders permissions: none < read < write < owner.
func (p Permission) Rank() int {
	switch p {
	case PermRead:
		return 1
	case PermWrite:
		return 2
	case PermOwner:
		return 3
	default:
		return 0
	}
}

// ShareKind distinguishes shares with another user from public links.
type ShareKind string

const (
	ShareUser ShareKind = "user"
	ShareLink ShareKind = "link"
)

// Share grants access to a node and everything beneath it.
type Share struct {
	ID         string
	Kind       ShareKind
	NodeID     string
	OwnerID    string
	CreatedBy  string
	Permission Permission
	CreatedAt  time.Time

	// User shares.
	RecipientID string

	// Link shares. The token itself is never stored, only its SHA-256, so a
	// leaked database does not leak working links.
	TokenHash      string
	PasswordHash   string // argon2id PHC string; empty if the link has no password
	ExpiresAt      *time.Time
	MaxDownloads   int64 // 0 = unlimited
	Downloads      int64
	FailedAttempts int64
	LockedUntil    *time.Time
}

// Expired reports whether a share has passed its expiry.
func (s *Share) Expired(now time.Time) bool {
	return s.ExpiresAt != nil && !now.Before(*s.ExpiresAt)
}

// Locked reports whether a link is temporarily locked after failed passwords.
func (s *Share) Locked(now time.Time) bool {
	return s.LockedUntil != nil && now.Before(*s.LockedUntil)
}

// TrashEntry is a trashed node and when it will be purged automatically.
type TrashEntry struct {
	Node      *Node
	ExpiresAt time.Time
}

// AppPassword is a revocable credential for non-browser clients (WebDAV,
// CLI, sync tools). Only a hash of the secret is stored.
type AppPassword struct {
	ID         string
	UserID     string
	Name       string
	TokenHash  string
	ReadOnly   bool
	CreatedAt  time.Time
	LastUsedAt *time.Time
	ExpiresAt  *time.Time
}
