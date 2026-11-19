// Package domain holds NoddaNAS's core types. It has no dependencies on
// HTTP, databases or storage backends, so the security rules built on top of
// it can be read and tested on their own.
//
// With end-to-end encryption the server never holds plaintext names or
// usable keys. Fields such as NameEnc, WrappedKey or Grant are opaque
// client-produced ciphertext (see docs/E2EE.md); the server only stores,
// relays and authorizes access to them.
package domain

import "time"

// Kind distinguishes files from folders.
type Kind string

const (
	KindFile   Kind = "file"
	KindFolder Kind = "folder"
)

// Node is a file or folder in a space.
type Node struct {
	ID         string // chosen by the client (bound into its encryption)
	SpaceID    string // tenant boundary: the space whose quota pays for it
	ParentID   string // empty for a space's root folder
	Kind       Kind
	NameEnc    string // client-encrypted name (empty for roots)
	NameHash   string // client-computed keyed hash, unique per folder
	WrappedKey string // node key wrapped under the parent's key (empty for roots)
	Size       int64  // current container size in bytes (what quota counts)
	PlainSize  int64  // plaintext size declared in the container header
	SHA256     string // current container's SHA-256 (files)
	VersionID  string
	CreatedAt  time.Time
	CreatedBy  string
	ModifiedAt time.Time
	ModifiedBy string
	Revision   int64
	TrashedAt  *time.Time
	TrashedBy  string
	RestoreKey string // node key + name sealed to the space, for restoring from trash
	RestoreSig string
}

// IsRoot reports whether the node is a space's root folder.
func (n *Node) IsRoot() bool { return n.ParentID == "" }

// Version is one stored, client-encrypted container.
type Version struct {
	ID        string
	NodeID    string
	SpaceID   string
	BlobKey   string
	Size      int64
	SHA256    string
	CreatedAt time.Time
	CreatedBy string
}

// User is a NoddaNAS account, provisioned just-in-time on first sign-in.
type User struct {
	ID              string // internal random ID; never the IdP subject
	Issuer          string // OIDC issuer or SAML IdP entity ID
	Subject         string // OIDC subject or SAML NameID
	Email           string // set only if the IdP asserted it as verified
	DisplayName     string
	Admin           bool
	PersonalSpaceID string
	Keys            *PublicKeys // nil until the user sets up encryption
	KeyBundle       string      // opaque client key bundle (JSON)
	CreatedAt       time.Time
}

// PublicKeys are a user's published E2EE keys (base64url).
type PublicKeys struct {
	Enc     string
	Sig     string
	SelfSig string
}

// SpaceKind distinguishes personal spaces from team folders.
type SpaceKind string

const (
	SpacePersonal SpaceKind = "personal"
	SpaceTeam     SpaceKind = "team"
)

// Space is an independently owned tree with its own quota.
type Space struct {
	ID          string
	Kind        SpaceKind
	OwnerUserID string // personal spaces only
	RootID      string
	NameEnc     string // team spaces only, encrypted under the space secret
	PublicKey   string // space X25519 public key
	KeySig      string // creator's signature over PublicKey
	KeySigner   string
	RootKey     string // root node key wrapped under the space secret
	QuotaBytes  int64
	UsedBytes   int64
	CreatedAt   time.Time
	CreatedBy   string
	DeletedAt   *time.Time
}

// HasKeys reports whether the space's encryption keys have been set up.
func (s *Space) HasKeys() bool { return s.PublicKey != "" }

// Role is a member's role in a team space.
type Role string

const (
	RoleNone   Role = ""
	RoleRead   Role = "read"
	RoleWrite  Role = "write"
	RoleManage Role = "manage"
)

// Permission converts a space role into a node permission.
func (r Role) Permission() Permission {
	switch r {
	case RoleRead:
		return PermRead
	case RoleWrite:
		return PermWrite
	case RoleManage:
		return PermOwner
	}
	return PermNone
}

// Max returns the stronger of two roles.
func (r Role) Max(o Role) Role {
	if r.Permission().Rank() >= o.Permission().Rank() {
		return r
	}
	return o
}

// Valid reports whether r is a real role.
func (r Role) Valid() bool { return r == RoleRead || r == RoleWrite || r == RoleManage }

// Membership is a user's relationship to a team space.
type Membership struct {
	SpaceID    string
	UserID     string
	DirectRole Role   // explicitly added
	GroupRoles []Role // via identity-provider group mappings
	Grant      string // space secret sealed to the user (empty until granted)
	GrantSig   string
	GrantedBy  string
	AddedAt    time.Time
}

// Role is the effective role: the strongest of direct and group roles.
func (m *Membership) Role() Role {
	r := m.DirectRole
	for _, g := range m.GroupRoles {
		r = r.Max(g)
	}
	return r
}

// Member is a membership plus the member's public identity.
type Member struct {
	Membership
	DisplayName string
	Email       string
	Keys        *PublicKeys
}

// GroupMapping maps an identity-provider group to a team space role.
type GroupMapping struct {
	SpaceID string
	Group   string
	Role    Role
}

// Permission is what a caller may do with a node.
type Permission string

const (
	PermNone  Permission = ""
	PermRead  Permission = "read"
	PermWrite Permission = "write" // implies read
	PermOwner Permission = "owner" // full control: share, link, manage
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
	ID         string // chosen by the client (bound into its encryption)
	Kind       ShareKind
	NodeID     string
	SpaceID    string
	CreatedBy  string
	Permission Permission
	CreatedAt  time.Time

	// User shares: node key + name sealed to the recipient, signed by the sharer.
	RecipientID string
	SealedKey   string
	ShareSig    string

	// Link shares. The token is stored only as a hash; the key that decrypts
	// (LinkKey) needs the link secret that lives in the URL fragment.
	TokenHash      string
	LinkKey        string
	PasswordHash   string
	ExpiresAt      *time.Time
	MaxDownloads   int64
	Downloads      int64
	FailedAttempts int64
	LockedUntil    *time.Time
}

// Expired reports whether a share has passed its expiry.
func (s *Share) Expired(now time.Time) bool {
	return s.ExpiresAt != nil && !now.Before(*s.ExpiresAt)
}

// Exhausted reports whether a link has used up its download limit.
func (s *Share) Exhausted() bool {
	return s.MaxDownloads > 0 && s.Downloads >= s.MaxDownloads
}

// Status summarizes whether a share currently works: "active", or for
// links "expired", "exhausted" (download limit reached) or "locked" (too
// many wrong passwords, temporarily).
func (s *Share) Status(now time.Time) string {
	if s.Kind != ShareLink {
		return "active"
	}
	switch {
	case s.Expired(now):
		return "expired"
	case s.Exhausted():
		return "exhausted"
	case s.Locked(now):
		return "locked"
	}
	return "active"
}

// Locked reports whether a link is temporarily locked after failed passwords.
func (s *Share) Locked(now time.Time) bool {
	return s.LockedUntil != nil && now.Before(*s.LockedUntil)
}

// AppPassword is a revocable credential for non-browser clients (WebDAV,
// CLI). Only a hash of the secret is stored.
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
