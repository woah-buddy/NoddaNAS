// Package service implements NoddaNAS's use cases: spaces and team folders,
// files, versions, trash, sharing and public links. It is the only place
// that makes authorization decisions (see access.go); transports such as the
// JSON API and WebDAV call into it and never touch storage directly.
//
// With end-to-end encryption, the service never sees plaintext or usable
// keys. It authorizes access to opaque, client-encrypted data, enforces
// quotas and structure, and validates the shape of everything it stores.
package service

import (
	"context"
	"log/slog"
	"slices"
	"time"
)

// Principal is an authenticated caller.
type Principal struct {
	UserID string
	// ReadOnly principals (e.g. a read-only app password) are capped at
	// read permission no matter what they own or were granted.
	ReadOnly bool
}

// Config holds tunable limits. Defaults are deliberately conservative.
type Config struct {
	DefaultQuota     int64         // bytes for new personal spaces
	DefaultTeamQuota int64         // bytes for new team spaces
	MaxFileSize      int64         // largest single container accepted
	MaxDepth         int           // deepest allowed folder nesting
	MaxVersions      int           // versions kept per file (including current)
	TrashRetention   time.Duration // trashed items are purged after this
	LinkDefaultTTL   time.Duration
	LinkMaxTTL       time.Duration
	LinkMaxFailures  int64
	LinkLockout      time.Duration
	PageSize         int
	MaxPageSize      int
	AdminGroups      []string // IdP groups whose members are administrators
	TeamCreation     bool     // whether any user may create team folders
}

// DefaultConfig returns safe defaults.
func DefaultConfig() Config {
	return Config{
		DefaultQuota:     10 << 30,
		DefaultTeamQuota: 50 << 30,
		MaxFileSize:      50 << 30,
		MaxDepth:         64,
		MaxVersions:      10,
		TrashRetention:   30 * 24 * time.Hour,
		LinkDefaultTTL:   30 * 24 * time.Hour,
		LinkMaxTTL:       365 * 24 * time.Hour,
		LinkMaxFailures:  10,
		LinkLockout:      15 * time.Minute,
		PageSize:         200,
		MaxPageSize:      1000,
		TeamCreation:     true,
	}
}

// Service is the application core.
type Service struct {
	store Store
	blobs BlobStore
	cfg   Config
	log   *slog.Logger
	now   func() time.Time
}

// New wires a Service.
func New(store Store, blobs BlobStore, cfg Config, log *slog.Logger) *Service {
	return &Service{store: store, blobs: blobs, cfg: cfg, log: log, now: func() time.Time { return time.Now().UTC() }}
}

// Config returns the service's configuration.
func (s *Service) Config() Config { return s.cfg }

func (s *Service) isAdminGroups(groups []string) bool {
	for _, g := range groups {
		if slices.Contains(s.cfg.AdminGroups, g) {
			return true
		}
	}
	return false
}

// audit records a security-relevant event. Records carry identifiers only.
func (s *Service) audit(ctx context.Context, event string, p Principal, attrs ...any) {
	s.log.LogAttrs(ctx, slog.LevelInfo, "audit",
		append([]slog.Attr{slog.String("event", event), slog.String("user", p.UserID)}, toAttrs(attrs)...)...)
}

func toAttrs(kv []any) []slog.Attr {
	var out []slog.Attr
	for i := 0; i+1 < len(kv); i += 2 {
		if k, ok := kv[i].(string); ok {
			out = append(out, slog.Any(k, kv[i+1]))
		}
	}
	return out
}

func (s *Service) pageSize(n int) int {
	switch {
	case n <= 0:
		return s.cfg.PageSize
	case n > s.cfg.MaxPageSize:
		return s.cfg.MaxPageSize
	default:
		return n
	}
}
