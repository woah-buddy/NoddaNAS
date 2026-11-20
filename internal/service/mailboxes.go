package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"time"
	"unicode/utf8"

	"github.com/woah-buddy/FrontDir/internal/domain"
	"github.com/woah-buddy/FrontDir/internal/e2ee"
	"github.com/woah-buddy/FrontDir/internal/secure"
	"github.com/woah-buddy/FrontDir/internal/validate"
)

// File mailboxes (docs/E2EE.md §6a): a link anyone can drop files into,
// and nobody can read or retrieve anything through.
//
// One-way twice over. There is no read path: the link's credential is
// accepted only by the endpoints that describe the mailbox and take a
// drop, and they reveal nothing about what is already there. And drops are
// encrypted to the mailbox's public key, so even their ciphertext is
// useless to the sender or anyone else holding the link.
//
// Drops wait outside the folder tree until someone with write access to
// the folder files them (their client unseals each drop's key and wraps it
// under the folder), or discards them. They count against the folder's
// space quota from the moment they arrive, and against the mailbox's own
// size and file caps, which every mailbox must have, as it must expire.

// MailboxOptions configures a new mailbox.
type MailboxOptions struct {
	ID        string
	BoxKey    string // the private key wrapped under the folder's key
	Info      string // title and owner, encrypted under the public key
	Password  string
	ExpiresAt time.Time
	MaxBytes  int64
	MaxFiles  int64
	AutoFile  bool
}

const (
	defaultMailboxFiles = 1000
	maxMailboxFiles     = 100_000
	maxDropsListed      = 1000
	maxMailboxesListed  = 500
)

// CreateMailbox opens a mailbox on a folder the caller can write to and
// returns it with its access token (shown once; only its hash is stored).
func (s *Service) CreateMailbox(ctx context.Context, p Principal, folderID string, o MailboxOptions) (*domain.Mailbox, string, error) {
	if err := firstErr(validate.ID(o.ID), validate.Opaque("boxKey", o.BoxKey, 12+32+16, 128),
		validate.Opaque("info", o.Info, 12+16+2, 4096)); err != nil {
		return nil, "", err
	}
	a, err := s.authorize(ctx, p, folderID, domain.PermWrite)
	if err != nil {
		return nil, "", err
	}
	if a.node.Kind != domain.KindFolder {
		return nil, "", domain.E(domain.CodeInvalid, "a mailbox needs a folder")
	}
	now := s.now()
	exp := o.ExpiresAt.UTC()
	if exp.Before(now.Add(time.Minute)) || exp.After(now.Add(s.conf().LinkMaxTTL)) {
		return nil, "", domain.E(domain.CodeInvalid, "expiry must be between one minute and %d days from now", int(s.conf().LinkMaxTTL.Hours()/24))
	}
	if o.MaxBytes < 1 || o.MaxBytes > a.space.QuotaBytes {
		return nil, "", domain.E(domain.CodeInvalid, "the size limit must be at least one byte and at most the folder's storage quota")
	}
	if o.MaxFiles == 0 {
		o.MaxFiles = defaultMailboxFiles
	}
	if o.MaxFiles < 1 || o.MaxFiles > maxMailboxFiles {
		return nil, "", domain.E(domain.CodeInvalid, "the file limit must be between 1 and %d", maxMailboxFiles)
	}
	pwHash := ""
	if o.Password != "" {
		if utf8.RuneCountInString(o.Password) < 10 || len(o.Password) > 256 {
			return nil, "", domain.E(domain.CodeInvalid, "mailbox passwords must be at least 10 characters")
		}
		pwHash = secure.HashPassword(o.Password)
	}
	token := secure.NewToken()
	m := &domain.Mailbox{ID: o.ID, NodeID: folderID, SpaceID: a.space.ID, CreatedBy: p.UserID, CreatedAt: now,
		TokenHash: secure.HashToken(secure.PurposeMailbox, token), BoxKey: o.BoxKey, Info: o.Info, PasswordHash: pwHash,
		ExpiresAt: exp, MaxBytes: o.MaxBytes, MaxFiles: o.MaxFiles, AutoFile: o.AutoFile}
	if err := s.store.CreateMailbox(ctx, m); err != nil {
		return nil, "", err
	}
	s.audit(ctx, "mailbox.create", p, "mailbox", m.ID, "node", folderID, "space", a.space.ID, "password", pwHash != "",
		"expires", exp, "max_bytes", o.MaxBytes, "max_files", o.MaxFiles, "auto_file", o.AutoFile)
	return m, token, nil
}

// FolderMailboxes lists the mailboxes on a folder the caller can write to.
func (s *Service) FolderMailboxes(ctx context.Context, p Principal, folderID string) ([]*domain.Mailbox, error) {
	if _, err := s.authorize(ctx, p, folderID, domain.PermWrite); err != nil {
		return nil, err
	}
	return s.store.ListMailboxesByNode(ctx, folderID)
}

// MyMailboxes lists the mailboxes the caller created that they can still
// manage (write access to the folder).
func (s *Service) MyMailboxes(ctx context.Context, p Principal) ([]*domain.Mailbox, error) {
	if p.UserID == "" {
		return nil, domain.ErrUnauthorized
	}
	ms, err := s.store.ListMailboxesByCreator(ctx, p.UserID, maxMailboxesListed)
	if err != nil {
		return nil, err
	}
	out := ms[:0]
	for _, m := range ms {
		if _, err := s.authorize(ctx, p, m.NodeID, domain.PermWrite); err == nil {
			out = append(out, m)
		}
	}
	return out, nil
}

// manageMailbox loads a mailbox the caller may manage: write access to its
// folder. Anything else looks like it does not exist.
func (s *Service) manageMailbox(ctx context.Context, p Principal, id string) (*domain.Mailbox, error) {
	if validate.ID(id) != nil {
		return nil, domain.ErrNotFound
	}
	m, err := s.store.GetMailbox(ctx, id)
	if err != nil {
		return nil, err
	}
	if _, err := s.authorize(ctx, p, m.NodeID, domain.PermWrite); err != nil {
		return nil, domain.ErrNotFound
	}
	return m, nil
}

// Inbox returns a mailbox and its pending drops.
func (s *Service) Inbox(ctx context.Context, p Principal, id string) (*domain.Mailbox, []*domain.Drop, error) {
	m, err := s.manageMailbox(ctx, p, id)
	if err != nil {
		return nil, nil, err
	}
	ds, err := s.store.ListDrops(ctx, id, maxDropsListed)
	return m, ds, err
}

// CloseMailbox stops a mailbox accepting drops. Pending drops stay to be
// filed or discarded, until the mailbox's drops expire.
func (s *Service) CloseMailbox(ctx context.Context, p Principal, id string) error {
	m, err := s.manageMailbox(ctx, p, id)
	if err != nil {
		return err
	}
	if err := s.store.CloseMailbox(ctx, m.ID, s.now()); err != nil {
		return err
	}
	s.audit(ctx, "mailbox.close", p, "mailbox", m.ID)
	return nil
}

// DropContent opens a pending drop's encrypted body, for review.
func (s *Service) DropContent(ctx context.Context, p Principal, mailboxID, dropID string) (*domain.Drop, io.ReadSeekCloser, error) {
	if _, err := s.manageMailbox(ctx, p, mailboxID); err != nil {
		return nil, nil, err
	}
	if validate.ID(dropID) != nil {
		return nil, nil, domain.ErrNotFound
	}
	d, err := s.store.GetDrop(ctx, mailboxID, dropID)
	if err != nil {
		return nil, nil, err
	}
	rc, err := s.blobs.Open(ctx, d.BlobKey)
	if err != nil {
		return nil, nil, err
	}
	return d, rc, nil
}

// DiscardDrop deletes a pending drop.
func (s *Service) DiscardDrop(ctx context.Context, p Principal, mailboxID, dropID string) error {
	if _, err := s.manageMailbox(ctx, p, mailboxID); err != nil {
		return err
	}
	if validate.ID(dropID) != nil {
		return domain.ErrNotFound
	}
	d, err := s.store.GetDrop(ctx, mailboxID, dropID)
	if err != nil {
		return err
	}
	if err := s.store.DeleteDrop(ctx, d); err != nil {
		return err
	}
	s.deleteBlob(ctx, d.BlobKey)
	s.audit(ctx, "mailbox.drop_discard", p, "mailbox", mailboxID, "drop", dropID)
	return nil
}

// FileDropRequest files a drop: the new file's directory entry, and the
// container prefix and trailer the filer's client made around the drop's
// unchanged body (docs/E2EE.md §6a), with its version record.
type FileDropRequest struct {
	NewID             string
	Entry             EntryFields
	Prefix, Trailer   []byte
	Record, RecordSig []byte
}

// FileDrop turns a pending drop into a file in the mailbox's folder. The
// server splices prefix, stored body and trailer into a container and
// stores it through the normal upload checks; the drop is consumed in the
// same transaction.
func (s *Service) FileDrop(ctx context.Context, p Principal, mailboxID, dropID string, req FileDropRequest) (*domain.Node, error) {
	m, err := s.manageMailbox(ctx, p, mailboxID)
	if err != nil {
		return nil, err
	}
	if validate.ID(dropID) != nil {
		return nil, domain.ErrNotFound
	}
	d, err := s.store.GetDrop(ctx, mailboxID, dropID)
	if err != nil {
		return nil, err
	}
	if len(req.Prefix) < 12 || len(req.Prefix) > 12+e2ee.MaxHeaderLen || len(req.Trailer) != e2ee.TrailerSize {
		return nil, domain.E(domain.CodeInvalid, "malformed container prefix or trailer")
	}
	// The prefix must describe exactly this drop's body.
	if pp, err := e2ee.ParsePrefix(bytes.NewReader(req.Prefix)); err != nil || pp.Size != d.PlainSize || pp.BodyOffset() != int64(len(req.Prefix)) {
		return nil, domain.E(domain.CodeInvalid, "the container prefix does not match the drop")
	}
	body, err := s.blobs.Open(ctx, d.BlobKey)
	if err != nil {
		return nil, err
	}
	defer func() { _ = body.Close() }()
	total := int64(len(req.Prefix)) + d.Size + int64(len(req.Trailer))
	n, err := s.Upload(ctx, p, UploadRequest{ParentID: m.NodeID, NewID: req.NewID, Entry: req.Entry, Size: total,
		Record: req.Record, RecordSig: req.RecordSig, dropID: d.ID, dropSize: d.Size},
		io.MultiReader(bytes.NewReader(req.Prefix), body, bytes.NewReader(req.Trailer)))
	if err != nil {
		return nil, err
	}
	s.deleteBlob(ctx, d.BlobKey)
	s.audit(ctx, "mailbox.drop_file", p, "mailbox", mailboxID, "drop", dropID, "node", n.ID)
	return n, nil
}

func (s *Service) deleteBlob(ctx context.Context, key string) {
	if err := s.blobs.Delete(context.WithoutCancel(ctx), key); err != nil {
		s.log.WarnContext(ctx, "blob delete failed (verify-storage will report it as an orphan)", "err", err)
	}
}

// ---- anonymous senders ---------------------------------------------------------------

// MailboxCredential is what a sender presents: the token from the link's
// fragment, and the password if the mailbox has one.
type MailboxCredential struct {
	Token    string
	Password string
}

// openMailbox checks a sender's credential. Unknown tokens, and mailboxes
// whose folder is gone, all look the same.
func (s *Service) openMailbox(ctx context.Context, cred MailboxCredential) (*domain.Mailbox, error) {
	if !secure.ValidToken(cred.Token) {
		return nil, domain.ErrNotFound
	}
	m, err := s.store.GetMailboxByTokenHash(ctx, secure.HashToken(secure.PurposeMailbox, cred.Token))
	if err != nil {
		return nil, err
	}
	if _, _, err := s.loadChain(ctx, m.NodeID); err != nil {
		return nil, domain.ErrNotFound // folder trashed or deleted
	}
	now := s.now()
	if !m.Accepting(now) {
		return nil, domain.E(domain.CodeGone, "this mailbox no longer accepts files")
	}
	if m.Locked(now) {
		return nil, domain.E(domain.CodeRateLimited, "too many wrong passwords; try again later")
	}
	if m.PasswordHash != "" {
		if cred.Password == "" {
			return nil, &domain.Error{Code: domain.CodeUnauthorized, Message: "this mailbox requires a password",
				Detail: map[string]string{"reason": "password_required"}}
		}
		if !secure.VerifyPassword(cred.Password, m.PasswordHash) {
			if err := s.store.RecordMailboxFailure(ctx, m.ID, s.conf().LinkMaxFailures, now.Add(s.conf().LinkLockout)); err != nil {
				return nil, err
			}
			s.log.WarnContext(ctx, "audit", "event", "mailbox.password_failed", "mailbox", m.ID)
			return nil, &domain.Error{Code: domain.CodeUnauthorized, Message: "wrong password",
				Detail: map[string]string{"reason": "password_wrong"}}
		}
		if m.FailedAttempts > 0 {
			if err := s.store.ResetMailboxFailures(ctx, m.ID); err != nil {
				return nil, err
			}
		}
	}
	return m, nil
}

// MailboxView is what a sender learns: the encrypted description and the
// limits that apply to them. Nothing about drops already made.
type MailboxView struct {
	ID          string
	Info        string
	ExpiresAt   time.Time
	MaxFileSize int64 // plaintext bytes one drop may have
	Remaining   int64 // encrypted bytes the mailbox still accepts
	FilesLeft   int64
}

// MailboxForSender describes a mailbox to someone holding its link.
func (s *Service) MailboxForSender(ctx context.Context, cred MailboxCredential) (*MailboxView, error) {
	m, err := s.openMailbox(ctx, cred)
	if err != nil {
		return nil, err
	}
	return &MailboxView{ID: m.ID, Info: m.Info, ExpiresAt: m.ExpiresAt, MaxFileSize: s.conf().MaxFileSize,
		Remaining: max(0, m.MaxBytes-m.UsedBytes), FilesLeft: max(0, m.MaxFiles-m.UsedFiles)}, nil
}

// Drop stores a file dropped into a mailbox: header is the drop header
// (docs/E2EE.md §6a), body its encrypted body of exactly the length the
// header implies. size is the declared Content-Length, or -1.
func (s *Service) Drop(ctx context.Context, cred MailboxCredential, header []byte, size int64, body io.Reader) error {
	m, err := s.openMailbox(ctx, cred)
	if err != nil {
		return err
	}
	h, err := e2ee.ParseDropHeader(header)
	if err != nil {
		return domain.E(domain.CodeInvalid, "malformed drop")
	}
	bodySize := e2ee.BodySize(h.Size)
	switch {
	case size >= 0 && size != bodySize:
		return domain.E(domain.CodeInvalid, "Content-Length does not match the drop's declared size")
	case bodySize > s.conf().MaxFileSize:
		return domain.E(domain.CodeTooLarge, "file exceeds the maximum size")
	case m.UsedBytes+bodySize > m.MaxBytes || m.UsedFiles >= m.MaxFiles:
		return domain.E(domain.CodeQuota, "this mailbox is full") // advisory; the binding check is atomic
	}
	blobKey := secure.NewID()
	lr := &limitReader{r: body, n: bodySize}
	sum := sha256.New()
	dg := e2ee.NewBodyDigester(h.Size)
	if _, err := s.blobs.Create(ctx, blobKey, io.TeeReader(lr, io.MultiWriter(sum, dg))); err != nil {
		s.deleteBlob(ctx, blobKey)
		if errors.Is(err, errOverLimit) {
			return domain.E(domain.CodeInvalid, "body is longer than the drop's declared size")
		}
		return err
	}
	digest, err := dg.Digest()
	if lr.read != bodySize || err != nil {
		s.deleteBlob(ctx, blobKey)
		return domain.E(domain.CodeInvalid, "body is shorter than the drop's declared size")
	}
	d := &domain.Drop{ID: h.ID, MailboxID: m.ID, SpaceID: m.SpaceID, BlobKey: blobKey, Size: bodySize, PlainSize: h.Size,
		Header: header, BodyHash: digest.BodyHash, SHA256: hex.EncodeToString(sum.Sum(nil)), CreatedAt: s.now()}
	if err := s.store.CreateDrop(ctx, d, s.now()); err != nil {
		s.deleteBlob(ctx, blobKey)
		return err
	}
	s.log.InfoContext(ctx, "audit", "event", "mailbox.drop", "mailbox", m.ID, "drop", d.ID, "size", d.Size)
	return nil
}

// ---- maintenance ------------------------------------------------------------------------

// expireMailboxes deletes the pending drops of mailboxes that closed or
// expired more than the trash retention ago, then the mailboxes.
func (s *Service) expireMailboxes(ctx context.Context) error {
	ms, err := s.store.FinishedMailboxes(ctx, s.now().Add(-s.conf().TrashRetention), 50)
	if err != nil {
		return err
	}
	for _, m := range ms {
		ds, err := s.store.ListDrops(ctx, m.ID, maxDropsListed)
		if err != nil {
			return err
		}
		for _, d := range ds {
			if err := s.blobs.Delete(ctx, d.BlobKey); err != nil {
				return err
			}
			if err := s.store.DeleteDrop(ctx, d); err != nil {
				return err
			}
		}
		if len(ds) < maxDropsListed {
			if err := s.store.DeleteMailbox(ctx, m.ID); err != nil {
				return err
			}
			s.log.InfoContext(ctx, "audit", "event", "mailbox.expired", "mailbox", m.ID, "discarded", len(ds))
		}
	}
	return nil
}

// purgeDrops deletes pending drops (blobs first) returned by next, until
// none are left. Used before a folder or space is deleted for good.
func (s *Service) purgeDrops(ctx context.Context, next func() ([]*domain.Drop, error)) error {
	for ctx.Err() == nil {
		ds, err := next()
		if err != nil {
			return err
		}
		if len(ds) == 0 {
			return nil
		}
		for _, d := range ds {
			if err := s.blobs.Delete(ctx, d.BlobKey); err != nil {
				return err
			}
			if err := s.store.DeleteDrop(ctx, d); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}
