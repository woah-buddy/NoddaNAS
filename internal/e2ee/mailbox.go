package e2ee

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

// File mailboxes (docs/E2EE.md §6a): a link anyone can drop files into,
// but nobody can read or retrieve anything through.
//
// Each mailbox has an X25519 key pair. The public key travels only in the
// link's fragment (which browsers never send to servers), and every drop is
// encrypted to it, so a sender, or anyone else holding the link, can drop
// but never decrypt. The private key is wrapped under the target folder's
// node key: whoever can read the folder can open its mailbox's drops.
//
// A drop is a container body (the usual STREAM chunks, keyed by a fresh
// node key NK and salt) with a small header: the salt, the key commitment,
// NK sealed to the mailbox key, the encrypted metadata, and an optional
// note from the sender. It is not yet a file: an anonymous sender cannot
// hold the folder's key (that would let them read the folder), so a key
// holder's client files it, sealing NK into the tree and signing a proper
// container header around the unchanged body.

// Mailbox is an opened mailbox key pair.
type Mailbox struct {
	ID   string
	Priv *ecdh.PrivateKey
}

// MailboxInfo is shown to senders: what the mailbox is for and whose it is.
type MailboxInfo struct {
	Title string `json:"title"`
	Owner string `json:"owner"`
}

// DropNote is what a sender may say about themselves. Nothing verifies it.
type DropNote struct {
	Name    string `json:"name,omitempty"`
	Email   string `json:"email,omitempty"`
	Message string `json:"message,omitempty"`
}

// DropHeader describes one drop (everything but its body).
type DropHeader struct {
	V      int    `json:"v"`
	ID     string `json:"id"`
	Size   int64  `json:"size"`
	Salt   string `json:"salt"`
	Commit string `json:"commit"`
	Key    string `json:"key"`  // NK sealed to the mailbox public key
	Meta   string `json:"meta"` // as in containers
	Note   string `json:"note,omitempty"`
}

// Limits on what senders can put in a drop's header.
const (
	MaxDropNote      = 2000 // characters of the message
	MaxDropHeaderLen = 16 << 10
	maxInfoTitle     = 200
)

// NewMailbox makes a mailbox key pair.
func NewMailbox(id string) (*Mailbox, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Mailbox{ID: id, Priv: priv}, nil
}

// Public returns the public key, which goes in the link.
func (m *Mailbox) Public() []byte { return m.Priv.PublicKey().Bytes() }

func mailboxWrapKey(folder *NodeKey) []byte { return kdf(folder.raw, nil, "mailbox/key") }

// Wrap encrypts the private key under the target folder's node key.
func (m *Mailbox) Wrap(folder *NodeKey) string {
	return B64(gcmSeal(mailboxWrapKey(folder), m.Priv.Bytes(), join("mailbox/key", m.ID)))
}

// OpenMailbox unwraps a mailbox's private key with its folder's key.
func OpenMailbox(id string, folder *NodeKey, wrapped string) (*Mailbox, error) {
	raw, err := openB64(mailboxWrapKey(folder), wrapped, join("mailbox/key", id))
	if err != nil {
		return nil, err
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, ErrAuth
	}
	return &Mailbox{ID: id, Priv: priv}, nil
}

// The mailbox's description is readable with the public key alone (the
// link), so senders see it and the server, which never sees the key, can
// neither read nor forge it.
func infoKey(pub []byte) []byte { return kdf(pub, nil, "mailbox/info") }

// SealMailboxInfo encrypts a mailbox's description for its link holders.
func SealMailboxInfo(id string, pub []byte, info MailboxInfo) (string, error) {
	if info.Title == "" || utf8.RuneCountInString(info.Title) > maxInfoTitle || utf8.RuneCountInString(info.Owner) > maxInfoTitle {
		return "", errors.New("e2ee: mailbox title must be 1-200 characters")
	}
	b, _ := json.Marshal(info)
	return B64(gcmSeal(infoKey(pub), b, join("mailbox/info", id))), nil
}

// OpenMailboxInfo decrypts a mailbox's description with its public key.
func OpenMailboxInfo(id string, pub []byte, enc string) (*MailboxInfo, error) {
	pt, err := openB64(infoKey(pub), enc, join("mailbox/info", id))
	if err != nil {
		return nil, err
	}
	var info MailboxInfo
	if json.Unmarshal(pt, &info) != nil {
		return nil, ErrAuth
	}
	return &info, nil
}

func dropCtx(mailboxID, dropID string) []byte { return join("mailbox/drop", mailboxID, dropID) }

func noteKey(nk *NodeKey, salt []byte) []byte { return kdf(nk.raw, salt, "drop/note") }

// NewDrop encrypts src (exactly size bytes) as a drop for the mailbox whose
// public key is pub. It returns the header and a reader for the body.
func NewDrop(src io.Reader, mailboxID, dropID string, pub []byte, size int64, meta Meta, note *DropNote) (*DropHeader, io.Reader, int64, error) {
	if size < 0 || size > MaxSize || !isID(dropID) || !isID(mailboxID) {
		return nil, nil, 0, errors.New("e2ee: invalid drop")
	}
	if note != nil && !noteOK(note) {
		return nil, nil, 0, errors.New("e2ee: the note is too long")
	}
	box, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return nil, nil, 0, err
	}
	nk, salt := NewNodeKey(), random(32)
	fk := deriveFileKeys(nk, salt)
	sealed, err := Seal(box, nk.raw, dropCtx(mailboxID, dropID))
	if err != nil {
		return nil, nil, 0, err
	}
	metaJSON, _ := json.Marshal(meta)
	h := &DropHeader{V: 1, ID: dropID, Size: size, Salt: B64(salt), Commit: B64(fk.commit), Key: B64(sealed),
		Meta: B64(gcmSeal(fk.meta, metaJSON, join("file/meta")))}
	if note != nil && *note != (DropNote{}) {
		nb, _ := json.Marshal(note)
		h.Note = B64(gcmSeal(noteKey(nk, salt), nb, join("drop/note", dropID)))
	}
	body := &writer{src: src, size: size, n: Chunks(size), aead: gcmFor(fk.content), buf: make([]byte, ChunkSize), bh: noHash{}}
	return h, &bodyOnly{body}, BodySize(size), nil
}

func noteOK(n *DropNote) bool {
	return utf8.RuneCountInString(n.Name) <= maxInfoTitle && utf8.RuneCountInString(n.Email) <= maxInfoTitle &&
		utf8.RuneCountInString(n.Message) <= MaxDropNote
}

// bodyOnly yields a writer's chunks and stops before the signature.
type bodyOnly struct{ w *writer }

func (b *bodyOnly) Read(p []byte) (int, error) {
	if len(b.w.out) == 0 && b.w.next == b.w.n {
		var one [1]byte
		if k, _ := io.ReadFull(b.w.src, one[:]); k != 0 {
			return 0, errors.New("e2ee: source is longer than the declared size")
		}
		return 0, io.EOF
	}
	return b.w.Read(p)
}

// noHash is a hash.Hash that discards (a drop's body hash is computed by
// whoever needs it).
type noHash struct{}

func (noHash) Write(p []byte) (int, error) { return len(p), nil }
func (noHash) Sum(b []byte) []byte         { return b }
func (noHash) Reset()                      {}
func (noHash) Size() int                   { return 32 }
func (noHash) BlockSize() int              { return 64 }

// ParseDropHeader checks a drop header's shape without any keys (the
// server uses it before accepting a drop).
func ParseDropHeader(raw []byte) (*DropHeader, error) {
	if len(raw) == 0 || len(raw) > MaxDropHeaderLen {
		return nil, ErrMalformed
	}
	var h DropHeader
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&h) != nil || dec.More() {
		return nil, ErrMalformed
	}
	salt, err1 := UnB64(h.Salt)
	commit, err2 := UnB64(h.Commit)
	key, err3 := UnB64(h.Key)
	meta, err4 := UnB64(h.Meta)
	if h.V != 1 || !isID(h.ID) || h.Size < 0 || h.Size > MaxSize || err1 != nil || err2 != nil || err3 != nil || err4 != nil ||
		len(salt) != 32 || len(commit) != 32 || len(key) != 32+12+32+16 || len(meta) < 12+16+2 || len(meta) > 4096 {
		return nil, ErrMalformed
	}
	if h.Note != "" {
		if note, err := UnB64(h.Note); err != nil || len(note) < 12+16+2 || len(note) > 12*1024 {
			return nil, ErrMalformed
		}
	}
	return &h, nil
}

// OpenedDrop is a drop decrypted with its mailbox's key.
type OpenedDrop struct {
	Header *DropHeader
	NK     *NodeKey
	Meta   Meta
	Note   *DropNote
	salt   []byte
	fk     *fileKeys
}

// OpenDrop unseals a drop's key, checks it against the key commitment and
// decrypts its metadata and note.
func (m *Mailbox) OpenDrop(h *DropHeader) (*OpenedDrop, error) {
	sealed, err := UnB64(h.Key)
	if err != nil {
		return nil, ErrAuth
	}
	raw, err := Open(m.Priv, sealed, dropCtx(m.ID, h.ID))
	if err != nil {
		return nil, err
	}
	nk, err := nodeKeyFrom(raw)
	if err != nil {
		return nil, err
	}
	salt, err := UnB64(h.Salt)
	if err != nil {
		return nil, ErrAuth
	}
	fk := deriveFileKeys(nk, salt)
	if B64(fk.commit) != h.Commit {
		return nil, ErrAuth
	}
	d := &OpenedDrop{Header: h, NK: nk, salt: salt, fk: fk}
	pt, err := openB64(fk.meta, h.Meta, join("file/meta"))
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(pt, &d.Meta) != nil {
		return nil, ErrAuth
	}
	d.Meta.From = nil // only filing sets it, from the note
	if h.Note != "" {
		pt, err := openB64(noteKey(nk, salt), h.Note, join("drop/note", h.ID))
		if err != nil {
			return nil, err
		}
		var n DropNote
		if json.Unmarshal(pt, &n) != nil || !noteOK(&n) {
			return nil, ErrAuth
		}
		d.Note = &n
	}
	return d, nil
}

// Body returns a seekable plaintext reader over the drop's body (src holds
// the body alone). Each chunk is authenticated by AES-GCM; a drop carries
// no signature, since its sender is anonymous.
func (d *OpenedDrop) Body(src io.ReadSeeker) *Reader {
	p := &Prefix{Header: Header{Size: d.Header.Size}}
	return NewReader(src, p, &FileKeys{fk: d.fk, nk: d.NK})
}

// FilePrefix builds the container prefix for filing the drop into a space:
// the same salt, commitment and body keys, NK sealed to the space for
// independent restore, the metadata (with the sender's note, if any), and
// the filer as signer. The filer signs the result with FileTrailer.
func (d *OpenedDrop) FilePrefix(spaceID string, spacePub *ecdh.PublicKey, filer *Account) ([]byte, error) {
	ownerKey, err := Seal(spacePub, d.NK.raw, ownerCtx(spaceID))
	if err != nil {
		return nil, err
	}
	meta := d.Meta
	meta.From = d.Note
	metaJSON, _ := json.Marshal(meta)
	var h Header
	h.V, h.Alg, h.Size, h.Salt, h.Commit = 1, Alg, d.Header.Size, d.Header.Salt, d.Header.Commit
	h.Owner.Space, h.Owner.Key = spaceID, B64(ownerKey)
	h.Meta = B64(gcmSeal(d.fk.meta, metaJSON, join("file/meta")))
	h.Signer.User, h.Signer.FP = filer.UserID, filer.Fingerprint()
	hdr, _ := json.Marshal(h)
	if len(hdr) > MaxHeaderLen {
		return nil, errors.New("e2ee: container header too large")
	}
	prefix := append([]byte(Magic), binary.BigEndian.AppendUint32(nil, uint32(len(hdr)))...) // #nosec G115 -- bounded above
	return append(prefix, hdr...), nil
}

// FileTrailer signs a filed container: the filer's signature over the new
// prefix and the drop body's hash (Digest of the body, §5b).
func FileTrailer(filer *Account, prefix, bodyHash []byte) []byte {
	msg := append(append(join("container"), 0), sum(prefix)...)
	msg = append(msg, bodyHash...)
	return append([]byte(trailerMagic), sign(filer.Sig, msg)...)
}

// NewBodyDigester computes the body hash of a drop body (no prefix, no
// trailer) of the given plaintext size.
func NewBodyDigester(size int64) *Digester {
	d := (&Prefix{Header: Header{Size: size}}).NewDigester()
	d.noTrailer = true
	return d
}
