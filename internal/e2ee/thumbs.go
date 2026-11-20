package e2ee

import (
	"encoding/json"
	"fmt"
)

// Thumbnails (docs/E2EE.md §5a).
//
// A thumbnail is a small encrypted record attached to one version of a
// file, next to its container rather than inside it, so a thumbnail can be
// added to an existing file without rewriting the file or touching its
// author's signature.
//
//	tk  = HKDF(NK, salt, info="L/file/thumb")      salt: that version's container salt
//	ct  = GCM(tk, JSON{"type","w","h","data"}, aad="L/file/thumb" \0 nodeId)
//	sig = Ed25519(creator, "L/thumb-sig" \0 nodeId \0 || salt || SHA-256(ct))
//
// Only key holders can make one (tk needs NK), the salt ties it to exactly
// one version, and the signature names who made it. Clients show a
// thumbnail only if it was made by the version's author (the container's
// signer) or by the viewer themselves, so a collaborator cannot put a
// misleading preview on someone else's file for others to see.

// Thumbnail limits: a small raster image, as WebP or JPEG.
const (
	MaxThumbBytes = 24 << 10
	MaxThumbSide  = 512
)

// Thumb is a decrypted thumbnail.
type Thumb struct {
	Type string `json:"type"`
	W    int    `json:"w"`
	H    int    `json:"h"`
	Data string `json:"data"` // b64u of the image bytes
}

func thumbTypeOK(t string) bool { return t == "image/webp" || t == "image/jpeg" }

func thumbSigMsg(nodeID string, salt, ct []byte) []byte {
	msg := append(join("thumb-sig", nodeID), 0)
	msg = append(msg, salt...)
	return append(msg, sum(ct)...)
}

// SealThumb encrypts and signs a thumbnail for the file version p
// describes. k must come from p.Keys, which has checked the key commitment.
func SealThumb(creator *Account, nodeID string, p *Prefix, k *FileKeys, img []byte, typ string, w, h int) (enc, sig string, err error) {
	if !thumbTypeOK(typ) || len(img) == 0 || len(img) > MaxThumbBytes || w < 1 || h < 1 || w > MaxThumbSide || h > MaxThumbSide {
		return "", "", fmt.Errorf("e2ee: thumbnail must be WebP or JPEG, at most %d bytes and %d pixels a side", MaxThumbBytes, MaxThumbSide)
	}
	pt, _ := json.Marshal(Thumb{Type: typ, W: w, H: h, Data: B64(img)})
	ct := gcmSeal(kdf(k.nk.raw, p.salt, "file/thumb"), pt, join("file/thumb", nodeID))
	return B64(ct), B64(sign(creator.Sig, thumbSigMsg(nodeID, p.salt, ct))), nil
}

// OpenThumb verifies a thumbnail record against the user who made it and
// decrypts it. Whether to show it (author or viewer only) is the caller's
// decision; ThumbAuthorOK states the rule.
func OpenThumb(maker *PublicUser, nodeID string, p *Prefix, k *FileKeys, enc, sig string) (*Thumb, []byte, error) {
	ct, err1 := UnB64(enc)
	s, err2 := UnB64(sig)
	if err1 != nil || err2 != nil {
		return nil, nil, ErrAuth
	}
	if err := verify(maker.Sig, thumbSigMsg(nodeID, p.salt, ct), s); err != nil {
		return nil, nil, err
	}
	pt, err := gcmOpen(kdf(k.nk.raw, p.salt, "file/thumb"), ct, join("file/thumb", nodeID))
	if err != nil {
		return nil, nil, err
	}
	var t Thumb
	if err := json.Unmarshal(pt, &t); err != nil {
		return nil, nil, ErrAuth
	}
	img, err := UnB64(t.Data)
	if err != nil || !thumbTypeOK(t.Type) || len(img) == 0 || len(img) > MaxThumbBytes ||
		t.W < 1 || t.H < 1 || t.W > MaxThumbSide || t.H > MaxThumbSide {
		return nil, nil, ErrAuth
	}
	return &t, img, nil
}

// ThumbAuthorOK is the display rule: a thumbnail is shown only if its maker
// is the version's author (as the container header names them, with the
// same key fingerprint) or the viewer.
func ThumbAuthorOK(p *Prefix, maker *PublicUser, viewerID string) bool {
	if maker.ID == viewerID {
		return true
	}
	return maker.ID == p.Signer.User && maker.Finger == p.Signer.FP
}
