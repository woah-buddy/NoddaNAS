package e2ee

import (
	"crypto/ecdh"
	"encoding/json"
)

// KeyAndName is what shares, links and trash entries carry: a node key plus
// the node's name, which is otherwise encrypted under the (possibly
// inaccessible) parent's key.
type KeyAndName struct {
	NK   string `json:"nk"`
	Name string `json:"name"`
	Kind string `json:"kind,omitempty"`
}

func (k KeyAndName) nodeKey() (*NodeKey, error) {
	raw, err := UnB64(k.NK)
	if err != nil {
		return nil, ErrAuth
	}
	return nodeKeyFrom(raw)
}

// ---- user shares (docs/E2EE.md §6) -------------------------------------------------

func shareCtx(shareID, nodeID, recipientID string) []byte {
	return join("share", shareID, nodeID, recipientID)
}

func shareSigMsg(shareID, nodeID, recipientID, perm string, sealed []byte) []byte {
	return append(append(join("share-sig", shareID, nodeID, recipientID, perm), 0), sum(sealed)...)
}

// ShareNode seals a node's key and name to a recipient and signs the grant.
func ShareNode(sharer *Account, recipient *PublicUser, shareID, nodeID, perm, name string, nk *NodeKey) (sealed, sig string, err error) {
	pt, _ := json.Marshal(KeyAndName{NK: B64(nk.raw), Name: nfc(name)})
	s, err := Seal(recipient.Enc, pt, shareCtx(shareID, nodeID, recipient.ID))
	if err != nil {
		return "", "", err
	}
	return B64(s), B64(sign(sharer.Sig, shareSigMsg(shareID, nodeID, recipient.ID, perm, s))), nil
}

// OpenShare verifies the sharer's signature and recovers the node key and name.
func OpenShare(me *Account, sharer *PublicUser, shareID, nodeID, perm, sealedB64, sigB64 string) (*NodeKey, string, error) {
	sealed, err1 := UnB64(sealedB64)
	sig, err2 := UnB64(sigB64)
	if err1 != nil || err2 != nil {
		return nil, "", ErrAuth
	}
	if err := verify(sharer.Sig, shareSigMsg(shareID, nodeID, me.UserID, perm, sealed), sig); err != nil {
		return nil, "", err
	}
	pt, err := Open(me.Enc, sealed, shareCtx(shareID, nodeID, me.UserID))
	if err != nil {
		return nil, "", err
	}
	var kn KeyAndName
	if err := json.Unmarshal(pt, &kn); err != nil {
		return nil, "", ErrAuth
	}
	nk, err := kn.nodeKey()
	return nk, kn.Name, err
}

// ---- public links ---------------------------------------------------------------

// NewLinkSecret returns a fresh link secret (it lives only in the URL fragment).
func NewLinkSecret() []byte { return random(32) }

// LinkKey encrypts a node's key and name under a link secret.
func LinkKey(secret []byte, shareID, nodeID, name string, nk *NodeKey) string {
	pt, _ := json.Marshal(KeyAndName{NK: B64(nk.raw), Name: nfc(name)})
	return B64(gcmSeal(kdf(secret, nil, "link"), pt, join("link", shareID, nodeID)))
}

// OpenLinkKey recovers a node key and name from a link.
func OpenLinkKey(secret []byte, shareID, nodeID, linkKey string) (*NodeKey, string, error) {
	pt, err := openB64(kdf(secret, nil, "link"), linkKey, join("link", shareID, nodeID))
	if err != nil {
		return nil, "", err
	}
	var kn KeyAndName
	if err := json.Unmarshal(pt, &kn); err != nil {
		return nil, "", ErrAuth
	}
	nk, err := kn.nodeKey()
	return nk, kn.Name, err
}

// ---- trash (docs/E2EE.md §7) -------------------------------------------------------

func trashSigMsg(nodeID string, sealed []byte) []byte {
	return append(append(join("trash-sig", nodeID), 0), sum(sealed)...)
}

// TrashKey seals a node's key, name and kind to its space so the owner can
// restore it later, even if its folder is gone.
func TrashKey(trasher *Account, spacePub *ecdh.PublicKey, nodeID, name, kind string, nk *NodeKey) (sealed, sig string, err error) {
	pt, _ := json.Marshal(KeyAndName{NK: B64(nk.raw), Name: nfc(name), Kind: kind})
	s, err := Seal(spacePub, pt, join("trash", nodeID))
	if err != nil {
		return "", "", err
	}
	return B64(s), B64(sign(trasher.Sig, trashSigMsg(nodeID, s))), nil
}

// OpenTrashKey verifies and opens a trash restore key with the space's keys.
func OpenTrashKey(space *Space, trasher *PublicUser, nodeID, sealedB64, sigB64 string) (*NodeKey, KeyAndName, error) {
	sealed, err1 := UnB64(sealedB64)
	sig, err2 := UnB64(sigB64)
	if err1 != nil || err2 != nil {
		return nil, KeyAndName{}, ErrAuth
	}
	if err := verify(trasher.Sig, trashSigMsg(nodeID, sealed), sig); err != nil {
		return nil, KeyAndName{}, err
	}
	pt, err := Open(space.Priv, sealed, join("trash", nodeID))
	if err != nil {
		return nil, KeyAndName{}, err
	}
	var kn KeyAndName
	if err := json.Unmarshal(pt, &kn); err != nil {
		return nil, KeyAndName{}, ErrAuth
	}
	nk, err := kn.nodeKey()
	return nk, kn, err
}
