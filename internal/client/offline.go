package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/woah-buddy/NoddaNAS/internal/e2ee"
)

// Offline decryption: no server, no database. Everything here works from
// files alone: a key backup (unlocked with the passphrase or recovery code)
// plus containers, or a whole WebDAV mirror of a space.

// OfflineKeys are unlocked keys loaded from a key backup.
type OfflineKeys struct {
	Account *e2ee.Account
	teams   map[string]*e2ee.Space
}

// UnlockBackup opens a key backup file with a passphrase or recovery code.
func UnlockBackup(data []byte, secret string, recovery bool) (*OfflineKeys, error) {
	var kb KeyBackup
	if err := json.Unmarshal(data, &kb); err != nil || kb.Format != "noddanas-keys/v1" || kb.Bundle == nil {
		return nil, errors.New("not a NoddaNAS key backup")
	}
	var acct *e2ee.Account
	var err error
	if recovery {
		acct, err = e2ee.UnlockWithRecoveryCode(kb.Bundle, secret)
	} else {
		acct, err = e2ee.Unlock(kb.Bundle, secret)
	}
	if err != nil {
		return nil, err
	}
	ok := &OfflineKeys{Account: acct, teams: map[string]*e2ee.Space{}}
	for _, t := range kb.Teams {
		granter, err := e2ee.VerifyPublicKeys(t.GrantedBy, t.GranterKeys, t.GranterSig)
		if err != nil {
			continue
		}
		if s, err := e2ee.OpenGrant(acct, granter, t.SpaceID, t.Grant, t.GrantSig); err == nil {
			ok.teams[t.SpaceID] = s
		}
	}
	return ok, nil
}

// Space returns the keys of a space: the personal space for any ID that is
// not a known team (personal secrets do not depend on the space ID).
func (k *OfflineKeys) Space(id string, personal bool) (*e2ee.Space, error) {
	if s, ok := k.teams[id]; ok {
		return s, nil
	}
	if personal {
		return k.Account.PersonalSpace(id), nil
	}
	return nil, fmt.Errorf("no key for team folder %s in this backup", id)
}

// DecryptContainer decrypts one container (e.g. a .ndne backup file) using
// only its owner seal. signer verifies the signature; pass nil to accept a
// container signed by the backup's own user only.
func (k *OfflineKeys) DecryptContainer(r io.Reader, w io.Writer, signer *e2ee.PublicUser) (*e2ee.Meta, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	p, err := e2ee.ParsePrefix(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	_, isTeam := k.teams[p.Owner.Space]
	s, err := k.Space(p.Owner.Space, !isTeam)
	if err != nil {
		return nil, err
	}
	nk, err := p.OwnerNodeKey(s)
	if err != nil {
		return nil, fmt.Errorf("these keys cannot open this container: %w", err)
	}
	keys, err := p.Keys(nk)
	if err != nil {
		return nil, err
	}
	meta, err := p.DecryptMeta(keys)
	if err != nil {
		return nil, err
	}
	if signer == nil {
		if p.Signer.User != k.Account.UserID {
			return nil, fmt.Errorf("container was signed by user %s; supply their public key to verify it", p.Signer.User)
		}
		signer = k.Account.Public()
	}
	return meta, e2ee.DecryptVerify(bytes.NewReader(data[p.BodyOffset():]), w, p, keys, signer)
}

// SpaceRecord and FolderRecord mirror the WebDAV backup metadata files.
type SpaceRecord struct {
	Format  string `json:"format"`
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	RootID  string `json:"rootId"`
	NameEnc string `json:"nameEnc"`
	RootKey string `json:"rootKey"`
}

type FolderRecord struct {
	Format   string `json:"format"`
	ID       string `json:"id"`
	Children []struct {
		ID         string `json:"id"`
		Kind       string `json:"kind"`
		NameEnc    string `json:"nameEnc"`
		WrappedKey string `json:"wrappedKey"`
	} `json:"children"`
}

// DecryptTree turns a WebDAV mirror of one space (a directory holding
// _noddanas-space.json) into a plaintext directory tree at out, with real
// names. signers resolves other users' public keys for signature checks;
// files signed by unknown users are skipped and reported.
func (k *OfflineKeys) DecryptTree(mirror, out string, signers map[string]*e2ee.PublicUser) (files int, skipped []string, err error) {
	raw, err := os.ReadFile(filepath.Join(mirror, "_noddanas-space.json"))
	if err != nil {
		return 0, nil, err
	}
	var sr SpaceRecord
	if err := json.Unmarshal(raw, &sr); err != nil || sr.Format != "noddanas-space/v1" {
		return 0, nil, errors.New("not a NoddaNAS space mirror")
	}
	s, err := k.Space(sr.ID, sr.Kind == "personal")
	if err != nil {
		return 0, nil, err
	}
	root, err := s.UnwrapRoot(sr.RootID, sr.RootKey)
	if err != nil {
		return 0, nil, err
	}
	if signers == nil {
		signers = map[string]*e2ee.PublicUser{}
	}
	signers[k.Account.UserID] = k.Account.Public()
	var walk func(dir, outDir string, nk *e2ee.NodeKey) error
	walk = func(dir, outDir string, nk *e2ee.NodeKey) error {
		raw, err := os.ReadFile(filepath.Join(dir, "_noddanas-folder.json"))
		if err != nil {
			return err
		}
		var fr FolderRecord
		if err := json.Unmarshal(raw, &fr); err != nil {
			return err
		}
		if err := os.MkdirAll(outDir, 0o700); err != nil {
			return err
		}
		for _, ch := range fr.Children {
			name, err := nk.DecryptName(ch.ID, ch.NameEnc)
			if err != nil {
				return fmt.Errorf("name of %s: %w", ch.ID, err)
			}
			if e2ee.ValidateName(name) != nil {
				return fmt.Errorf("refusing unsafe name for %s", ch.ID)
			}
			ck, err := nk.UnwrapChild(ch.ID, ch.WrappedKey)
			if err != nil {
				return fmt.Errorf("key of %s: %w", ch.ID, err)
			}
			if ch.Kind == "folder" {
				if err := walk(filepath.Join(dir, ch.ID), filepath.Join(outDir, name), ck); err != nil {
					return err
				}
				continue
			}
			ok, err := decryptFile(filepath.Join(dir, ch.ID+".ndne"), filepath.Join(outDir, name), ck, signers)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			if ok {
				files++
			} else {
				skipped = append(skipped, filepath.Join(outDir, name))
			}
		}
		return nil
	}
	err = walk(mirror, out, root)
	return files, skipped, err
}

func decryptFile(src, dst string, nk *e2ee.NodeKey, signers map[string]*e2ee.PublicUser) (bool, error) {
	f, err := os.Open(src)
	if err != nil {
		return false, err
	}
	defer f.Close()
	p, err := e2ee.ParsePrefix(f)
	if err != nil {
		return false, err
	}
	keys, err := p.Keys(nk)
	if err != nil {
		return false, err
	}
	signer := signers[p.Signer.User]
	if signer == nil {
		return false, nil
	}
	tmp := dst + ".partial"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return false, err
	}
	err = e2ee.DecryptVerify(f, out, p, keys, signer)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return false, err
	}
	return true, os.Rename(tmp, dst)
}

// SafeJoin is used by tools that write decrypted names to disk.
func SafeJoin(dir, name string) (string, error) {
	if e2ee.ValidateName(name) != nil || strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("unsafe name %q", name)
	}
	return filepath.Join(dir, name), nil
}
