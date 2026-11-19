// Command frontdir-cli is the FrontDir end-to-end encrypted command-line
// client. Everything is encrypted and decrypted locally; the server only
// ever sees ciphertext.
//
// Online (needs FRONTDIR_URL and an app password in FRONTDIR_TOKEN or
// FRONTDIR_TOKEN_FILE; your encryption passphrase is prompted for, or read
// from FRONTDIR_PASSPHRASE_FILE):
//
//	frontdir-cli ls [path]                  list a folder (decrypted names)
//	frontdir-cli get <path> [local-file]    download and decrypt a file
//	frontdir-cli put <local-file> [folder]  encrypt and upload (new version if it exists)
//	frontdir-cli mkdir <path>               create a folder
//	frontdir-cli teams                      list team folders
//	frontdir-cli backup <dir>               save your personal space, still encrypted
//	frontdir-cli restore <file.fdenc> [folder]  restore one backed-up file
//	frontdir-cli export-keys <file>         save your (encrypted) key backup
//
// Offline (no server, no network):
//
//	frontdir-cli decrypt <file.fdenc> <out> --keys <keys.json> [--recovery]
//	frontdir-cli decrypt-tree <backup-dir> <out-dir> --keys <keys.json> [--recovery]
//
// Paths are relative to your personal space, e.g. "Documents/taxes.pdf".
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/woah-buddy/FrontDir/internal/client"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	ctx := context.Background()
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	// Variables from before the rename from NoddaNAS are no longer read;
	// say so rather than failing later with a puzzling "no server URL".
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); strings.HasPrefix(name, "NODDANAS_") {
			fmt.Fprintf(os.Stderr, "frontdir-cli: %s is no longer read: rename it to FRONTDIR_%s\n", name, strings.TrimPrefix(name, "NODDANAS_"))
			os.Exit(2)
		}
	}
	switch cmd {
	case "decrypt", "decrypt-tree":
		err = offline(cmd, args)
	case "ls", "get", "put", "mkdir", "teams", "backup", "restore", "export-keys":
		err = online(ctx, cmd, args)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "frontdir-cli:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: frontdir-cli <command> [args]

online:   ls [path] | get <path> [local] | put <local> [folder] | mkdir <path> | teams
          backup <dir> | restore <file.fdenc> [folder] | export-keys <file>
offline:  decrypt <file.fdenc> <out> --keys <keys.json> [--recovery]
          decrypt-tree <backup-dir> <out-dir> --keys <keys.json> [--recovery]

Online commands need FRONTDIR_URL and an app password (FRONTDIR_TOKEN or FRONTDIR_TOKEN_FILE).`)
	os.Exit(2)
}

// secret reads a secret from NAME_FILE or prompts without echo.
func secret(fileEnv, prompt string) (string, error) {
	if f := os.Getenv(fileEnv); f != "" {
		b, err := os.ReadFile(f) // #nosec G304 G703 -- the user's own CLI configuration
		return strings.TrimSpace(string(b)), err
	}
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(line), err
}

func online(ctx context.Context, cmd string, args []string) error {
	base := os.Getenv("FRONTDIR_URL")
	if base == "" {
		return errors.New("set FRONTDIR_URL (e.g. https://files.example.com)")
	}
	token := os.Getenv("FRONTDIR_TOKEN")
	if f := os.Getenv("FRONTDIR_TOKEN_FILE"); f != "" {
		b, err := os.ReadFile(f) // #nosec G304 G703 -- the user's own CLI configuration
		if err != nil {
			return err
		}
		token = strings.TrimSpace(string(b))
	}
	if token == "" {
		return errors.New("set FRONTDIR_TOKEN or FRONTDIR_TOKEN_FILE to an app password (create one under Settings)")
	}
	c := client.New(base, &http.Client{}, token)
	pass, err := secret("FRONTDIR_PASSPHRASE_FILE", "Encryption passphrase: ")
	if err != nil {
		return err
	}
	if err := c.Unlock(ctx, pass, false); err != nil {
		return err
	}
	arg := func(i int, def string) string {
		if i < len(args) {
			return args[i]
		}
		return def
	}
	switch cmd {
	case "ls":
		n, err := c.Resolve(ctx, arg(0, ""))
		if err != nil {
			return err
		}
		kids, err := c.List(ctx, n.ID)
		if err != nil {
			return err
		}
		for _, k := range kids {
			size := ""
			if k.Kind == "file" {
				size = fmt.Sprint(k.PlainSize)
			}
			kind := "-"
			if k.Kind == "folder" {
				kind = "d"
			}
			fmt.Printf("%s %12s  %s  %s\n", kind, size, k.ModifiedAt.Local().Format("2006-01-02 15:04"), k.Name)
		}
	case "get":
		n, err := c.Resolve(ctx, arg(0, ""))
		if err != nil {
			return err
		}
		return writeAtomically(arg(1, n.Name), func(w io.Writer) error { _, err := c.Download(ctx, n.ID, w); return err })
	case "put":
		local := arg(0, "")
		f, err := os.Open(local) // #nosec G304 -- the file the user asked to upload
		if err != nil {
			return err
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return err
		}
		dir, err := c.Resolve(ctx, arg(1, ""))
		if err != nil {
			return err
		}
		name := filepath.Base(local)
		_, err = c.Upload(ctx, dir.ID, name, f, st.Size(), st.ModTime())
		var exists *client.ErrExists
		if errors.As(err, &exists) && exists.Kind == "file" {
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return err
			}
			_, err = c.UploadVersion(ctx, exists.ExistingID, name, f, st.Size(), st.ModTime())
		}
		return err
	case "mkdir":
		p := strings.Trim(arg(0, ""), "/")
		parent, err := c.Resolve(ctx, path.Dir(p))
		if err != nil {
			return err
		}
		_, err = c.Mkdir(ctx, parent.ID, path.Base(p))
		return err
	case "teams":
		spaces, err := c.Spaces(ctx)
		if err != nil {
			return err
		}
		for _, s := range spaces {
			if s.Kind == "team" {
				fmt.Printf("%s  %-8s %s\n", s.ID, s.Role, s.Name)
			}
		}
	case "backup":
		return backup(ctx, c, arg(0, ""))
	case "restore":
		data, err := os.ReadFile(arg(0, ""))
		if err != nil {
			return err
		}
		dir, err := c.Resolve(ctx, arg(1, ""))
		if err != nil {
			return err
		}
		n, err := c.RestoreContainer(ctx, dir.ID, data)
		if err == nil {
			fmt.Println("restored", n.Name)
		}
		return err
	case "export-keys":
		kb, err := c.ExportKeys(ctx)
		if err != nil {
			return err
		}
		raw, _ := json.MarshalIndent(kb, "", "  ")
		return writeAtomically(arg(0, "frontdir-keys.json"), func(w io.Writer) error { _, err := w.Write(raw); return err })
	}
	return nil
}

// backup saves the personal space in the same layout as the WebDAV mirror:
// node-ID file names (no plaintext names on the backup disk), encrypted
// folder records and unchanged containers. decrypt-tree reads it offline.
func backup(ctx context.Context, c *client.Client, dir string) error {
	if dir == "" {
		return errors.New("usage: backup <dir>")
	}
	me, err := c.Me(ctx)
	if err != nil {
		return err
	}
	sp := me.PersonalSpace
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	rec, _ := json.MarshalIndent(map[string]any{"format": "frontdir-space/v1", "id": sp.ID, "kind": sp.Kind, "rootId": sp.RootID,
		"nameEnc": sp.NameEnc, "rootKey": sp.RootKey}, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "_frontdir-space.json"), rec, 0o600); err != nil {
		return err
	}
	files := 0
	var walk func(id, local string) error
	walk = func(id, local string) error {
		if err := os.MkdirAll(local, 0o700); err != nil {
			return err
		}
		kids, err := c.List(ctx, id)
		if err != nil {
			return err
		}
		type entry struct {
			ID         string `json:"id"`
			Kind       string `json:"kind"`
			NameEnc    string `json:"nameEnc"`
			WrappedKey string `json:"wrappedKey"`
		}
		fr := struct {
			Format   string  `json:"format"`
			ID       string  `json:"id"`
			Children []entry `json:"children"`
		}{Format: "frontdir-folder/v1", ID: id}
		for _, k := range kids {
			fr.Children = append(fr.Children, entry{k.ID, k.Kind, k.NameEnc, k.WrappedKey})
			if k.Kind == "folder" {
				if err := walk(k.ID, filepath.Join(local, k.ID)); err != nil {
					return err
				}
				continue
			}
			if err := writeAtomically(filepath.Join(local, k.ID+".fdenc"), func(w io.Writer) error {
				return c.DownloadContainer(ctx, k.ID, w)
			}); err != nil {
				return err
			}
			files++
		}
		raw, _ := json.MarshalIndent(fr, "", "  ")
		return os.WriteFile(filepath.Join(local, "_frontdir-folder.json"), raw, 0o600)
	}
	if err := walk(sp.RootID, dir); err != nil {
		return err
	}
	fmt.Printf("backed up %d files (still encrypted) to %s\nkeep a key backup (export-keys) to decrypt them without the server\n", files, dir)
	return nil
}

func offline(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	keysFile := fs.String("keys", "", "key backup file (from export-keys or the web app)")
	recovery := fs.Bool("recovery", false, "unlock with the recovery code instead of the passphrase")
	var pos []string
	for len(args) > 0 { // allow flags before or after positional arguments
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if *keysFile == "" || len(pos) != 2 {
		usage()
	}
	data, err := os.ReadFile(*keysFile) // #nosec G304 G703 -- the key backup the user named
	if err != nil {
		return err
	}
	prompt := "Encryption passphrase: "
	if *recovery {
		prompt = "Recovery code: "
	}
	pass, err := secret("FRONTDIR_PASSPHRASE_FILE", prompt)
	if err != nil {
		return err
	}
	keys, err := client.UnlockBackup(data, pass, *recovery)
	if err != nil {
		return err
	}
	switch cmd {
	case "decrypt":
		in, err := os.Open(pos[0]) // #nosec G304 G703 -- the container the user asked to decrypt
		if err != nil {
			return err
		}
		defer in.Close()
		return writeAtomically(pos[1], func(w io.Writer) error {
			meta, err := keys.DecryptContainer(in, w, nil)
			if err == nil {
				fmt.Fprintf(os.Stderr, "decrypted %q (signature verified)\n", meta.Name)
			}
			return err
		})
	case "decrypt-tree":
		n, skipped, err := keys.DecryptTree(pos[0], pos[1], nil)
		fmt.Fprintf(os.Stderr, "decrypted %d files into %s\n", n, pos[1])
		for _, s := range skipped {
			fmt.Fprintf(os.Stderr, "skipped (signed by another user; verify their key to include it): %s\n", s)
		}
		return err
	}
	return nil
}

// writeAtomically writes to a temporary file and renames it into place only
// on success, so a failed decryption never leaves partial plaintext behind.
func writeAtomically(dst string, fn func(io.Writer) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".frontdir-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if err := fn(tmp); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst) // #nosec G703 -- the destination the user asked for
}
