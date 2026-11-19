# Your files as a drive: `frontdir-cli mount`

`frontdir-cli mount` shows your FrontDir files, decrypted, as a network drive on your own
computer. You can open, edit, save, rename, move and delete them in Finder, File Explorer or GNOME
Files like any other folder. Nothing changes on the server's side: it still only ever receives
and stores ciphertext. The decryption happens in `frontdir-cli`, on your machine, with your keys.

Think of it as a translator sitting next to you: the server speaks only ciphertext, your file
manager only plaintext, and `frontdir-cli` translates between the two without leaving the room.

## Start it

You need `frontdir-cli` (`make cli`), an **app password** (Settings → App passwords; not
read-only if you want to make changes) and your encryption passphrase.

```sh
export FRONTDIR_URL=https://files.example.com
export FRONTDIR_TOKEN_FILE=~/.frontdir-token      # the app password, in a file only you can read
frontdir-cli mount
```

It asks for your passphrase, then prints an address like

```
http://127.0.0.1:8484/Jx3…Qk/FrontDir/
```

Keep it running while you use the drive. **Ctrl+C** stops it, which also locks your keys again.

| Option | Meaning |
|---|---|
| `--listen 127.0.0.1:8484` | Address and port on this computer. Only loopback addresses are accepted. |
| `--read-only` | Refuse every change. |
| `--url-file FILE` | Keep the secret part of the address in `FILE` (created with permissions 0600), so the address stays the same between runs and a saved Finder favourite keeps working. Without it, every run gets a new address. |
| `-v` | Log WebDAV errors. |

## Connect to it

- **macOS:** Finder → Go → Connect to Server (⌘K), paste the address, Connect. The drive appears
  as *FrontDir*. Add it to Favourites to reconnect later (with `--url-file`).
- **Windows:** File Explorer → This PC → Map network drive → "Connect to a Web site that you can
  use to store your documents and pictures", or in a terminal: `net use * <address>`. Windows'
  WebDAV client refuses files larger than 50 MB until you raise its limit: set
  `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WebClient\Parameters\FileSizeLimitInBytes`
  to `4294967295` (4 GB, the most it supports) and restart the *WebClient* service.
- **Linux:** GNOME Files → Other Locations → Connect to Server, with `dav://` instead of
  `http://`. Or mount it with davfs2, or use it as an rclone `webdav` remote.

## What you see

- **Home** is your personal space; each team folder you hold the key for appears beside it. Team
  folders where you only have read access are read-only.
- **Opening a file** fetches and decrypts only the parts that are read, so starting a video or
  previewing a large PDF does not download all of it first.
- **Saving** encrypts the file on your computer and uploads it as a new version (older versions
  stay available in the web app). A new file appears for everyone as soon as it is saved.
- **Deleting** moves items to the trash; restore them in the web app.
- **Moving** works within a space. To move something from Home into a team folder (or back),
  copy it and delete the original: the two spaces have different keys.
- **Clutter stays local.** `.DS_Store`, `._…` files, `Thumbs.db`, `desktop.ini` and Office lock
  files (`~$…`) that operating systems write to network drives live in `frontdir-cli`'s memory for
  the session and are never uploaded.

## How it keeps your files safe

- It listens on this computer only (127.0.0.1 or ::1); there is deliberately no option to serve
  the network.
- Every request must contain the random secret in the address, so other users of the same
  computer cannot browse it. Treat the address like a password while the drive runs.
- It refuses requests from web pages (they carry an `Origin` or `Sec-Fetch-Site` header) and
  requests for any other host name (which defeats DNS-rebinding tricks), and marks every response
  so that a browser could not run it as a page.
- Every piece of a file it hands out has been authenticated with AES-GCM under that file's key, so
  nobody without the key, the server included, can change anything unnoticed. When a file is read
  from start to finish (copying it, for example), the author's signature is checked before the
  last piece is handed out; if it fails, the copy fails and the drive refuses that file from then
  on. ([E2EE.md §5](E2EE.md#5-file-containers) explains the rule.)
- Large uploads are buffered on disk only in encrypted form, under a key that exists only in
  memory, and removed after upload.
- Your keys are in memory while it runs, so stop it when you do not need it.

Shared items from other people (Shared → Shared with me) are not shown on the drive yet; open them
in the web app.
