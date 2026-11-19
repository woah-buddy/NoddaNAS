// Package web embeds the static web client into the NoddaNAS binary, so a
// deployment is a single file with no separate asset server to secure.
package web

import (
	"embed"
	"io/fs"
)

//go:embed static
var static embed.FS

// Static returns the web client's files.
func Static() fs.FS {
	sub, err := fs.Sub(static, "static")
	if err != nil {
		panic(err)
	}
	return sub
}
