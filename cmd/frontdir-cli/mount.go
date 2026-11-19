package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/woah-buddy/FrontDir/internal/davgw"
	"github.com/woah-buddy/FrontDir/internal/secure"
)

// mount runs the local decrypting WebDAV gateway until interrupted.
func mount(ctx context.Context, args []string) error {
	fl := flag.NewFlagSet("mount", flag.ContinueOnError)
	listen := fl.String("listen", "127.0.0.1:8484", "loopback address to serve on")
	readOnly := fl.Bool("read-only", false, "refuse every change")
	urlFile := fl.String("url-file", "", "keep the secret part of the URL in this file (created if missing), so the address stays the same between runs")
	verbose := fl.Bool("v", false, "log WebDAV errors")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if err := davgw.CheckListen(*listen); err != nil {
		return err
	}
	token, err := mountToken(*urlFile)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer ln.Close()

	c, err := connect(ctx)
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "frontdir-mount-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	fsys := davgw.New(davgw.Options{Client: c, ReadOnly: *readOnly, TempDir: tmp, Log: log})
	addr := ln.Addr().String()
	srv := &http.Server{
		Handler:           davgw.Handler(fsys, token, addr, log),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       5 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}

	host, port, _ := net.SplitHostPort(addr)
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	u := fmt.Sprintf("http://%s:%s/%s/%s/", host, port, token, davgw.MountName)
	mode := "read and write"
	if *readOnly {
		mode = "read-only"
	}
	fmt.Fprintf(os.Stderr, `
Your files are available, decrypted, on this computer only (%s), at:

  %s

  macOS:   Finder > Go > Connect to Server, then paste the address.
  Windows: File Explorer > This PC > Map network drive > Connect to a Web site, or
           net use * %s
  Linux:   GNOME Files > Other Locations: dav://%s:%s/%s/%s/   (or davfs2)

Treat the address like a password: anyone on this computer who has it can read your files
while this runs. Deleting moves items to the trash. Press Ctrl+C to stop and lock.
`, mode, u, u, host, port, token, davgw.MountName)

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	sig, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-sig.Done():
		fmt.Fprintln(os.Stderr, "stopping; unfinished uploads are discarded")
		shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
	}
	return nil
}

// mountToken returns the secret path segment: fresh each run, or kept in
// a file (mode 0600) for an address that survives restarts.
func mountToken(file string) (string, error) {
	if file == "" {
		return secure.NewToken(), nil
	}
	b, err := os.ReadFile(file) // #nosec G304 -- a path the user chose for their own token
	if err == nil {
		if t := strings.TrimSpace(string(b)); secure.ValidToken(t) {
			return t, nil
		}
		return "", fmt.Errorf("%s does not hold a valid token; delete it to create a new one", file)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	t := secure.NewToken()
	f, err := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- see above
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(t + "\n"); err != nil {
		_ = f.Close()
		return "", err
	}
	return t, f.Close()
}
