// Command noddanas is the NoddaNAS server and admin tool.
//
//	noddanas serve                 run the server (default)
//	noddanas migrate               apply database migrations and exit
//	noddanas set-quota EMAIL SIZE  set a user's personal storage quota (e.g. 50GiB)
//	noddanas healthcheck           probe the local server (for container HEALTHCHECK)
//	noddanas version               print the version
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/woah-buddy/NoddaNAS/internal/auth"
	"github.com/woah-buddy/NoddaNAS/internal/blob/fsblob"
	"github.com/woah-buddy/NoddaNAS/internal/config"
	"github.com/woah-buddy/NoddaNAS/internal/httpapi"
	"github.com/woah-buddy/NoddaNAS/internal/service"
	"github.com/woah-buddy/NoddaNAS/internal/store/postgres"
	"github.com/woah-buddy/NoddaNAS/web"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve()
	case "migrate":
		err = migrate()
	case "set-quota":
		err = setQuota(os.Args[2:])
	case "healthcheck":
		err = healthcheck()
	case "version":
		fmt.Println(version)
	default:
		err = fmt.Errorf("unknown command %q (try: serve, migrate, set-quota, healthcheck, version)", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "noddanas:", err)
		os.Exit(1)
	}
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}

func serve() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration:\n%w", err)
	}
	log := newLogger(cfg.LogLevel)
	slog.SetDefault(log)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store, err := postgres.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer store.Close()
	if cfg.AutoMigrate {
		if err := store.Migrate(ctx); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	blobs, err := fsblob.New(cfg.DataDir)
	if err != nil {
		return err
	}

	svc := service.New(store, blobs, cfg.Service, log)
	var oidc *auth.OIDC
	var saml *auth.SAML
	if cfg.OIDC != nil {
		oidc = auth.NewOIDC(*cfg.OIDC)
	}
	if cfg.SAML != nil {
		saml = auth.NewSAML(*cfg.SAML)
		if !cfg.SAML.TrustEmail {
			log.Info("SAML emails are not treated as verified; set NODDANAS_SAML_TRUST_EMAIL=true if your IdP verifies them (needed for sharing by email)")
		}
	}
	am := auth.NewManager(store, svc, cfg.Auth, oidc, saml)
	if cfg.Policy.Open() {
		log.Warn("no sign-in policy set: every account your identity provider authenticates can sign in " +
			"(set NODDANAS_ALLOWED_GROUPS or NODDANAS_ALLOWED_EMAIL_DOMAINS)")
	}
	api := httpapi.New(svc, am, httpapi.Config{
		PublicURL: cfg.PublicURL, TrustedProxies: cfg.TrustedProxies, EnableWebDAV: cfg.WebDAV,
	}, log, web.Static(), store, blobs)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}

	if cfg.Worker {
		go svc.RunWorker(ctx, time.Minute)
		go func() {
			t := time.NewTicker(15 * time.Minute)
			defer t.Stop()
			for {
				if err := am.Cleanup(ctx); err != nil && ctx.Err() == nil {
					log.Error("auth cleanup", "err", err)
				}
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
			}
		}()
	}

	errc := make(chan error, 1)
	go func() {
		log.Info("noddanas listening", "addr", cfg.Listen, "public_url", cfg.PublicURL.String(), "version", version,
			"webdav", cfg.WebDAV, "worker", cfg.Worker)
		if cfg.TLSCertFile != "" {
			errc <- srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			errc <- srv.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		log.Info("shutting down")
		shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
	return nil
}

func migrate() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration:\n%w", err)
	}
	store, err := postgres.Open(context.Background(), cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer store.Close()
	return store.Migrate(context.Background())
}

func setQuota(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: noddanas set-quota EMAIL SIZE (e.g. 50GiB)")
	}
	size, err := config.ParseSize(args[1])
	if err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration:\n%w", err)
	}
	log := newLogger("warn")
	store, err := postgres.Open(context.Background(), cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer store.Close()
	blobs, err := fsblob.New(cfg.DataDir)
	if err != nil {
		return err
	}
	svc := service.New(store, blobs, cfg.Service, log)
	if err := svc.SetUserQuotaByEmail(context.Background(), args[0], size); err != nil {
		return err
	}
	fmt.Printf("quota for %s set to %d bytes\n", args[0], size)
	return nil
}

// healthcheck lets a distroless image (no shell, no curl) define a
// container HEALTHCHECK.
func healthcheck() error {
	addr := os.Getenv("NODDANAS_LISTEN")
	if addr == "" {
		addr = ":8080"
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	scheme := "http"
	if os.Getenv("NODDANAS_TLS_CERT_FILE") != "" {
		scheme = "https"
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		// Loopback probe of our own listener; the certificate names the
		// public host, not 127.0.0.1.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // loopback self-probe only
	}}
	resp, err := client.Get(scheme + "://" + addr + "/healthz")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unhealthy: %s", resp.Status)
	}
	return nil
}
