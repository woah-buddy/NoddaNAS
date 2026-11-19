// Command noddanas is the NoddaNAS server and admin tool.
//
//	noddanas serve                 run the server (default)
//	noddanas migrate               apply database migrations and exit
//	noddanas set-quota EMAIL SIZE  set a user's personal storage quota (e.g. 50GiB)
//	noddanas revoke-links --user EMAIL|ID | --all
//	                               revoke public links (break-glass; works without the web UI)
//	noddanas revoke-access --user EMAIL|ID
//	                               offboard: end sessions, delete app passwords, revoke links
//	noddanas revoke-sessions --all sign everyone out of every browser (e.g. after a restore)
//	noddanas verify-storage [--hash]
//	                               check every stored file is present and intact (no keys needed)
//	noddanas setup-link            print a one-time link to set up sign-in and become an administrator
//	noddanas settings show         list settings and where each value comes from (secrets hidden)
//	noddanas settings reset KEY|GROUP|all ...
//	                               clear settings saved in the web admin area (break-glass)
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
	"github.com/woah-buddy/NoddaNAS/internal/domain"
	"github.com/woah-buddy/NoddaNAS/internal/httpapi"
	"github.com/woah-buddy/NoddaNAS/internal/service"
	"github.com/woah-buddy/NoddaNAS/internal/settings"
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
	case "revoke-links":
		err = revokeLinks(os.Args[2:])
	case "revoke-access":
		err = revokeAccess(os.Args[2:])
	case "revoke-sessions":
		err = revokeSessions(os.Args[2:])
	case "verify-storage":
		err = verifyStorage(os.Args[2:])
	case "setup-link":
		err = setupLink(os.Args[2:])
	case "settings":
		err = settingsCmd(os.Args[2:])
	case "healthcheck":
		err = healthcheck()
	case "version":
		fmt.Println(version)
	default:
		err = fmt.Errorf("unknown command %q (try: serve, migrate, set-quota, revoke-links, revoke-access, revoke-sessions, verify-storage, setup-link, settings, healthcheck, version)", cmd)
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
	am := auth.NewManager(store, svc, cfg.Auth, nil, nil)
	// The settings manager merges the environment with settings saved in
	// the web admin area, applies them to the service and the sign-in
	// methods, and keeps them current.
	sm, err := settings.New(cfg, store, svc, am, log)
	if err != nil {
		return err
	}
	if err := sm.Load(ctx); err != nil {
		return err
	}
	rt := sm.Runtime()
	switch {
	case sm.SetupMode():
		log.Warn("NoddaNAS is not set up yet: no sign-in method is configured. " +
			"On the server, run `noddanas setup-link` for a one-time setup link (it is printed there, never logged)")
	case rt.Policy.Open():
		log.Warn("no sign-in policy set: every account your identity provider authenticates can sign in " +
			"(set allowed groups or email domains in the admin area, or NODDANAS_ALLOWED_GROUPS / NODDANAS_ALLOWED_EMAIL_DOMAINS)")
	}
	if rt.SAML != nil && !rt.SAML.TrustEmail {
		log.Info("SAML emails are not treated as verified; turn on \"trust asserted emails\" if your IdP verifies them (needed for sharing by email)")
	}
	if cfg.SettingsKey == nil {
		log.Info("NODDANAS_SETTINGS_KEY is not set: secrets such as the OIDC client secret cannot be saved from the web admin area")
	}
	api := httpapi.New(svc, am, httpapi.Config{
		PublicURL: cfg.PublicURL, TrustedProxies: cfg.TrustedProxies, EnableWebDAV: cfg.WebDAV, Theme: rt.Theme, Settings: sm,
	}, log, web.Static(), store, blobs)
	sm.OnApply(func(rt *config.Runtime) { api.SetTheme(rt.Theme) })
	// Other replicas may save settings too; pick their changes up.
	go sm.Watch(ctx, 15*time.Second)

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

// setupLink prints a one-time setup link. It goes to this terminal only:
// whoever opens it can choose the identity provider and become an
// administrator, so it is never written to a log.
func setupLink(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: noddanas setup-link")
	}
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration:\n%w", err)
	}
	store, err := postgres.Open(context.Background(), cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer store.Close()
	link, exp, err := settings.NewSetupLink(context.Background(), store, cfg, time.Now().UTC())
	if err != nil {
		return err
	}
	fmt.Printf("Open this link to set up sign-in. The first person to sign in through it becomes an administrator.\n\n  %s\n\n"+
		"It works once, until %s, and replaces any earlier setup link. Treat it like a password: share it only with\n"+
		"the person setting up NoddaNAS, over a channel you trust.\n", link, exp.Format(time.RFC1123))
	return nil
}

// settingsCmd lists or clears settings saved in the web admin area. Reset
// is the way out when saved settings stop the server from starting, or
// lock everyone out; running servers pick the change up within seconds.
func settingsCmd(args []string) error {
	const usage = "usage: noddanas settings show\n       noddanas settings reset KEY|GROUP|all ...   (e.g. OIDC_CLIENT_SECRET, oidc, saml, branding)"
	if len(args) == 0 || args[0] != "show" && args[0] != "reset" || args[0] == "show" && len(args) != 1 || args[0] == "reset" && len(args) < 2 {
		return errors.New(usage)
	}
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration:\n%w", err)
	}
	store, err := postgres.Open(context.Background(), cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer store.Close()
	ctx := context.Background()
	if args[0] == "show" {
		lines, err := settings.Describe(ctx, cfg, store)
		if err != nil {
			return err
		}
		fmt.Printf("%-24s %-8s %s\n", "SETTING", "SOURCE", "VALUE")
		for _, l := range lines {
			fmt.Println(l)
		}
		return nil
	}
	removed, err := settings.Reset(ctx, store, args[1:], time.Now().UTC())
	if err != nil {
		return err
	}
	if len(removed) == 0 {
		fmt.Println("nothing to reset: none of those settings is saved in the web admin area")
		return nil
	}
	newLogger("info").Info("audit", "event", "settings.reset", "user", "cli", "keys", removed)
	fmt.Printf("reset %s (back to the environment or the default)\n", strings.Join(removed, ", "))
	return nil
}

// operator is the service and auth layer opened directly against the
// database, for commands run from the server's shell.
type operator struct {
	svc   *service.Service
	auth  *auth.Manager
	store *postgres.Store
	log   *slog.Logger
}

func adminService() (*operator, func(), error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, fmt.Errorf("configuration:\n%w", err)
	}
	store, err := postgres.Open(context.Background(), cfg.DatabaseURL)
	if err != nil {
		return nil, nil, err
	}
	blobs, err := fsblob.New(cfg.DataDir)
	if err != nil {
		store.Close()
		return nil, nil, err
	}
	// Operator actions are audited to stdout like the server's own events.
	log := newLogger("info")
	svc := service.New(store, blobs, cfg.Service, log)
	return &operator{svc: svc, auth: auth.NewManager(store, svc, cfg.Auth, nil, nil), store: store, log: log}, store.Close, nil
}

func setQuota(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: noddanas set-quota EMAIL SIZE (e.g. 50GiB)")
	}
	size, err := config.ParseSize(args[1])
	if err != nil {
		return err
	}
	op, closeFn, err := adminService()
	if err != nil {
		return err
	}
	defer closeFn()
	if err := op.svc.SetUserQuotaByEmail(context.Background(), args[0], size); err != nil {
		return err
	}
	fmt.Printf("quota for %s set to %d bytes\n", args[0], size)
	return nil
}

// revokeLinks is the break-glass kill switch for public links. It needs no
// web session, so it works even if the UI is down or admin accounts are
// compromised. The scope must be stated explicitly: there is no default.
func revokeLinks(args []string) error {
	const usage = "usage: noddanas revoke-links --user EMAIL|ID   (one user's links)\n" +
		"       noddanas revoke-links --all             (every public link on this instance)"
	var all bool
	var who string
	switch {
	case len(args) == 1 && args[0] == "--all":
		all = true
	case len(args) == 2 && args[0] == "--user" && args[1] != "":
		who = args[1]
	default:
		return errors.New(usage)
	}
	op, closeFn, err := adminService()
	if err != nil {
		return err
	}
	defer closeFn()
	var n int64
	if all {
		n, err = op.svc.OperatorRevokeAllLinks(context.Background())
	} else {
		var u *domain.User
		if u, err = op.svc.OperatorFindUser(context.Background(), who); err != nil {
			return fmt.Errorf("%s: %w", who, err)
		}
		n, err = op.svc.OperatorRevokeLinks(context.Background(), u.ID)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "revoked %d public link(s)\n", n)
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
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- loopback self-probe of our own listener
	}}
	resp, err := client.Get(scheme + "://" + addr + "/healthz") // #nosec G704 -- loopback address from our own listen setting
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unhealthy: %s", resp.Status)
	}
	return nil
}

// revokeAccess offboards a user: every browser session ends, every app
// password stops working, and every public link they created is revoked.
// Remove the user from the identity provider (or the allowed groups) first,
// or they can simply sign in again. Their files and team memberships are
// left in place for an administrator to reassign or remove.
func revokeAccess(args []string) error {
	if len(args) != 2 || args[0] != "--user" || args[1] == "" {
		return errors.New("usage: noddanas revoke-access --user EMAIL|ID")
	}
	op, closeFn, err := adminService()
	if err != nil {
		return err
	}
	defer closeFn()
	ctx := context.Background()
	u, err := op.svc.OperatorFindUser(ctx, args[1])
	if err != nil {
		return fmt.Errorf("%s: %w", args[1], err)
	}
	apps, err := op.auth.RevokeUserCredentials(ctx, u.ID)
	if err != nil {
		return err
	}
	links, err := op.svc.OperatorRevokeLinks(ctx, u.ID)
	if err != nil {
		return err
	}
	op.log.Warn("audit", "event", "operator.access.revoke", "actor", "cli", "target", u.ID, "app_passwords", apps, "links", links)
	fmt.Fprintf(os.Stderr, "%s (%s): all sessions ended, %d app password(s) and %d public link(s) revoked\n",
		u.ID, u.DisplayName, apps, links)
	return nil
}

// revokeSessions signs every user out. After restoring a backup, sessions
// that had ended since the backup was taken exist again; this ends them all,
// so everyone signs in afresh through the identity provider's current rules.
func revokeSessions(args []string) error {
	if len(args) != 1 || args[0] != "--all" {
		return errors.New("usage: noddanas revoke-sessions --all")
	}
	op, closeFn, err := adminService()
	if err != nil {
		return err
	}
	defer closeFn()
	n, err := op.auth.EndEverySession(context.Background())
	if err != nil {
		return err
	}
	op.log.Warn("audit", "event", "operator.sessions.revoke_all", "actor", "cli", "count", n)
	fmt.Fprintf(os.Stderr, "ended %d browser session(s); app passwords are unchanged\n", n)
	return nil
}

// verifyStorage checks that every file version recorded in the database has
// its encrypted container in storage, with the right size and, with --hash,
// the right SHA-256. It reads only ciphertext and needs no keys.
func verifyStorage(args []string) error {
	hash := false
	switch {
	case len(args) == 0:
	case len(args) == 1 && args[0] == "--hash":
		hash = true
	default:
		return errors.New("usage: noddanas verify-storage [--hash]")
	}
	op, closeFn, err := adminService()
	if err != nil {
		return err
	}
	defer closeFn()
	r, err := op.svc.OperatorVerifyStorage(context.Background(), hash)
	if err != nil {
		return err
	}
	how := "sizes checked"
	if hash {
		how = "sizes and SHA-256 checked"
	}
	fmt.Printf("%d file versions, %d bytes of ciphertext (%s)\n", r.Versions, r.Bytes, how)
	for _, g := range []struct {
		label string
		list  []service.StorageProblem
	}{{"missing", r.Missing}, {"wrong size", r.WrongSize}, {"wrong SHA-256", r.WrongHash}} {
		fmt.Printf("%-14s %d\n", g.label+":", len(g.list))
		for i, p := range g.list {
			if i == 100 {
				fmt.Printf("  ... and %d more\n", len(g.list)-100)
				break
			}
			fmt.Printf("  space %s  node %s  version %s\n", p.SpaceID, p.NodeID, p.VersionID)
		}
	}
	if r.Orphans >= 0 {
		fmt.Printf("%-14s %d (stored but not referenced; harmless ciphertext)\n", "unreferenced:", r.Orphans)
	}
	if !r.OK() {
		return errors.New("storage verification failed")
	}
	fmt.Println("OK")
	return nil
}
