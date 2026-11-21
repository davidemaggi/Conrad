// Command conrad is a self-hosted certificate authority with an ACME server.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/davidemaggi/conrad/internal/auth"
	"github.com/davidemaggi/conrad/internal/ca"
	"github.com/davidemaggi/conrad/internal/config"
	"github.com/davidemaggi/conrad/internal/crypto/signer"
	"github.com/davidemaggi/conrad/internal/server"
	"github.com/davidemaggi/conrad/internal/store"
)

// Set by the linker (-X main.version=...).
var version = "dev"

const usage = `Conrad — a self-hosted CA with an ACME server. Every certificate gets its stamp.

Usage:
  conrad serve        [-config file]   run the server (default)
  conrad init         [-config file] -admin-user U [-cn NAME] [-issuer SLUG]
                      headless setup: create the CA and the admin
                      (password from CONRAD_ADMIN_PASSWORD, passphrase from CONRAD_CA_PASSPHRASE)
  conrad backup       [-config file] FILE     consistent online copy of the database
  conrad restore      [-config file] FILE     replace the database (server must be stopped)
  conrad reset-admin  [-config file]          new admin password, re-enable password login, end sessions
  conrad healthcheck  [-config file]          exit 0 if the local server answers /healthz (for containers)
  conrad version
`

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "init":
		err = initCmd(args)
	case "backup":
		err = backup(args)
	case "restore":
		err = restore(args)
	case "reset-admin":
		err = resetAdmin(args)
	case "healthcheck":
		err = healthcheck(args)
	case "version":
		fmt.Println("conrad", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "conrad:", err)
		os.Exit(1)
	}
}

func loadConfig(fs *flag.FlagSet, args []string) (*config.Config, error) {
	path := fs.String("config", os.Getenv("CONRAD_CONFIG"), "YAML config file (optional)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return config.Load(*path)
}

func newLogger(cfg *config.Config) *slog.Logger {
	var lvl slog.Level
	_ = lvl.UnmarshalText([]byte(cfg.Log.Level))
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler = slog.NewTextHandler(os.Stderr, opts)
	if cfg.Log.Format == "json" {
		h = slog.NewJSONHandler(os.Stderr, opts)
	}
	return slog.New(h)
}

func serve(args []string) error {
	cfg, err := loadConfig(flag.NewFlagSet("serve", flag.ExitOnError), args)
	if err != nil {
		return err
	}
	log := newLogger(cfg)
	slog.SetDefault(log)
	s, err := server.New(cfg, log, version)
	if err != nil {
		return err
	}
	defer s.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("starting Conrad", "version", version, "data_dir", cfg.DataDir)
	return s.Run(ctx)
}

func initCmd(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	user := fs.String("admin-user", "admin", "admin username")
	lang := fs.String("language", "en", "admin UI language (en, it)")
	cn := fs.String("cn", "Conrad Root CA", "root common name")
	org := fs.String("org", "", "root organization")
	alg := fs.String("algorithm", string(signer.ECDSAP384), "root key algorithm")
	slug := fs.String("issuer", "default", "first issuer slug")
	rootYears := fs.Int("root-years", 10, "root validity (years)")
	issYears := fs.Int("issuer-years", 3, "issuer validity (years)")
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	pw := os.Getenv("CONRAD_ADMIN_PASSWORD")
	if pw == "" {
		return errors.New("set CONRAD_ADMIN_PASSWORD")
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		return err
	}
	secret := cfg.CAPassphrase
	if cfg.PKCS11.Module != "" {
		secret = cfg.PKCS11.PIN
	}
	if secret == "" {
		return errors.New("set CONRAD_CA_PASSPHRASE (or the PKCS#11 PIN)")
	}
	s, err := server.New(cfg, newLogger(cfg), version)
	if err != nil {
		return err
	}
	defer s.Close()
	ctx := context.Background()
	if has, _ := s.Store.HasAdmin(ctx); has {
		return errors.New("already set up")
	}
	y := func(n int) time.Duration { return time.Duration(n) * 365 * 24 * time.Hour }
	root, iss, err := s.CA.Init(ctx, ca.InitRequest{
		Secret: secret, Subject: ca.Subject{CommonName: *cn, Organization: *org}, Algorithm: signer.Algorithm(*alg), Validity: y(*rootYears),
		Issuer: ca.IssuerRequest{Slug: *slug, Name: *slug, Validity: y(*issYears)},
	})
	if err != nil {
		return err
	}
	if err := s.Store.CreateAdmin(ctx, &store.Admin{Username: *user, PasswordHash: hash, Language: *lang}); err != nil {
		return err
	}
	s.Audit.Record(ctx, "cli", "setup.completed", *user, "", map[string]any{"root": root.ID, "issuer": iss.Slug})
	fmt.Printf("CA ready.\n  root:      %s\n  issuer:    %s\n  directory: %s/acme/%s/directory\n  root cert: %s/roots/current.crt\n",
		root.ID, iss.Slug, s.BaseURL, iss.Slug, s.BaseURL)
	return nil
}

func backup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: conrad backup FILE")
	}
	st, err := store.Open(cfg.DBPath())
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Backup(context.Background(), fs.Arg(0)); err != nil {
		return err
	}
	fmt.Println("backup written to", fs.Arg(0), "(keep it with your CA passphrase: keys are encrypted with it)")
	return nil
}

func restore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: conrad restore FILE")
	}
	src := fs.Arg(0)
	// Validate the backup by opening it (runs migrations on a copy check).
	chk, err := store.Open(src)
	if err != nil {
		return fmt.Errorf("not a valid Conrad database: %w", err)
	}
	if has, err := chk.HasAuthorities(context.Background()); err != nil || !has {
		chk.Close()
		return errors.New("backup contains no CA")
	}
	chk.Close()
	dst := cfg.DBPath()
	if _, err := os.Stat(dst); err == nil {
		old := dst + "." + time.Now().Format("20060102-150405") + ".bak"
		if err := os.Rename(dst, old); err != nil {
			return err
		}
		fmt.Println("previous database moved to", old)
	}
	for _, suf := range []string{"-wal", "-shm"} {
		_ = os.Remove(dst + suf)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	fmt.Println("restored. Start the server and unlock the CA with the passphrase used for that backup.")
	return nil
}

func resetAdmin(args []string) error {
	fs := flag.NewFlagSet("reset-admin", flag.ExitOnError)
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DBPath())
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	ad, err := st.GetAdmin(ctx)
	if err != nil {
		return errors.New("no admin yet: complete setup first")
	}
	pw := os.Getenv("CONRAD_ADMIN_PASSWORD")
	generated := pw == ""
	if generated {
		pw = auth.RandomToken(15)
	}
	if ad.PasswordHash, err = auth.HashPassword(pw); err != nil {
		return err
	}
	if err := st.UpdateAdmin(ctx, ad); err != nil {
		return err
	}
	if err := st.SetSetting(ctx, "auth.password_login", "true"); err != nil {
		return err
	}
	if err := st.DeleteAllSessions(ctx); err != nil {
		return err
	}
	_ = st.InsertAudit(ctx, &store.AuditEntry{Actor: "cli", Action: "auth.admin_reset", Target: ad.Username})
	fmt.Println("admin:", ad.Username)
	if generated {
		fmt.Println("new password:", pw)
	}
	fmt.Println("password login re-enabled; all sessions ended.")
	return nil
}

// healthcheck probes the local listener; TLS is not verified because it targets loopback.
func healthcheck(args []string) error {
	cfg, err := loadConfig(flag.NewFlagSet("healthcheck", flag.ExitOnError), args)
	if err != nil {
		return err
	}
	_, port, err := net.SplitHostPort(cfg.HTTPSAddr)
	if err != nil {
		return err
	}
	scheme := "https"
	if cfg.TLSMode == config.TLSOff {
		scheme = "http"
	}
	c := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // loopback probe
	resp, err := c.Get(scheme + "://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz: %s", resp.Status)
	}
	return nil
}
