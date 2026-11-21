// Package server wires Conrad together: store, CA, ACME, API, web UI and listeners.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/davidemaggi/conrad/internal/acme"
	"github.com/davidemaggi/conrad/internal/api"
	"github.com/davidemaggi/conrad/internal/audit"
	"github.com/davidemaggi/conrad/internal/auth"
	"github.com/davidemaggi/conrad/internal/ca"
	"github.com/davidemaggi/conrad/internal/challenge"
	"github.com/davidemaggi/conrad/internal/config"
	"github.com/davidemaggi/conrad/internal/crypto/signer"
	"github.com/davidemaggi/conrad/internal/notify"
	"github.com/davidemaggi/conrad/internal/store"
	"github.com/davidemaggi/conrad/internal/web"
)

// NewPKCS11 is set by the pkcs11 build (see pkcs11.go); nil in default builds.
var NewPKCS11 func(cfg *config.Config) (signer.Provider, error)

// Server is a running Conrad instance.
type Server struct {
	Cfg     *config.Config
	Log     *slog.Logger
	Version string
	BaseURL string

	Store  *store.Store
	CA     *ca.Service
	ACME   *acme.Server
	API    *api.API
	Audit  *audit.Logger
	Notify *notify.Notifier
	Setup  *api.SetupToken

	// ACMEEvents receives ACME events after they are audited (notifications hook).
	ACMEEvents func(context.Context, acme.Event)
	// ExtraRoutes lets other packages register authenticated API routes.
	ExtraRoutes func(r *api.Router)

	tls tlsManager
}

// New opens the database and builds every component.
func New(cfg *config.Config, log *slog.Logger, version string) (*Server, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	st, err := store.Open(cfg.DBPath())
	if err != nil {
		return nil, err
	}
	keys, err := keyProvider(cfg)
	if err != nil {
		st.Close()
		return nil, err
	}
	s := &Server{Cfg: cfg, Log: log, Version: version, Store: st, BaseURL: baseURL(cfg)}
	s.CA = ca.New(st, keys, s.BaseURL, log)
	s.Audit = audit.New(st, log)
	s.Notify = notify.New(st, s.BaseURL, log)
	s.Audit.OnRecord = s.Notify.FromAudit
	s.tls = tlsManager{s: s, dir: cfg.DataDir + "/tls"}

	v := &challenge.Validator{HTTPPort: cfg.ChallengePorts.HTTP, TLSPort: cfg.ChallengePorts.TLS, Resolvers: cfg.DNSResolvers}
	s.ACME = acme.New(s.CA, v, s.BaseURL, log)
	s.ACME.OnEvent = func(ctx context.Context, e acme.Event) {
		d := map[string]any{"issuer": e.IssuerSlug}
		for k, v := range e.Detail {
			d[k] = v
		}
		actor := "acme"
		if e.AccountID != "" {
			actor = "acme:" + e.AccountID
		}
		s.Audit.Record(ctx, actor, e.Type, e.Target, "", d)
		if s.ACMEEvents != nil {
			s.ACMEEvents(ctx, e)
		}
	}

	if has, _ := st.HasAdmin(context.Background()); !has {
		s.Setup = api.NewSetupToken()
	}
	secure := cfg.TLSMode == config.TLSSelf || strings.HasPrefix(s.BaseURL, "https://")
	s.API = api.New(api.Deps{
		Store: st, CA: s.CA, Sessions: auth.NewSessions(st, secure),
		OIDC:  auth.NewOIDC(st, s.BaseURL+"/api/v1/auth/oidc/callback"),
		Audit: s.Audit, Notifier: s.Notify, Log: log, Setup: s.Setup, BaseURL: s.BaseURL, DataDir: cfg.DataDir, Version: version,
		OnCAReady: func(ctx context.Context) { s.tls.refresh(ctx, true) },
		Extra: func(r *api.Router) {
			if s.ExtraRoutes != nil {
				s.ExtraRoutes(r)
			}
		},
	})
	return s, nil
}

func keyProvider(cfg *config.Config) (signer.Provider, error) {
	if cfg.PKCS11.Module == "" {
		return signer.NewSoftware(), nil
	}
	if NewPKCS11 == nil {
		return nil, errors.New("pkcs11 is configured but this binary was built without PKCS#11 support (build tag pkcs11)")
	}
	return NewPKCS11(cfg)
}

// baseURL is the external URL used in certificates, ACME directories and links.
func baseURL(cfg *config.Config) string {
	if cfg.ExternalURL != "" {
		return strings.TrimRight(cfg.ExternalURL, "/")
	}
	host := "localhost"
	if len(cfg.Hostnames) > 0 {
		host = cfg.Hostnames[0]
	} else if h, err := os.Hostname(); err == nil && h != "" {
		host = strings.ToLower(h)
	}
	scheme := "https"
	if cfg.TLSMode == config.TLSOff {
		scheme = "http"
	}
	_, port, _ := net.SplitHostPort(cfg.HTTPSAddr)
	if port != "" && !(scheme == "https" && port == "443") && !(scheme == "http" && port == "80") {
		host = net.JoinHostPort(host, port)
	}
	return scheme + "://" + host
}

// serverHosts are the names on Conrad's own TLS certificate.
func (s *Server) serverHosts() []string {
	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	if u, err := url.Parse(s.BaseURL); err == nil {
		add(u.Hostname())
	}
	for _, h := range s.Cfg.Hostnames {
		add(h)
	}
	return out
}

// Close releases resources.
func (s *Server) Close() error { return s.Store.Close() }

// Handler returns the full HTTPS route tree.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.public(mux)
	mux.Handle("/acme/", s.ACME.Handler())
	mux.Handle("/api/v1/", s.API.Handler())
	mux.Handle("/", spaHeaders(web.Handler()))
	return s.common(mux)
}

// plainHandler serves the HTTP (:80) listener: public PKI files plus a redirect to HTTPS.
func (s *Server) plainHandler() http.Handler {
	mux := http.NewServeMux()
	s.public(mux)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		u, err := url.Parse(s.BaseURL)
		if err != nil || u.Scheme != "https" {
			http.NotFound(w, r)
			return
		}
		u.Path, u.RawQuery = r.URL.Path, r.URL.RawQuery
		http.Redirect(w, r, u.String(), http.StatusMovedPermanently)
	})
	return s.common(mux)
}

func (s *Server) common(h http.Handler) http.Handler {
	hsts := s.Cfg.TLSMode == config.TLSSelf
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		if hsts && r.TLS != nil {
			hd.Set("Strict-Transport-Security", "max-age=31536000")
		}
		h.ServeHTTP(w, r)
	})
}

func spaHeaders(h http.Handler) http.Handler {
	const csp = "default-src 'self'; img-src 'self' data:; font-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; " +
		"connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("X-Frame-Options", "DENY")
		h.ServeHTTP(w, r)
	})
}

// Run starts background work and listeners until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	if s.Setup != nil {
		s.Log.Warn("first run: open the web UI and complete setup with this one-time token",
			"url", s.BaseURL, "setup_token", s.Setup.Value())
	}
	s.autoUnlock(ctx)
	s.ACME.Start(ctx)
	if s.Cfg.TLSMode == config.TLSSelf {
		if err := s.tls.refresh(ctx, false); err != nil {
			return err
		}
	}
	go s.housekeeping(ctx)
	go s.Notify.RunScheduler(ctx, 6*time.Hour)

	var servers []*http.Server
	main := &http.Server{Addr: s.Cfg.HTTPSAddr, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second, ErrorLog: slog.NewLogLogger(s.Log.Handler(), slog.LevelDebug)}
	servers = append(servers, main)
	if s.Cfg.HTTPAddr != "" && s.Cfg.TLSMode == config.TLSSelf {
		servers = append(servers, &http.Server{Addr: s.Cfg.HTTPAddr, Handler: s.plainHandler(), ReadHeaderTimeout: 10 * time.Second})
	}
	errc := make(chan error, len(servers))
	var wg sync.WaitGroup
	for i, srv := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			if i == 0 && s.Cfg.TLSMode == config.TLSSelf {
				srv.TLSConfig = s.tls.config()
				s.Log.Info("listening (https)", "addr", srv.Addr, "url", s.BaseURL)
				err = srv.ListenAndServeTLS("", "")
			} else {
				s.Log.Info("listening (http)", "addr", srv.Addr)
				err = srv.ListenAndServe()
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("%s: %w", srv.Addr, err)
			}
		}()
	}
	var err error
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shut)
	}
	wg.Wait()
	s.Notify.Wait()
	return err
}

func (s *Server) autoUnlock(ctx context.Context) {
	secret := s.Cfg.CAPassphrase
	if s.Cfg.PKCS11.Module != "" {
		secret = s.Cfg.PKCS11.PIN
	}
	if init, _ := s.CA.Initialized(ctx); !init || !s.CA.Locked() {
		return
	}
	if secret == "" {
		s.Log.Warn("CA is locked: unlock it from the web UI (or set CONRAD_CA_PASSPHRASE)")
		s.Notify.CALockedAlert(ctx)
		return
	}
	if err := s.CA.Unlock(ctx, secret); err != nil {
		s.Log.Error("automatic CA unlock failed", "err", err)
		s.Notify.CALockedAlert(ctx)
		return
	}
	s.Audit.Record(ctx, "system", "ca.unlocked", "", "", map[string]any{"automatic": true})
}

func (s *Server) housekeeping(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		_ = s.Store.PurgeSessions(ctx, s.Store.Now().Add(-12*time.Hour))
		if !s.CA.Locked() {
			if err := s.CA.RetireExpired(ctx); err != nil {
				s.Log.Warn("retire expired authorities", "err", err)
			}
			if s.Cfg.TLSMode == config.TLSSelf {
				_ = s.tls.refresh(ctx, false)
			}
		}
	}
}
