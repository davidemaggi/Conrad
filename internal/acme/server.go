// Package acme implements an RFC 8555 ACME server (with EAB, ARI and per-issuer directories).
package acme

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/davidemaggi/conrad/internal/ca"
	"github.com/davidemaggi/conrad/internal/challenge"
	"github.com/davidemaggi/conrad/internal/policy"
	"github.com/davidemaggi/conrad/internal/store"
)

// Lifetimes of ACME objects.
const (
	NonceTTL = time.Hour
	OrderTTL = 7 * 24 * time.Hour
)

// Event is emitted for audit logging and notifications.
type Event struct {
	Type       string // account.created, account.deactivated, account.keychange, order.created, challenge.valid, challenge.invalid, order.invalid, cert.issued, cert.revoked
	IssuerSlug string
	AccountID  string
	Target     string
	Detail     map[string]any
}

// Server serves ACME for every active issuer under /acme/{slug}/ (and /acme/directory for the default).
type Server struct {
	CA        *ca.Service
	Store     *store.Store
	Validator *challenge.Validator
	Log       *slog.Logger
	BaseURL   string // external URL without trailing slash
	// RetrySchedule is the delay before each validation attempt; failure is final after the last.
	RetrySchedule []time.Duration
	Workers       int
	OnEvent       func(context.Context, Event)

	queue   chan job
	limiter *ipLimiter
	once    sync.Once
}

// New creates a Server with sane defaults.
func New(c *ca.Service, v *challenge.Validator, baseURL string, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		CA: c, Store: c.Store(), Validator: v, Log: log, BaseURL: baseURL,
		RetrySchedule: []time.Duration{0, 2 * time.Second, 5 * time.Second, 10 * time.Second, 20 * time.Second, 25 * time.Second},
		Workers:       8,
	}
}

func (s *Server) init() {
	s.once.Do(func() {
		s.queue = make(chan job, 1024)
		s.limiter = &ipLimiter{hits: map[string][]time.Time{}}
	})
}

// Start launches validation workers and housekeeping until ctx ends.
func (s *Server) Start(ctx context.Context) {
	s.init()
	for i := 0; i < s.Workers; i++ {
		go s.worker(ctx)
	}
	// Resume validations interrupted by a restart.
	if chals, err := s.Store.ProcessingChallenges(ctx); err == nil {
		for _, c := range chals {
			s.enqueue(c.ID)
		}
	}
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = s.Store.PurgeNonces(ctx)
			}
		}
	}()
}

func (s *Server) emit(ctx context.Context, e Event) {
	if s.OnEvent != nil {
		s.OnEvent(ctx, e)
	}
}

func (s *Server) base(slug string) string { return s.BaseURL + "/acme/" + slug }

// Handler returns the ACME routes (paths start with /acme/).
func (s *Server) Handler() http.Handler {
	s.init()
	m := http.NewServeMux()
	m.HandleFunc("GET /acme/directory", s.wrap(s.directory, false))
	m.HandleFunc("GET /acme/{slug}/directory", s.wrap(s.directory, false))
	m.HandleFunc("HEAD /acme/{slug}/new-nonce", s.wrap(s.newNonce, false))
	m.HandleFunc("GET /acme/{slug}/new-nonce", s.wrap(s.newNonce, false))
	m.HandleFunc("POST /acme/{slug}/new-account", s.wrap(s.newAccount, true))
	m.HandleFunc("POST /acme/{slug}/account/{id}", s.wrap(s.account, true))
	m.HandleFunc("POST /acme/{slug}/account/{id}/orders", s.wrap(s.accountOrders, true))
	m.HandleFunc("POST /acme/{slug}/key-change", s.wrap(s.keyChange, true))
	m.HandleFunc("POST /acme/{slug}/new-order", s.wrap(s.newOrder, true))
	m.HandleFunc("POST /acme/{slug}/order/{id}", s.wrap(s.order, true))
	m.HandleFunc("POST /acme/{slug}/order/{id}/finalize", s.wrap(s.finalize, true))
	m.HandleFunc("POST /acme/{slug}/authz/{id}", s.wrap(s.authz, true))
	m.HandleFunc("POST /acme/{slug}/chall/{id}", s.wrap(s.challenge, true))
	m.HandleFunc("POST /acme/{slug}/cert/{id}", s.wrap(s.certificate, true))
	m.HandleFunc("POST /acme/{slug}/revoke-cert", s.wrap(s.revokeCert, true))
	m.HandleFunc("GET /acme/{slug}/renewal-info/{certid...}", s.wrap(s.renewalInfo, false))
	return m
}

type handlerFunc func(w http.ResponseWriter, r *http.Request, slug string) *Problem

// wrap resolves the issuer, adds Replay-Nonce/Link headers and renders problems.
func (s *Server) wrap(h handlerFunc, post bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slug := r.PathValue("slug")
		iss, err := s.CA.Issuer(r.Context(), slug)
		if err != nil {
			if errors.Is(err, ca.ErrIssuerNotFound) || errors.Is(err, ca.ErrIssuerInactive) || errors.Is(err, store.ErrNotFound) {
				writeProblem(w, notFoundP("no active issuer %q", slug))
			} else {
				writeProblem(w, serverErr("%v", err))
			}
			return
		}
		slug = iss.Slug
		if n, err := s.Store.NewNonce(r.Context(), NonceTTL); err == nil {
			w.Header().Set("Replay-Nonce", n)
		}
		w.Header().Set("Cache-Control", "no-store")
		if post || r.URL.Path != "/acme/directory" {
			w.Header().Add("Link", `<`+s.base(slug)+`/directory>;rel="index"`)
		}
		if p := h(w, r, slug); p != nil {
			if p.Status >= 500 {
				s.Log.Error("acme", "path", r.URL.Path, "err", p.Detail)
			}
			writeProblem(w, p)
		}
	}
}

func (s *Server) directory(w http.ResponseWriter, r *http.Request, slug string) *Problem {
	pol, err := policy.Load(r.Context(), s.Store, slug)
	if err != nil {
		return serverErr("%v", err)
	}
	b := s.base(slug)
	writeJSON(w, 200, map[string]any{
		"newNonce":    b + "/new-nonce",
		"newAccount":  b + "/new-account",
		"newOrder":    b + "/new-order",
		"revokeCert":  b + "/revoke-cert",
		"keyChange":   b + "/key-change",
		"renewalInfo": b + "/renewal-info",
		"meta": map[string]any{
			"website":                 s.BaseURL,
			"externalAccountRequired": pol.RequireEAB,
		},
	})
	return nil
}

func (s *Server) newNonce(w http.ResponseWriter, r *http.Request, slug string) *Problem {
	if r.Method == http.MethodGet {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	return nil
}

// ipLimiter is a sliding one-hour window counter per client IP.
type ipLimiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func (l *ipLimiter) allow(ip string, limit int, now time.Time) bool {
	if limit <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := now.Add(-time.Hour)
	h := l.hits[ip][:0]
	for _, t := range l.hits[ip] {
		if t.After(cut) {
			h = append(h, t)
		}
	}
	if len(h) >= limit {
		l.hits[ip] = h
		return false
	}
	l.hits[ip] = append(h, now)
	return true
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
