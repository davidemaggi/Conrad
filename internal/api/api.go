// Package api is the JSON REST API used by the web UI (/api/v1).
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/davidemaggi/conrad/internal/audit"
	"github.com/davidemaggi/conrad/internal/auth"
	"github.com/davidemaggi/conrad/internal/ca"
	"github.com/davidemaggi/conrad/internal/notify"
	"github.com/davidemaggi/conrad/internal/store"
)

// Deps are the API's collaborators.
type Deps struct {
	Store    *store.Store
	CA       *ca.Service
	Sessions *auth.Sessions
	OIDC     *auth.OIDC
	Audit    *audit.Logger
	Log      *slog.Logger
	Setup    *SetupToken
	Notifier *notify.Notifier
	BaseURL  string
	DataDir  string
	Version  string
	// OnCAReady is called after the CA is initialized or unlocked (e.g. to install the TLS certificate).
	OnCAReady func(context.Context)
	// Extra lets later milestones (notifications) register routes on the authenticated mux.
	Extra func(r *Router)
}

// API serves /api/v1.
type API struct {
	Deps
	throttle *auth.Throttle
	setupMu  sync.Mutex
	started  time.Time
}

// New creates the API.
func New(d Deps) *API {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	return &API{Deps: d, throttle: auth.NewThrottle(), started: time.Now()}
}

// SetupToken guards the setup wizard with a one-time token printed at startup.
type SetupToken struct {
	mu    sync.Mutex
	token string
}

// NewSetupToken generates a token.
func NewSetupToken() *SetupToken { return &SetupToken{token: auth.RandomToken(18)} }

// Value returns the token ("" once consumed).
func (s *SetupToken) Value() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.token
}

func (s *SetupToken) check(t string) bool {
	v := s.Value()
	return v != "" && subtle.ConstantTimeCompare([]byte(v), []byte(t)) == 1
}

func (s *SetupToken) consume() {
	if s != nil {
		s.mu.Lock()
		s.token = ""
		s.mu.Unlock()
	}
}

// Router registers authenticated (session + CSRF) or public handlers.
type Router struct {
	a   *API
	mux *http.ServeMux
}

// Auth registers a handler that requires a valid session (and CSRF for unsafe methods).
func (r *Router) Auth(pattern string, h http.HandlerFunc) { r.mux.HandleFunc(pattern, r.a.authed(h)) }

// Public registers an unauthenticated handler.
func (r *Router) Public(pattern string, h http.HandlerFunc) { r.mux.HandleFunc(pattern, h) }

// Handler returns the routes (paths begin with /api/v1/).
func (a *API) Handler() http.Handler {
	r := &Router{a: a, mux: http.NewServeMux()}
	const p = "/api/v1"
	r.Public("GET "+p+"/system/status", a.status)
	r.Public("POST "+p+"/setup", a.setup)
	r.Public("POST "+p+"/auth/login", a.login)
	r.Public("GET "+p+"/auth/oidc/start", a.oidcStart)
	r.Public("GET "+p+"/auth/oidc/callback", a.oidcCallback)

	r.Auth("POST "+p+"/auth/logout", a.logout)
	r.Auth("GET "+p+"/auth/me", a.me)
	r.Auth("PUT "+p+"/auth/password", a.changePassword)
	r.Auth("PUT "+p+"/auth/profile", a.updateProfile)
	r.Auth("GET "+p+"/settings/auth", a.getAuthSettings)
	r.Auth("PUT "+p+"/settings/auth", a.putAuthSettings)
	r.Auth("POST "+p+"/ca/unlock", a.unlock)

	r.Auth("GET "+p+"/dashboard", a.dashboard)
	r.Auth("GET "+p+"/authorities", a.listAuthorities)
	r.Auth("POST "+p+"/authorities", a.createIssuer)
	r.Auth("POST "+p+"/authorities/successor-root", a.successorRoot)
	r.Auth("GET "+p+"/authorities/{id}", a.getAuthority)
	r.Auth("PATCH "+p+"/authorities/{id}", a.updateAuthority)
	r.Auth("POST "+p+"/authorities/{id}/default", a.setDefault)
	r.Auth("POST "+p+"/authorities/{id}/rotate", a.rotateIssuer)
	r.Auth("POST "+p+"/authorities/{id}/revoke", a.revokeIssuer)
	r.Auth("GET "+p+"/authorities/{id}/policy", a.getPolicy)
	r.Auth("PUT "+p+"/authorities/{id}/policy", a.putPolicy)
	r.Auth("GET "+p+"/authorities/{id}/eab-keys", a.listEAB)
	r.Auth("POST "+p+"/authorities/{id}/eab-keys", a.createEAB)
	r.Auth("DELETE "+p+"/authorities/{id}/eab-keys/{kid}", a.revokeEAB)

	r.Auth("GET "+p+"/certificates", a.listCertificates)
	r.Auth("POST "+p+"/certificates", a.issueCertificate)
	r.Auth("GET "+p+"/certificates/{id}", a.getCertificate)
	r.Auth("POST "+p+"/certificates/{id}/revoke", a.revokeCertificate)
	r.Auth("GET "+p+"/accounts", a.listAccounts)
	r.Auth("POST "+p+"/accounts/{id}/deactivate", a.deactivateAccount)

	r.Auth("GET "+p+"/notifications/channels", a.listChannels)
	r.Auth("POST "+p+"/notifications/channels", a.createChannel)
	r.Auth("PUT "+p+"/notifications/channels/{id}", a.updateChannel)
	r.Auth("DELETE "+p+"/notifications/channels/{id}", a.deleteChannel)
	r.Auth("POST "+p+"/notifications/channels/{id}/test", a.testChannel)
	r.Auth("POST "+p+"/notifications/test", a.testDraftChannel)
	r.Auth("GET "+p+"/notifications/settings", a.getNotifySettings)
	r.Auth("PUT "+p+"/notifications/settings", a.putNotifySettings)

	r.Auth("GET "+p+"/audit", a.listAudit)
	r.Auth("GET "+p+"/system/info", a.systemInfo)
	r.Auth("GET "+p+"/system/backup", a.backup)
	if a.Extra != nil {
		a.Extra(r)
	}
	r.mux.HandleFunc(p+"/", func(w http.ResponseWriter, _ *http.Request) {
		fail(w, http.StatusNotFound, "not_found", "unknown API endpoint")
	})
	return r.mux
}

type ctxKey struct{}

func (a *API) authed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, err := a.Sessions.Get(r)
		if err != nil {
			fail(w, http.StatusUnauthorized, "auth.required", "authentication required")
			return
		}
		if !auth.CheckCSRF(r, s) {
			fail(w, http.StatusForbidden, "auth.csrf", "missing or invalid CSRF token")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, s)))
	}
}

// ---- helpers ----

// Error is the API error shape; Code doubles as the UI i18n key.
type Error struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

func fail(w http.ResponseWriter, status int, code, msg string) {
	failDetails(w, status, code, msg, nil)
}

func failDetails(w http.ResponseWriter, status int, code, msg string, d map[string]any) {
	writeJSON(w, status, Error{Code: code, Message: msg, Details: d})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		fail(w, http.StatusBadRequest, "validation", "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

// failErr maps domain errors to API errors.
func (a *API) failErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ca.ErrLocked):
		fail(w, http.StatusLocked, "ca.locked", "the CA is locked")
	case errors.Is(err, ca.ErrNotInitialized):
		fail(w, http.StatusConflict, "ca.not_initialized", "the CA is not initialized")
	case errors.Is(err, ca.ErrAlreadyInit):
		fail(w, http.StatusConflict, "ca.already_initialized", "the CA is already initialized")
	case errors.Is(err, ca.ErrIssuerNotFound), errors.Is(err, store.ErrNotFound):
		fail(w, http.StatusNotFound, "not_found", "not found")
	case errors.Is(err, ca.ErrIssuerInactive):
		fail(w, http.StatusConflict, "issuer.inactive", err.Error())
	case errors.Is(err, ca.ErrSlugTaken):
		fail(w, http.StatusConflict, "issuer.slug_taken", err.Error())
	case errors.Is(err, ca.ErrInvalidSlug):
		fail(w, http.StatusBadRequest, "issuer.invalid_slug", err.Error())
	case errors.Is(err, ca.ErrCannotRevokeDef):
		fail(w, http.StatusConflict, "issuer.cannot_revoke_default", err.Error())
	default:
		a.Log.Error("api error", "err", err)
		fail(w, http.StatusInternalServerError, "internal", "internal error")
	}
}

func (a *API) audit(r *http.Request, action, target string, details map[string]any) {
	a.Audit.Record(r.Context(), "admin", action, target, auth.ClientIP(r), details)
}

func (a *API) caReady(ctx context.Context) {
	if a.OnCAReady != nil {
		a.OnCAReady(context.WithoutCancel(ctx))
	}
}

func intQuery(r *http.Request, k string, def int) int {
	if v, err := strconv.Atoi(r.URL.Query().Get(k)); err == nil {
		return v
	}
	return def
}
