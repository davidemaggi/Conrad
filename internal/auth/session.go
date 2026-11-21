package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"time"

	"github.com/davidemaggi/conrad/internal/store"
)

// Cookie and header names.
const (
	SessionCookie = "conrad_session"
	CSRFCookie    = "conrad_csrf"
	CSRFHeader    = "X-CSRF-Token"
)

// Sessions manages cookie sessions (12h idle, 7d absolute by default).
type Sessions struct {
	Store    *store.Store
	Idle     time.Duration
	Absolute time.Duration
	Secure   bool // set the Secure cookie attribute (false only for plain-HTTP deployments)
}

// NewSessions returns a manager with the spec defaults.
func NewSessions(st *store.Store, secure bool) *Sessions {
	return &Sessions{Store: st, Idle: 12 * time.Hour, Absolute: 7 * 24 * time.Hour, Secure: secure}
}

func hashToken(t string) []byte {
	h := sha256.Sum256([]byte(t))
	return h[:]
}

// Create starts a session and sets the session and CSRF cookies.
func (m *Sessions) Create(ctx context.Context, w http.ResponseWriter, r *http.Request, method string) (*store.Session, error) {
	token := RandomToken(32)
	now := m.Store.Now()
	s := &store.Session{
		TokenHash: hashToken(token), CSRFToken: RandomToken(32), CreatedAt: now, LastSeen: now,
		ExpiresAt: now.Add(m.Absolute), IP: ClientIP(r), UserAgent: truncate(r.UserAgent(), 256), Method: method,
	}
	if err := m.Store.InsertSession(ctx, s); err != nil {
		return nil, err
	}
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: m.Secure,
		SameSite: http.SameSiteStrictMode, Expires: s.ExpiresAt})
	http.SetCookie(w, &http.Cookie{Name: CSRFCookie, Value: s.CSRFToken, Path: "/", Secure: m.Secure,
		SameSite: http.SameSiteStrictMode, Expires: s.ExpiresAt})
	return s, nil
}

// ErrNoSession means the request is not authenticated.
var ErrNoSession = errors.New("not authenticated")

// Get validates the session cookie and refreshes the idle timer.
func (m *Sessions) Get(r *http.Request) (*store.Session, error) {
	c, err := r.Cookie(SessionCookie)
	if err != nil || c.Value == "" {
		return nil, ErrNoSession
	}
	ctx := r.Context()
	s, err := m.Store.GetSession(ctx, hashToken(c.Value))
	if err != nil {
		return nil, ErrNoSession
	}
	now := m.Store.Now()
	if now.After(s.ExpiresAt) || now.Sub(s.LastSeen) > m.Idle {
		_ = m.Store.DeleteSession(ctx, s.TokenHash)
		return nil, ErrNoSession
	}
	if now.Sub(s.LastSeen) > time.Minute {
		_ = m.Store.TouchSession(ctx, s.TokenHash, now)
	}
	return s, nil
}

// Destroy removes the current session and clears cookies.
func (m *Sessions) Destroy(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookie); err == nil {
		_ = m.Store.DeleteSession(r.Context(), hashToken(c.Value))
	}
	for _, n := range []string{SessionCookie, CSRFCookie} {
		http.SetCookie(w, &http.Cookie{Name: n, Value: "", Path: "/", MaxAge: -1, Secure: m.Secure, SameSite: http.SameSiteStrictMode})
	}
}

// CheckCSRF enforces the double-submit token for unsafe methods.
func CheckCSRF(r *http.Request, s *store.Session) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	h := r.Header.Get(CSRFHeader)
	c, err := r.Cookie(CSRFCookie)
	if h == "" || err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(h), []byte(c.Value)) == 1 &&
		subtle.ConstantTimeCompare([]byte(h), []byte(s.CSRFToken)) == 1
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
