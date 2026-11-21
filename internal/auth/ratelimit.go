package auth

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// Throttle applies exponential backoff after repeated failures per key (IP or username).
type Throttle struct {
	Max time.Duration

	mu    sync.Mutex
	state map[string]*throttleState
	now   func() time.Time
}

type throttleState struct {
	failures int
	until    time.Time
	last     time.Time
}

// NewThrottle returns a throttle allowing 3 free failures, then 1s, 2s, 4s... capped at 15 minutes.
func NewThrottle() *Throttle {
	return &Throttle{Max: 15 * time.Minute, state: map[string]*throttleState{}, now: time.Now}
}

// Wait returns how long the caller must wait before trying keys again (0 = allowed).
func (t *Throttle) Wait(keys ...string) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	var max time.Duration
	for _, k := range keys {
		if s := t.state[k]; s != nil && s.until.After(now) {
			if d := s.until.Sub(now); d > max {
				max = d
			}
		}
	}
	return max
}

// Fail records a failure for each key.
func (t *Throttle) Fail(keys ...string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for _, k := range keys {
		s := t.state[k]
		if s == nil || now.Sub(s.last) > 24*time.Hour {
			s = &throttleState{}
			t.state[k] = s
		}
		s.failures++
		s.last = now
		if s.failures > 3 {
			d := time.Second << min(s.failures-4, 20)
			if d > t.Max {
				d = t.Max
			}
			s.until = now.Add(d)
		}
	}
}

// Reset clears keys after a successful login.
func (t *Throttle) Reset(keys ...string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, k := range keys {
		delete(t.state, k)
	}
}

// ClientIP returns the remote IP of the request.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
