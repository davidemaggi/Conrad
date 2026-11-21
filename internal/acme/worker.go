package acme

import (
	"context"
	"errors"
	"time"

	"github.com/davidemaggi/conrad/internal/challenge"
)

type job struct {
	id      string
	attempt int
}

func (s *Server) enqueue(id string) { s.schedule(job{id: id}) }

func (s *Server) schedule(j job) {
	var d time.Duration
	if j.attempt < len(s.RetrySchedule) {
		d = s.RetrySchedule[j.attempt]
	}
	push := func() {
		select {
		case s.queue <- j:
		default:
			s.Log.Warn("acme validation queue full; dropping", "challenge", j.id)
			_ = s.Store.FinishChallenge(context.Background(), j.id, "pending", "")
		}
	}
	if d <= 0 {
		push()
		return
	}
	time.AfterFunc(d, push)
}

func (s *Server) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-s.queue:
			s.attempt(ctx, j)
		}
	}
}

// attempt runs one validation try and either finishes the challenge or reschedules it.
func (s *Server) attempt(ctx context.Context, j job) {
	c, err := s.Store.GetChallenge(ctx, j.id)
	if err != nil || c.Status != "processing" {
		return
	}
	a, err := s.Store.GetAuthz(ctx, c.AuthzID)
	if err != nil {
		return
	}
	if a.Status != "pending" {
		_ = s.Store.FinishChallenge(ctx, c.ID, "invalid", malformed("authorization is %s", a.Status).json())
		return
	}
	acct, err := s.Store.GetAccount(ctx, a.AccountID)
	if err != nil {
		return
	}
	keyAuth := c.Token + "." + acct.JWKThumbprint
	verr := s.Validator.Validate(ctx, c.Type, a.IDType, a.IDValue, c.Token, keyAuth)
	ev := Event{IssuerSlug: acct.IssuerSlug, AccountID: acct.ID, Target: a.IDValue, Detail: map[string]any{"type": c.Type}}
	if verr == nil {
		_ = s.Store.FinishChallenge(ctx, c.ID, "valid", "")
		_ = s.Store.UpdateAuthzStatus(ctx, a.ID, "valid")
		if o, err := s.Store.GetOrder(ctx, a.OrderID); err == nil {
			_ = s.refreshOrder(ctx, o)
		}
		ev.Type = "challenge.valid"
		s.emit(ctx, ev)
		return
	}
	if j.attempt+1 < len(s.RetrySchedule) {
		s.Log.Debug("acme validation failed; retrying", "challenge", c.ID, "attempt", j.attempt+1, "err", verr)
		s.schedule(job{id: j.id, attempt: j.attempt + 1})
		return
	}
	typ := "connection"
	var ce *challenge.Error
	if errors.As(verr, &ce) {
		typ = ce.Type
	}
	p := prob(403, typ, "%s", verr.Error())
	p.Identifier = &ident{Type: a.IDType, Value: a.IDValue}
	_ = s.Store.FinishChallenge(ctx, c.ID, "invalid", p.json())
	_ = s.Store.UpdateAuthzStatus(ctx, a.ID, "invalid")
	if o, err := s.Store.GetOrder(ctx, a.OrderID); err == nil && (o.Status == "pending" || o.Status == "ready") {
		o.Status, o.Error = "invalid", p.json()
		_ = s.Store.UpdateOrder(ctx, o)
	}
	ev.Type, ev.Detail["error"] = "challenge.invalid", verr.Error()
	s.emit(ctx, ev)
	s.Log.Info("acme challenge failed", "identifier", a.IDValue, "type", c.Type, "err", verr)
}
