// Package audit records security-relevant actions in the append-only audit log.
package audit

import (
	"context"
	"log/slog"

	"github.com/davidemaggi/conrad/internal/store"
)

// Logger writes audit entries and mirrors them to slog.
type Logger struct {
	Store *store.Store
	Log   *slog.Logger
	// OnRecord is called after an entry is stored (e.g. to send notifications).
	OnRecord func(context.Context, *store.AuditEntry)
}

// New creates an audit logger.
func New(st *store.Store, log *slog.Logger) *Logger {
	if log == nil {
		log = slog.Default()
	}
	return &Logger{Store: st, Log: log}
}

// Record appends an entry; failures are logged, never returned.
func (l *Logger) Record(ctx context.Context, actor, action, target, ip string, details map[string]any) {
	e := &store.AuditEntry{Actor: actor, Action: action, Target: target, IP: ip, Details: details}
	if err := l.Store.InsertAudit(context.WithoutCancel(ctx), e); err != nil {
		l.Log.Error("audit write failed", "action", action, "err", err)
		return
	}
	l.Log.Info("audit", "actor", actor, "action", action, "target", target, "ip", ip)
	if l.OnRecord != nil {
		l.OnRecord(context.WithoutCancel(ctx), e)
	}
}
