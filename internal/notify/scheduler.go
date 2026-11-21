package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/davidemaggi/conrad/internal/store"
)

const thresholdsSetting = "notify.thresholds"

// DefaultThresholds are the certificate expiry warnings, in days.
var DefaultThresholds = []int{30, 14, 7, 1}

// caThresholds are fixed warnings for roots and issuers, in days.
var caThresholds = []int{90, 30, 7, 1}

// Thresholds returns the configured certificate thresholds, descending.
func Thresholds(ctx context.Context, st *store.Store) []int {
	raw, err := st.GetSetting(ctx, thresholdsSetting)
	var t []int
	if err != nil || json.Unmarshal([]byte(raw), &t) != nil || len(t) == 0 {
		t = slices.Clone(DefaultThresholds)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(t)))
	return t
}

// SaveThresholds validates and stores thresholds (1..365 days, at most 10).
func SaveThresholds(ctx context.Context, st *store.Store, t []int) error {
	if len(t) == 0 || len(t) > 10 {
		return errors.New("between 1 and 10 thresholds are required")
	}
	seen := map[int]bool{}
	for _, d := range t {
		if d < 1 || d > 365 || seen[d] {
			return fmt.Errorf("invalid or duplicate threshold %d", d)
		}
		seen[d] = true
	}
	b, _ := json.Marshal(t)
	return st.SetSetting(ctx, thresholdsSetting, string(b))
}

// threshold returns the tightest threshold that daysLeft has crossed (0 = none).
func threshold(daysLeft int, desc []int) int {
	t := 0
	for _, th := range desc {
		if daysLeft <= th {
			t = th
		}
	}
	return t
}

func daysLeft(now, notAfter time.Time) int {
	return int((notAfter.Sub(now) + 24*time.Hour - time.Second) / (24 * time.Hour))
}

// RunScheduler checks expiries at start and then every interval until ctx ends.
func (n *Notifier) RunScheduler(ctx context.Context, interval time.Duration) {
	for {
		if err := n.CheckExpiries(ctx); err != nil && ctx.Err() == nil {
			n.Log.Error("notify: expiry check failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// CheckExpiries notifies each (subject, threshold) pair once.
func (n *Notifier) CheckExpiries(ctx context.Context) error {
	now := n.Store.Now()
	ths := Thresholds(ctx, n.Store)
	valid, _, err := n.Store.ListCertificates(ctx, store.CertFilter{Status: store.CertValid, Limit: 100000})
	if err != nil {
		return err
	}
	// A certificate is superseded when a later one from the same issuer covers the same names
	// (the usual ACME renewal); only the newest is checked.
	newest := map[string]time.Time{}
	key := func(c *store.Certificate) string {
		names := slices.Clone(c.SANs)
		slices.Sort(names)
		return c.IssuerSlug + "|" + strings.Join(names, ",")
	}
	for _, c := range valid {
		if k := key(c); c.NotAfter.After(newest[k]) {
			newest[k] = c.NotAfter
		}
	}
	for _, c := range valid {
		if c.Source == "system" || c.NotAfter.Before(newest[key(c)]) {
			continue
		}
		d := daysLeft(now, c.NotAfter)
		th := threshold(d, ths)
		if th == 0 {
			continue
		}
		n.notifyOnce(ctx, c.ID, th, Event{Type: CertExpiring, Subject: c.ID, Data: Data{
			CommonName: certName(c), Names: c.SANs, Issuer: c.IssuerSlug, Serial: c.Serial, NotAfter: c.NotAfter, DaysLeft: d,
		}})
	}
	auths, err := n.Store.ListAuthorities(ctx)
	if err != nil {
		return err
	}
	for _, a := range auths {
		if a.Status != "active" || !a.NotAfter.After(now) {
			continue
		}
		d := daysLeft(now, a.NotAfter)
		if th := threshold(d, caThresholds); th > 0 {
			n.notifyOnce(ctx, a.ID, th, Event{Type: CAExpiring, Subject: a.ID, Data: Data{
				Authority: a.Name, Kind: a.Kind, Issuer: a.Slug, Serial: a.Serial, NotAfter: a.NotAfter, DaysLeft: d,
			}})
		}
	}
	return nil
}

func (n *Notifier) notifyOnce(ctx context.Context, subject string, th int, e Event) {
	fresh, err := n.Store.MarkNotified(ctx, subject, th)
	if err != nil || !fresh {
		return
	}
	if _, delivered := n.EmitSync(ctx, e); delivered == 0 {
		// Nothing reached anyone (no channel yet, or all failed): try again on the next run.
		_ = n.Store.UnmarkNotified(context.WithoutCancel(ctx), subject, th)
	}
}

func certName(c *store.Certificate) string {
	if c.CommonName != "" {
		return c.CommonName
	}
	if len(c.SANs) > 0 {
		return c.SANs[0]
	}
	return c.Serial
}

var reasons = map[int]string{0: "unspecified", 1: "keyCompromise", 2: "cACompromise", 3: "affiliationChanged",
	4: "superseded", 5: "cessationOfOperation", 6: "certificateHold", 9: "privilegeWithdrawn", 10: "aACompromise"}

// FromAudit turns audit entries into notifications (hook for audit.Logger).
func (n *Notifier) FromAudit(ctx context.Context, e *store.AuditEntry) {
	str := func(k string) string { s, _ := e.Details[k].(string); return s }
	switch e.Action {
	case "cert.issued", "cert.revoked":
		c, err := n.Store.GetCertificate(ctx, e.Target)
		if err != nil || c.Source == "system" {
			return
		}
		ev := Event{Type: CertIssued, Subject: c.ID, Data: Data{CommonName: certName(c), Names: c.SANs, Issuer: c.IssuerSlug, Serial: c.Serial, NotAfter: c.NotAfter}}
		if e.Action == "cert.revoked" {
			ev.Type, ev.Data.Reason = CertRevoked, reasons[c.RevocationReason]
		}
		n.Emit(ctx, ev)
	case "challenge.invalid", "order.invalid":
		ev := Event{Type: ACMEFailed, Data: Data{CommonName: e.Target, Issuer: str("issuer"), Error: str("error")}}
		if e.Action == "order.invalid" {
			ev.Data.CommonName = "order " + e.Target
		}
		n.Emit(ctx, ev)
	}
}

// CALockedAlert notifies that the CA started locked.
func (n *Notifier) CALockedAlert(ctx context.Context) { n.Emit(ctx, Event{Type: CALocked}) }
