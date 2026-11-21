package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/davidemaggi/conrad/internal/store"
)

// Notifier delivers events to every enabled, subscribed channel.
type Notifier struct {
	Store   *store.Store
	Log     *slog.Logger
	BaseURL string
	// Backoff is the delay before each retry (3 retries by default).
	Backoff []time.Duration
	HTTP    *http.Client
	Dial    dialFunc

	wg sync.WaitGroup
}

// New creates a notifier.
func New(st *store.Store, baseURL string, log *slog.Logger) *Notifier {
	if log == nil {
		log = slog.Default()
	}
	d := &net.Dialer{Timeout: 15 * time.Second}
	return &Notifier{
		Store: st, Log: log, BaseURL: strings.TrimRight(baseURL, "/"),
		Backoff: []time.Duration{5 * time.Second, 30 * time.Second, 2 * time.Minute},
		HTTP:    &http.Client{Timeout: 15 * time.Second},
		Dial:    d.DialContext,
	}
}

func (n *Notifier) language(ctx context.Context) string {
	if a, err := n.Store.GetAdmin(ctx); err == nil {
		return a.Language
	}
	return "en"
}

func (n *Notifier) channels(ctx context.Context, typ string) []*Channel {
	list, err := n.Store.ListChannels(ctx)
	if err != nil {
		n.Log.Error("notify: list channels", "err", err)
		return nil
	}
	var out []*Channel
	for _, sc := range list {
		c, err := Decode(sc)
		if err != nil {
			n.Log.Error("notify: bad channel", "err", err)
			continue
		}
		if c.Enabled && c.Subscribed(typ) {
			out = append(out, c)
		}
	}
	return out
}

func (n *Notifier) prepare(e *Event) {
	if e.ID == "" {
		e.ID = store.NewID()
	}
	if e.At.IsZero() {
		e.At = n.Store.Now()
	}
	if e.Data.Link == "" && n.BaseURL != "" {
		e.Data.Link = n.BaseURL + "/"
		if e.Subject != "" && strings.HasPrefix(e.Type, "cert.") {
			e.Data.Link = n.BaseURL + "/certificates/" + e.Subject
		}
	}
}

// Emit delivers e asynchronously with retries. It returns the number of target channels.
func (n *Notifier) Emit(ctx context.Context, e Event) int {
	n.prepare(&e)
	chans := n.channels(ctx, e.Type)
	if len(chans) == 0 {
		return 0
	}
	lang := n.language(ctx)
	ctx = context.WithoutCancel(ctx)
	for _, c := range chans {
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			n.deliverWithRetry(ctx, c, lang, e)
		}()
	}
	return len(chans)
}

// EmitSync delivers e to every target channel (with retries) and reports whether at least one succeeded.
func (n *Notifier) EmitSync(ctx context.Context, e Event) (targets int, delivered int) {
	n.prepare(&e)
	chans := n.channels(ctx, e.Type)
	lang := n.language(ctx)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, c := range chans {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if n.deliverWithRetry(ctx, c, lang, e) == nil {
				mu.Lock()
				delivered++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return len(chans), delivered
}

// Wait blocks until pending asynchronous deliveries finish (tests, shutdown).
func (n *Notifier) Wait() { n.wg.Wait() }

func (n *Notifier) deliverWithRetry(ctx context.Context, c *Channel, lang string, e Event) error {
	var err error
	for attempt := 0; attempt <= len(n.Backoff); attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(n.Backoff[attempt-1]):
			}
		}
		if err = n.Deliver(ctx, c, lang, e); err == nil {
			return nil
		}
		n.Log.Warn("notify: delivery failed", "channel", c.Name, "event", e.Type, "attempt", attempt+1, "err", err)
	}
	n.Log.Error("notify: giving up", "channel", c.Name, "event", e.Type, "err", err)
	return err
}

// Deliver sends e to a single channel once.
func (n *Notifier) Deliver(ctx context.Context, c *Channel, lang string, e Event) error {
	switch c.Kind {
	case "smtp":
		if c.SMTP == nil {
			return errors.New("missing smtp settings")
		}
		return sendMail(ctx, n.Dial, c.SMTP, Render(lang, e))
	case "webhook":
		if c.Webhook == nil {
			return errors.New("missing webhook settings")
		}
		return n.postWebhook(ctx, c.Webhook, lang, e)
	}
	return fmt.Errorf("unknown channel kind %q", c.Kind)
}

// Test sends a test notification to one channel, synchronously and without retries.
func (n *Notifier) Test(ctx context.Context, c *Channel) error {
	e := Event{Type: Test}
	n.prepare(&e)
	return n.Deliver(ctx, c, n.language(ctx), e)
}

// Sign computes the X-Conrad-Signature value: hex HMAC-SHA256 over "<timestamp>.<body>".
func Sign(secret string, timestamp string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(timestamp + "."))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

type webhookPayload struct {
	Event
	Title string `json:"title"`
	Text  string `json:"text"`
}

func (n *Notifier) postWebhook(ctx context.Context, w *WebhookConfig, lang string, e Event) error {
	r := Render(lang, e)
	body, err := json.Marshal(webhookPayload{Event: e, Title: r.Subject, Text: r.Subject + "\n\n" + r.Text})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Conrad-Webhook/1")
	req.Header.Set("X-Conrad-Event", e.Type)
	req.Header.Set("X-Conrad-Delivery", e.ID)
	req.Header.Set("X-Conrad-Timestamp", ts)
	if w.Secret != "" {
		req.Header.Set("X-Conrad-Signature", Sign(w.Secret, ts, body))
	}
	res, err := n.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("webhook returned HTTP %d", res.StatusCode)
	}
	return nil
}
