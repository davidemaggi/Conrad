package notify

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/davidemaggi/conrad/internal/ca"
	"github.com/davidemaggi/conrad/internal/crypto/signer"
	"github.com/davidemaggi/conrad/internal/store"
)

// ---- fake SMTP server ----

type fakeSMTP struct {
	ln       net.Listener
	mode     string // none | starttls | tls
	tlsCfg   *tls.Config
	mu       sync.Mutex
	authUser string
	authPass string
	messages []string
	sawTLS   bool
}

func testTLSConfig(t *testing.T) *tls.Config {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mail.test"}, DNSNames: []string{"mail.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

func startSMTP(t *testing.T, mode string) *fakeSMTP {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln, mode: mode, tlsCfg: testTLSConfig(t)}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSMTP) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	secure := false
	if f.mode == "tls" {
		c = tls.Server(c, f.tlsCfg)
		secure = true
	}
	rd := bufio.NewReader(c)
	say := func(s string) { _, _ = io.WriteString(c, s+"\r\n") }
	line := func() string { l, _ := rd.ReadString('\n'); return strings.TrimRight(l, "\r\n") }
	say("220 fake ESMTP")
	for {
		l := line()
		cmd := strings.ToUpper(strings.SplitN(l, " ", 2)[0])
		switch cmd {
		case "EHLO", "HELO":
			if f.mode == "starttls" && !secure {
				say("250-fake")
				say("250-STARTTLS")
			} else {
				say("250-fake")
			}
			say("250 AUTH PLAIN LOGIN")
		case "STARTTLS":
			say("220 go ahead")
			tc := tls.Server(c, f.tlsCfg)
			if tc.Handshake() != nil {
				return
			}
			c, rd, secure = tc, bufio.NewReader(tc), true
		case "AUTH":
			parts := strings.Fields(l)
			var user, pass string
			if strings.EqualFold(parts[1], "PLAIN") {
				b, _ := base64.StdEncoding.DecodeString(parts[2])
				p := strings.Split(string(b), "\x00")
				user, pass = p[1], p[2]
			} else {
				say("334 VXNlcm5hbWU6")
				u, _ := base64.StdEncoding.DecodeString(line())
				say("334 UGFzc3dvcmQ6")
				pw, _ := base64.StdEncoding.DecodeString(line())
				user, pass = string(u), string(pw)
			}
			f.mu.Lock()
			f.authUser, f.authPass = user, pass
			f.mu.Unlock()
			say("235 ok")
		case "MAIL", "RCPT", "RSET", "NOOP":
			say("250 ok")
		case "DATA":
			say("354 go")
			var b strings.Builder
			for {
				d := line()
				if d == "." {
					break
				}
				b.WriteString(d + "\n")
			}
			f.mu.Lock()
			f.messages = append(f.messages, b.String())
			f.sawTLS = secure
			f.mu.Unlock()
			say("250 queued")
		case "QUIT":
			say("221 bye")
			return
		default:
			if l == "" {
				return
			}
			say("500 what")
		}
	}
}

func newTestNotifier(t *testing.T) (*Notifier, *store.Store) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	n := New(st, "https://conrad.test", nil)
	n.Backoff = []time.Duration{10 * time.Millisecond, 10 * time.Millisecond, 10 * time.Millisecond}
	return n, st
}

func TestSMTPModes(t *testing.T) {
	n, _ := newTestNotifier(t)
	cases := []struct {
		mode, user, method string
	}{
		{"none", "", "plain"},       // unauthenticated relay
		{"none", "relay", "plain"},  // auth on plain connection (explicit choice)
		{"starttls", "me", "login"}, // STARTTLS + LOGIN
		{"tls", "me", "plain"},      // implicit TLS
	}
	for _, tc := range cases {
		t.Run(tc.mode+"-"+tc.user, func(t *testing.T) {
			f := startSMTP(t, tc.mode)
			c := &Channel{Kind: "smtp", Name: "mail", Enabled: true, SMTP: &SMTPConfig{
				Host: "127.0.0.1", Port: f.port(), Security: tc.mode, Username: tc.user, Password: "pw", AuthMethod: tc.method,
				SkipVerify: true, From: "Conrad <conrad@home.lab>", To: []string{"admin@home.lab"},
			}}
			if err := c.Normalize(); err != nil {
				t.Fatal(err)
			}
			if err := n.Test(context.Background(), c); err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.messages) != 1 || !strings.Contains(f.messages[0], "multipart/alternative") {
				t.Fatalf("message not delivered: %q", f.messages)
			}
			if tc.user != "" && (f.authUser != tc.user || f.authPass != "pw") {
				t.Fatalf("auth got %q/%q", f.authUser, f.authPass)
			}
			if tc.user == "" && f.authUser != "" {
				t.Fatal("unexpected AUTH")
			}
			if (tc.mode != "none") != f.sawTLS {
				t.Fatalf("tls=%v for mode %s", f.sawTLS, tc.mode)
			}
		})
	}
}

func TestStartTLSRequired(t *testing.T) {
	n, _ := newTestNotifier(t)
	f := startSMTP(t, "none") // does not advertise STARTTLS
	c := &Channel{Kind: "smtp", Name: "m", SMTP: &SMTPConfig{Host: "127.0.0.1", Port: f.port(), Security: "starttls",
		From: "c@h.lab", To: []string{"a@h.lab"}}}
	_ = c.Normalize()
	if err := n.Test(context.Background(), c); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("want STARTTLS error, got %v", err)
	}
}

func TestWebhookSignatureAndRetry(t *testing.T) {
	n, st := newTestNotifier(t)
	var calls atomic.Int32
	got := make(chan bool, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(500)
			return
		}
		body, _ := io.ReadAll(r.Body)
		ok := r.Header.Get("X-Conrad-Signature") == Sign("s3cret", r.Header.Get("X-Conrad-Timestamp"), body) &&
			r.Header.Get("X-Conrad-Event") == CertExpiring && strings.Contains(string(body), `"daysLeft":7`)
		got <- ok
	}))
	defer srv.Close()
	c := &Channel{Kind: "webhook", Name: "hook", Enabled: true, Events: []string{CertExpiring}, Webhook: &WebhookConfig{URL: srv.URL, Secret: "s3cret"}}
	if err := c.Normalize(); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertChannel(context.Background(), c.Encode()); err != nil {
		t.Fatal(err)
	}
	if n.Emit(context.Background(), Event{Type: CertIssued}) != 0 {
		t.Fatal("unsubscribed event must not be delivered")
	}
	n.Emit(context.Background(), Event{Type: CertExpiring, Data: Data{CommonName: "nas.home.lab", DaysLeft: 7}})
	n.Wait()
	select {
	case ok := <-got:
		if !ok {
			t.Fatal("bad signature or payload")
		}
	default:
		t.Fatal("webhook not delivered after retries")
	}
}

func TestSchedulerDedupe(t *testing.T) {
	n, st := newTestNotifier(t)
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	st.SetClock(func() time.Time { return now })

	var mu sync.Mutex
	var events []string
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		events = append(events, string(b))
		mu.Unlock()
	}))
	defer srv.Close()
	c := &Channel{Kind: "webhook", Name: "hook", Enabled: true, Events: []string{CertExpiring}, Webhook: &WebhookConfig{URL: srv.URL}}
	_ = c.Normalize()
	_ = st.InsertChannel(ctx, c.Encode())

	svc := ca.New(st, signer.NewSoftware(), "https://conrad.test", nil)
	if _, _, err := svc.Init(ctx, ca.InitRequest{Secret: "a very long passphrase", Subject: ca.Subject{CommonName: "R"},
		Issuer: ca.IssuerRequest{Slug: "homelab"}}); err != nil {
		t.Fatal(err)
	}
	mk := func(_ string, sans []string, notAfter time.Time) {
		if _, _, err := svc.IssueWithKey(ctx, "homelab", "", ca.IssueRequest{DNSNames: sans, NotAfter: notAfter, Source: "acme"}); err != nil {
			t.Fatal(err)
		}
	}
	mk("a", []string{"nas.home.lab"}, now.Add(10*24*time.Hour))  // 10 days -> threshold 14
	mk("b", []string{"old.home.lab"}, now.Add(5*24*time.Hour))   // superseded by c
	mk("c", []string{"old.home.lab"}, now.Add(85*24*time.Hour))  // renewal, not expiring
	mk("d", []string{"far.home.lab"}, now.Add(200*24*time.Hour)) // not expiring

	count := func() int { mu.Lock(); defer mu.Unlock(); return len(events) }
	if err := n.CheckExpiries(ctx); err != nil {
		t.Fatal(err)
	}
	if count() != 1 || !strings.Contains(events[0], "nas.home.lab") {
		t.Fatalf("want 1 notification for nas, got %d: %v", count(), events)
	}
	_ = n.CheckExpiries(ctx)
	if count() != 1 {
		t.Fatal("duplicate notification")
	}
	now = now.Add(4 * 24 * time.Hour) // 6 days left -> threshold 7
	_ = n.CheckExpiries(ctx)
	if count() != 2 {
		t.Fatalf("want threshold-7 notification, got %d", count())
	}
}

func TestThresholdMath(t *testing.T) {
	desc := []int{30, 14, 7, 1}
	for d, want := range map[int]int{45: 0, 30: 30, 20: 30, 14: 14, 8: 14, 7: 7, 2: 7, 1: 1, 0: 1} {
		if got := threshold(d, desc); got != want {
			t.Errorf("threshold(%d)=%d want %d", d, got, want)
		}
	}
	now := time.Unix(0, 0)
	if daysLeft(now, now.Add(36*time.Hour)) != 2 || daysLeft(now, now.Add(24*time.Hour)) != 1 {
		t.Fatal("daysLeft rounding")
	}
}

func TestRenderItalian(t *testing.T) {
	r := Render("it", Event{Type: CertExpiring, Data: Data{CommonName: "nas.home.lab", DaysLeft: 1, Link: "https://c/x"}})
	if r.Subject != "Il certificato nas.home.lab scade tra 1 giorno" {
		t.Fatalf("subject %q", r.Subject)
	}
	if !strings.Contains(r.HTML, "Apri in Conrad") || !strings.Contains(r.Text, "Apri in Conrad: https://c/x") {
		t.Fatal("html not localized")
	}
	if strings.Contains(Render("xx", Event{Type: Test}).Subject, "{{") {
		t.Fatal("fallback failed")
	}
}

func TestRedactAndKeepSecrets(t *testing.T) {
	old := &Channel{Kind: "smtp", SMTP: &SMTPConfig{Host: "mail.lab", Username: "u", Password: "pw"}}
	if r := old.Redacted(); r.SMTP.Password != "" || !r.SecretOK || old.SMTP.Password != "pw" {
		t.Fatal("redaction")
	}
	same := &Channel{Kind: "smtp", SMTP: &SMTPConfig{Host: "MAIL.lab", Username: "u"}}
	same.KeepSecrets(old)
	moved := &Channel{Kind: "smtp", SMTP: &SMTPConfig{Host: "evil.example", Username: "u"}}
	moved.KeepSecrets(old)
	if same.SMTP.Password != "pw" || moved.SMTP.Password != "" {
		t.Fatal("secret reuse rules")
	}
}
