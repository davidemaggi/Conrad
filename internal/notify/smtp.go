package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// dialFunc lets tests intercept SMTP connections.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func sendMail(ctx context.Context, dial dialFunc, c *SMTPConfig, r Rendered) error {
	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	tlsCfg := &tls.Config{ServerName: c.Host, InsecureSkipVerify: c.SkipVerify, MinVersion: tls.VersionTLS12} //nolint:gosec // opt-in for self-signed relays
	if c.Security == "tls" {
		tc := tls.Client(conn, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return fmt.Errorf("tls handshake: %w", err)
		}
		conn = tc
	}
	cl, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer cl.Close()
	if err := cl.Hello("conrad"); err != nil {
		return err
	}
	if c.Security == "starttls" {
		if ok, _ := cl.Extension("STARTTLS"); !ok {
			return errors.New("server does not support STARTTLS")
		}
		if err := cl.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}
	if c.Username != "" {
		var a smtp.Auth = &plainAuth{user: c.Username, pass: c.Password}
		if c.AuthMethod == "login" {
			a = &loginAuth{user: c.Username, pass: c.Password}
		}
		if err := cl.Auth(a); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	from, _ := mail.ParseAddress(c.From)
	if err := cl.Mail(from.Address); err != nil {
		return err
	}
	for _, t := range c.To {
		to, err := mail.ParseAddress(t)
		if err != nil {
			return err
		}
		if err := cl.Rcpt(to.Address); err != nil {
			return fmt.Errorf("rcpt %s: %w", to.Address, err)
		}
	}
	w, err := cl.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(buildMessage(c, r)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return cl.Quit()
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func qp(s string) string {
	var b bytes.Buffer
	w := quotedprintable.NewWriter(&b)
	_, _ = w.Write([]byte(strings.ReplaceAll(s, "\n", "\r\n")))
	_ = w.Close()
	return b.String()
}

func buildMessage(c *SMTPConfig, r Rendered) []byte {
	boundary := "conrad-" + randHex(12)
	domain := "conrad.local"
	if from, err := mail.ParseAddress(c.From); err == nil {
		if i := strings.LastIndex(from.Address, "@"); i >= 0 {
			domain = from.Address[i+1:]
		}
	}
	var b bytes.Buffer
	h := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	h("From", c.From)
	h("To", strings.Join(c.To, ", "))
	h("Subject", mime.QEncoding.Encode("utf-8", r.Subject))
	h("Date", time.Now().Format(time.RFC1123Z))
	h("Message-ID", "<"+randHex(16)+"@"+domain+">")
	h("MIME-Version", "1.0")
	h("Auto-Submitted", "auto-generated")
	h("Content-Type", `multipart/alternative; boundary="`+boundary+`"`)
	b.WriteString("\r\n")
	for _, part := range []struct{ ctype, body string }{{"text/plain", r.Text}, {"text/html", r.HTML}} {
		b.WriteString("--" + boundary + "\r\n")
		h("Content-Type", part.ctype+"; charset=utf-8")
		h("Content-Transfer-Encoding", "quoted-printable")
		b.WriteString("\r\n" + qp(part.body) + "\r\n")
	}
	b.WriteString("--" + boundary + "--\r\n")
	return b.Bytes()
}

// plainAuth and loginAuth allow AUTH on unencrypted connections only when the
// admin explicitly chose security "none" (an internal relay); net/smtp refuses that.
type plainAuth struct{ user, pass string }

func (a *plainAuth) Start(*smtp.ServerInfo) (string, []byte, error) {
	return "PLAIN", []byte("\x00" + a.user + "\x00" + a.pass), nil
}

func (a *plainAuth) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		return nil, errors.New("unexpected server challenge")
	}
	return nil, nil
}

type loginAuth struct {
	user, pass string
	step       int
}

func (a *loginAuth) Start(*smtp.ServerInfo) (string, []byte, error) { return "LOGIN", nil, nil }

func (a *loginAuth) Next(_ []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	a.step++
	switch a.step {
	case 1:
		return []byte(a.user), nil
	case 2:
		return []byte(a.pass), nil
	}
	return nil, errors.New("unexpected server challenge")
}
