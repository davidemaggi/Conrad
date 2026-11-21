// Package challenge validates ACME HTTP-01, DNS-01 and TLS-ALPN-01 challenges.
package challenge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Error carries a human readable reason and the ACME problem type suffix.
type Error struct {
	Type   string // e.g. "connection", "dns", "incorrectResponse", "unauthorized", "tls"
	Detail string
}

func (e *Error) Error() string { return e.Detail }

func fail(typ, format string, args ...any) error {
	return &Error{Type: typ, Detail: fmt.Sprintf(format, args...)}
}

// Validator checks challenges. Zero ports default to 80/443.
type Validator struct {
	HTTPPort  int
	TLSPort   int
	Resolvers []string // "host:port" or "host"; empty = system resolver
	Timeout   time.Duration
	// DialContext is used for HTTP-01 and TLS-ALPN-01 connections (tests may override).
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Validate checks challenge typ for identifier (type "dns"/"ip", value).
func (v *Validator) Validate(ctx context.Context, typ, idType, idValue, token, keyAuth string) error {
	timeout := v.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	switch typ {
	case "http-01":
		return v.http01(ctx, idValue, token, keyAuth)
	case "dns-01":
		return v.dns01(ctx, idValue, keyAuth)
	case "tls-alpn-01":
		return v.tlsALPN01(ctx, idType, idValue, keyAuth)
	}
	return fail("malformed", "unsupported challenge type %q", typ)
}

func (v *Validator) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if v.DialContext != nil {
		return v.DialContext(ctx, network, addr)
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	return d.DialContext(ctx, network, addr)
}

func port(p, def int) string {
	if p == 0 {
		p = def
	}
	return strconv.Itoa(p)
}

func (v *Validator) http01(ctx context.Context, host, token, keyAuth string) error {
	u := "http://" + net.JoinHostPort(host, port(v.HTTPPort, 80)) + "/.well-known/acme-challenge/" + token
	client := &http.Client{
		Transport: &http.Transport{
			DialContext:     v.dial,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // redirects to https are allowed, trust not required (RFC 8555 §8.3)
			Proxy:           nil,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("User-Agent", "Conrad-ACME-Validator")
	resp, err := client.Do(req)
	if err != nil {
		return fail("connection", "HTTP-01: cannot fetch %s: %v", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fail("unauthorized", "HTTP-01: %s returned HTTP %d", u, resp.StatusCode)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if strings.TrimSpace(string(body)) != keyAuth {
		return fail("incorrectResponse", "HTTP-01: unexpected key authorization at %s", u)
	}
	return nil
}

// DNS01Value returns the TXT record value expected for keyAuth.
func DNS01Value(keyAuth string) string {
	sum := sha256.Sum256([]byte(keyAuth))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (v *Validator) dns01(ctx context.Context, domain, keyAuth string) error {
	name := "_acme-challenge." + strings.TrimPrefix(domain, "*.")
	want := DNS01Value(keyAuth)
	records, src, err := v.lookupTXT(ctx, name)
	if err != nil {
		return fail("dns", "DNS-01: TXT lookup for %s via %s failed: %v", name, src, err)
	}
	for _, r := range records {
		if r == want {
			return nil
		}
	}
	if len(records) == 0 {
		return fail("unauthorized", "DNS-01: TXT record %s not found via %s", name, src)
	}
	return fail("unauthorized", "DNS-01: TXT record %s found via %s but no value matches", name, src)
}

func (v *Validator) lookupTXT(ctx context.Context, name string) ([]string, string, error) {
	if len(v.Resolvers) == 0 {
		recs, err := net.DefaultResolver.LookupTXT(ctx, name)
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, "system resolver", nil
		}
		return recs, "system resolver", err
	}
	var lastErr error
	for _, r := range v.Resolvers {
		addr := r
		if _, _, err := net.SplitHostPort(r); err != nil {
			addr = net.JoinHostPort(r, "53")
		}
		recs, err := queryTXT(ctx, addr, dns.Fqdn(name), 0)
		if err == nil {
			return recs, addr, nil
		}
		lastErr = err
	}
	return nil, strings.Join(v.Resolvers, ","), lastErr
}

// queryTXT asks addr for TXT records of name, following CNAMEs (acme-dns style).
func queryTXT(ctx context.Context, addr, name string, depth int) ([]string, error) {
	if depth > 8 {
		return nil, errors.New("CNAME chain too long")
	}
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeTXT)
	m.RecursionDesired = true
	c := &dns.Client{Timeout: 5 * time.Second}
	in, _, err := c.ExchangeContext(ctx, m, addr)
	if err != nil {
		return nil, err
	}
	if in.Truncated {
		c.Net = "tcp"
		if in, _, err = c.ExchangeContext(ctx, m, addr); err != nil {
			return nil, err
		}
	}
	if in.Rcode == dns.RcodeNameError {
		return nil, nil
	}
	if in.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("rcode %s", dns.RcodeToString[in.Rcode])
	}
	var out []string
	var cname string
	for _, rr := range in.Answer {
		switch r := rr.(type) {
		case *dns.TXT:
			out = append(out, strings.Join(r.Txt, ""))
		case *dns.CNAME:
			if strings.EqualFold(r.Hdr.Name, name) {
				cname = r.Target
			}
		}
	}
	if len(out) == 0 && cname != "" {
		return queryTXT(ctx, addr, cname, depth+1)
	}
	return out, nil
}

// OIDACMEIdentifier is id-pe-acmeIdentifier (RFC 8737).
var OIDACMEIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

func (v *Validator) tlsALPN01(ctx context.Context, idType, idValue, keyAuth string) error {
	sni := idValue
	if idType == "ip" {
		ip := net.ParseIP(idValue)
		rev, err := dns.ReverseAddr(ip.String())
		if err != nil {
			return fail("malformed", "TLS-ALPN-01: %v", err)
		}
		sni = strings.TrimSuffix(rev, ".")
	}
	addr := net.JoinHostPort(idValue, port(v.TLSPort, 443))
	raw, err := v.dial(ctx, "tcp", addr)
	if err != nil {
		return fail("connection", "TLS-ALPN-01: cannot connect to %s: %v", addr, err)
	}
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{
		ServerName:         sni,
		NextProtos:         []string{"acme-tls/1"},
		InsecureSkipVerify: true, // the self-signed validation certificate is checked below
		MinVersion:         tls.VersionTLS12,
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		return fail("tls", "TLS-ALPN-01: handshake with %s failed: %v", addr, err)
	}
	st := conn.ConnectionState()
	if st.NegotiatedProtocol != "acme-tls/1" {
		return fail("tls", "TLS-ALPN-01: server did not negotiate acme-tls/1")
	}
	if len(st.PeerCertificates) == 0 {
		return fail("tls", "TLS-ALPN-01: no certificate presented")
	}
	return checkALPNCert(st.PeerCertificates[0], idType, idValue, keyAuth)
}

func checkALPNCert(cert *x509.Certificate, idType, idValue, keyAuth string) error {
	switch idType {
	case "ip":
		ip := net.ParseIP(idValue)
		if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(ip) || len(cert.DNSNames) != 0 {
			return fail("unauthorized", "TLS-ALPN-01: certificate must contain exactly IP %s", idValue)
		}
	default:
		if len(cert.DNSNames) != 1 || !strings.EqualFold(cert.DNSNames[0], idValue) || len(cert.IPAddresses) != 0 {
			return fail("unauthorized", "TLS-ALPN-01: certificate must contain exactly %s", idValue)
		}
	}
	sum := sha256.Sum256([]byte(keyAuth))
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(OIDACMEIdentifier) {
			continue
		}
		if !ext.Critical {
			return fail("unauthorized", "TLS-ALPN-01: acmeIdentifier extension must be critical")
		}
		var got []byte
		if _, err := asn1.Unmarshal(ext.Value, &got); err != nil || !bytes.Equal(got, sum[:]) {
			return fail("incorrectResponse", "TLS-ALPN-01: acmeIdentifier does not match key authorization")
		}
		return nil
	}
	return fail("unauthorized", "TLS-ALPN-01: acmeIdentifier extension missing")
}
