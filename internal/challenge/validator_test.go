package challenge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const keyAuth = "token123.thumbprint"

func portOf(t *testing.T, addr string) int {
	_, p, _ := net.SplitHostPort(addr)
	n, _ := strconv.Atoi(p)
	return n
}

func TestHTTP01(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/acme-challenge/token123" {
			w.Write([]byte(keyAuth + "\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	v := &Validator{HTTPPort: portOf(t, srv.Listener.Addr().String())}
	if err := v.Validate(context.Background(), "http-01", "dns", "127.0.0.1", "token123", keyAuth); err != nil {
		t.Fatal(err)
	}
	err := v.Validate(context.Background(), "http-01", "dns", "127.0.0.1", "other", keyAuth)
	var ce *Error
	if !errors.As(err, &ce) || ce.Type != "unauthorized" {
		t.Fatalf("want unauthorized, got %v", err)
	}
}

func TestDNS01WithCNAME(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		switch q.Name {
		case "_acme-challenge.nas.home.lab.":
			m.Answer = append(m.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 1}, Target: "delegated.acme.lab."})
		case "delegated.acme.lab.":
			m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1}, Txt: []string{DNS01Value(keyAuth)}})
		default:
			m.Rcode = dns.RcodeNameError
		}
		w.WriteMsg(m)
	})
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go srv.ActivateAndServe()
	defer srv.Shutdown()

	v := &Validator{Resolvers: []string{pc.LocalAddr().String()}}
	if err := v.Validate(context.Background(), "dns-01", "dns", "*.nas.home.lab", "", keyAuth); err != nil {
		t.Fatal(err)
	}
	err = v.Validate(context.Background(), "dns-01", "dns", "missing.home.lab", "", keyAuth)
	var ce *Error
	if !errors.As(err, &ce) || ce.Type != "unauthorized" {
		t.Fatalf("want unauthorized, got %v", err)
	}
}

func alpnCert(t *testing.T, name string, ka string, critical bool) tls.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sum := sha256.Sum256([]byte(ka))
	val, _ := asn1.Marshal(sum[:])
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: name},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		DNSNames:        []string{name},
		ExtraExtensions: []pkix.Extension{{Id: OIDACMEIdentifier, Critical: critical, Value: val}},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func TestTLSALPN01(t *testing.T) {
	cert := alpnCert(t, "nas.home.lab", keyAuth, true)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"acme-tls/1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	v := &Validator{TLSPort: portOf(t, ln.Addr().String())}
	if err := checkALPNCert(mustParse(cert), "dns", "nas.home.lab", keyAuth); err != nil {
		t.Fatal(err)
	}
	if err := checkALPNCert(mustParse(alpnCert(t, "nas.home.lab", keyAuth, false)), "dns", "nas.home.lab", keyAuth); err == nil {
		t.Fatal("non-critical extension must fail")
	}
	if err := checkALPNCert(mustParse(alpnCert(t, "nas.home.lab", "wrong", true)), "dns", "nas.home.lab", keyAuth); err == nil {
		t.Fatal("wrong digest must fail")
	}
	err = v.Validate(context.Background(), "tls-alpn-01", "dns", "127.0.0.1", "", keyAuth)
	var ce *Error
	if !errors.As(err, &ce) || ce.Type != "unauthorized" {
		t.Fatalf("network path: want unauthorized (name mismatch), got %v", err)
	}
}

func mustParse(c tls.Certificate) *x509.Certificate {
	x, _ := x509.ParseCertificate(c.Certificate[0])
	return x
}
