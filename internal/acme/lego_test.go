package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/miekg/dns"

	"github.com/davidemaggi/conrad/internal/ca"
	"github.com/davidemaggi/conrad/internal/challenge"
	"github.com/davidemaggi/conrad/internal/crypto/signer"
	"github.com/davidemaggi/conrad/internal/policy"
	"github.com/davidemaggi/conrad/internal/store"
)

type env struct {
	t      *testing.T
	srv    *httptest.Server
	acme   *Server
	svc    *ca.Service
	st     *store.Store
	dns    string
	mu     sync.Mutex
	txt    map[string][]string
	events []Event
}

func newEnv(t *testing.T) *env {
	t.Helper()
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")
	ctx := context.Background()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	svc := ca.New(st, signer.NewSoftware(), "https://conrad.test", nil)
	if _, _, err := svc.Init(ctx, ca.InitRequest{Secret: "a very long passphrase", Subject: ca.Subject{CommonName: "Test Root"},
		Issuer: ca.IssuerRequest{Slug: "default", Name: "Default"}}); err != nil {
		t.Fatal(err)
	}
	p := policy.Default()
	p.AllowedDomains = []string{"*.home.lab"}
	p.AllowIPs = true
	if err := policy.Save(ctx, st, "default", p); err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, svc: svc, st: st, txt: map[string][]string{}}
	e.startDNS()

	v := &challenge.Validator{Resolvers: []string{e.dns}, Timeout: 5 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(addr)
			var d net.Dialer
			return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		}}
	e.acme = New(svc, v, "", nil)
	e.acme.RetrySchedule = []time.Duration{0, 100 * time.Millisecond, 100 * time.Millisecond}
	e.acme.OnEvent = func(_ context.Context, ev Event) { e.mu.Lock(); e.events = append(e.events, ev); e.mu.Unlock() }
	e.srv = httptest.NewUnstartedServer(e.acme.Handler())
	e.srv.StartTLS()
	t.Cleanup(e.srv.Close)
	e.acme.BaseURL = e.srv.URL
	cctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	e.acme.Start(cctx)
	return e
}

func (e *env) startDNS() {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		e.t.Fatal(err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		e.mu.Lock()
		vals := e.txt[strings.ToLower(q.Name)]
		e.mu.Unlock()
		if q.Qtype == dns.TypeTXT && len(vals) > 0 {
			for _, v := range vals {
				m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1}, Txt: []string{v}})
			}
		} else if len(vals) == 0 {
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	e.t.Cleanup(func() { _ = srv.Shutdown() })
	e.dns = pc.LocalAddr().String()
}

// dnsProvider publishes DNS-01 records into the fake DNS server.
type dnsProvider struct{ e *env }

func (p dnsProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	p.e.mu.Lock()
	defer p.e.mu.Unlock()
	p.e.txt[info.FQDN] = append(p.e.txt[info.FQDN], info.Value)
	return nil
}
func (p dnsProvider) CleanUp(domain, token, keyAuth string) error { return nil }
func (p dnsProvider) Timeout() (time.Duration, time.Duration) {
	return 5 * time.Second, 50 * time.Millisecond
}

type user struct {
	key crypto.PrivateKey
	reg *registration.Resource
}

func (u *user) GetEmail() string                        { return "admin@home.lab" }
func (u *user) GetRegistration() *registration.Resource { return u.reg }
func (u *user) GetPrivateKey() crypto.PrivateKey        { return u.key }

func (e *env) client(slug string, u *user) (*lego.Client, *user) {
	e.t.Helper()
	if u == nil {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		u = &user{key: k}
	}
	cfg := lego.NewConfig(u)
	cfg.CADirURL = e.srv.URL + "/acme/" + slug + "/directory"
	cfg.HTTPClient = e.srv.Client()
	cfg.Certificate.KeyType = certcrypto.EC256
	c, err := lego.NewClient(cfg)
	if err != nil {
		e.t.Fatal(err)
	}
	return c, u
}

func (e *env) register(c *lego.Client, u *user) {
	e.t.Helper()
	reg, err := c.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		e.t.Fatal(err)
	}
	u.reg = reg
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func leaf(t *testing.T, res *certificate.Resource) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode(res.Certificate)
	x, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func (e *env) verify(res *certificate.Resource, name string) *x509.Certificate {
	e.t.Helper()
	root, _ := e.svc.Root(context.Background())
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(root.CertPEM))
	inter := x509.NewCertPool()
	inter.AppendCertsFromPEM(res.IssuerCertificate)
	x := leaf(e.t, res)
	// certbot's chain.pem is the first cert after the leaf: it must be the issuer, not the leaf again.
	if b, _ := pem.Decode(res.IssuerCertificate); b == nil {
		e.t.Fatal("no issuer certificate in chain")
	} else if ic, err := x509.ParseCertificate(b.Bytes); err != nil || x.CheckSignatureFrom(ic) != nil {
		e.t.Fatalf("first chain certificate is not the leaf's issuer (subject %v)", ic.Subject)
	}
	if _, err := x.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: name}); err != nil {
		e.t.Fatalf("chain does not verify: %v", err)
	}
	return x
}

func (e *env) useHTTP01(c *lego.Client) {
	port := freePort(e.t)
	e.acme.Validator.HTTPPort = port
	if err := c.Challenge.SetHTTP01Provider(http01.NewProviderServer("127.0.0.1", strconv.Itoa(port))); err != nil {
		e.t.Fatal(err)
	}
}

func TestLegoHTTP01RenewRevoke(t *testing.T) {
	e := newEnv(t)
	c, u := e.client("default", nil)
	e.register(c, u)
	e.useHTTP01(c)

	res, err := c.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{"nas.home.lab", "www.home.lab"}, Bundle: true})
	if err != nil {
		t.Fatal(err)
	}
	x := e.verify(res, "www.home.lab")
	if len(x.DNSNames) != 2 {
		t.Fatalf("SANs = %v", x.DNSNames)
	}

	// ARI: the window is in the last third of the lifetime.
	ri, err := c.Certificate.GetRenewalInfo(certificate.RenewalInfoRequest{Cert: x})
	if err != nil {
		t.Fatal(err)
	}
	if !ri.SuggestedWindow.Start.After(x.NotBefore.Add(50 * 24 * time.Hour)) {
		t.Fatalf("unexpected ARI window %v", ri.SuggestedWindow)
	}

	// Renewal replacing the first certificate.
	certID, _ := certificate.MakeARICertID(x)
	res2, err := c.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{"nas.home.lab", "www.home.lab"}, Bundle: true, ReplacesCertID: certID})
	if err != nil {
		t.Fatal(err)
	}
	e.verify(res2, "nas.home.lab")

	// The /acme/directory alias serves the default issuer too.
	alias, _ := e.client("", nil)
	_ = alias

	if err := c.Certificate.Revoke(res.Certificate); err != nil {
		t.Fatal(err)
	}
	rec, err := e.st.GetCertificateBySerial(context.Background(), ca.SerialHex(x.SerialNumber))
	if err != nil || rec.Status != store.CertRevoked {
		t.Fatalf("cert should be revoked: %+v %v", rec, err)
	}
	ri, err = c.Certificate.GetRenewalInfo(certificate.RenewalInfoRequest{Cert: x})
	if err != nil || ri.SuggestedWindow.End.After(time.Now().Add(time.Minute)) {
		t.Fatalf("revoked cert should renew now: %+v %v", ri, err)
	}
	if err := c.Certificate.Revoke(res.Certificate); err == nil || !strings.Contains(err.Error(), "alreadyRevoked") {
		t.Fatalf("second revoke: %v", err)
	}
}

func TestLegoDNS01Wildcard(t *testing.T) {
	e := newEnv(t)
	c, u := e.client("default", nil)
	e.register(c, u)
	err := c.Challenge.SetDNS01Provider(dnsProvider{e},
		dns01.AddRecursiveNameservers([]string{e.dns}),
		dns01.WrapPreCheck(func(string, string, string, dns01.PreCheckFunc) (bool, error) { return true, nil }))
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{"*.k8s.home.lab", "k8s.home.lab"}, Bundle: true})
	if err != nil {
		t.Fatal(err)
	}
	e.verify(res, "grafana.k8s.home.lab")
}

func TestLegoTLSALPN01(t *testing.T) {
	e := newEnv(t)
	c, u := e.client("default", nil)
	e.register(c, u)
	port := freePort(t)
	e.acme.Validator.TLSPort = port
	if err := c.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer("127.0.0.1", strconv.Itoa(port))); err != nil {
		t.Fatal(err)
	}
	res, err := c.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{"router.home.lab"}, Bundle: true})
	if err != nil {
		t.Fatal(err)
	}
	e.verify(res, "router.home.lab")
}

func TestLegoEAB(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	p, _ := policy.Load(ctx, e.st, "default")
	p.RequireEAB = true
	if err := policy.Save(ctx, e.st, "default", p); err != nil {
		t.Fatal(err)
	}
	c, _ := e.client("default", nil)
	if _, err := c.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true}); err == nil || !strings.Contains(err.Error(), "externalAccountRequired") {
		t.Fatalf("want externalAccountRequired, got %v", err)
	}
	key, err := e.st.CreateEABKey(ctx, "default", "test")
	if err != nil {
		t.Fatal(err)
	}
	opts := registration.RegisterEABOptions{TermsOfServiceAgreed: true, Kid: key.ID, HmacEncoded: key.EncodedHMAC()}
	if _, err := c.Registration.RegisterWithExternalAccountBinding(opts); err != nil {
		t.Fatal(err)
	}
	c2, _ := e.client("default", nil)
	if _, err := c2.Registration.RegisterWithExternalAccountBinding(opts); err == nil {
		t.Fatal("EAB key reuse must fail")
	}
}

func TestIssuerIsolation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.svc.CreateIssuer(ctx, ca.IssuerRequest{Slug: "lab", Name: "Lab"}); err != nil {
		t.Fatal(err)
	}
	p := policy.Default()
	p.AllowedDomains = []string{"*.lab.internal"}
	if err := policy.Save(ctx, e.st, "lab", p); err != nil {
		t.Fatal(err)
	}

	// An account from the default directory is unknown to "lab".
	cd, ud := e.client("default", nil)
	e.register(cd, ud)
	cl, _ := e.client("lab", ud)
	e.useHTTP01(cl)
	if _, err := cl.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{"svc.lab.internal"}}); err == nil || !strings.Contains(err.Error(), "accountDoesNotExist") {
		t.Fatalf("cross-directory kid should fail, got %v", err)
	}

	cl, ul := e.client("lab", nil)
	e.register(cl, ul)
	e.useHTTP01(cl)
	if _, err := cl.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{"nas.home.lab"}}); err == nil || !strings.Contains(err.Error(), "rejectedIdentifier") {
		t.Fatalf("lab policy should reject home.lab, got %v", err)
	}
	res, err := cl.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{"svc.lab.internal"}, Bundle: true})
	if err != nil {
		t.Fatal(err)
	}
	x := e.verify(res, "svc.lab.internal")
	rec, _ := e.st.GetCertificateBySerial(ctx, ca.SerialHex(x.SerialNumber))
	if rec.IssuerSlug != "lab" {
		t.Fatalf("issued by %q", rec.IssuerSlug)
	}
}

func TestChallengeFailure(t *testing.T) {
	e := newEnv(t)
	c, u := e.client("default", nil)
	e.register(c, u)
	port := freePort(t)
	e.acme.Validator.HTTPPort = freePort(t) // validator looks at a port nobody listens on
	if err := c.Challenge.SetHTTP01Provider(http01.NewProviderServer("127.0.0.1", strconv.Itoa(port))); err != nil {
		t.Fatal(err)
	}
	_, err := c.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{"down.home.lab"}})
	if err == nil || !strings.Contains(err.Error(), "connection") {
		t.Fatalf("want connection error, got %v", err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	found := false
	for _, ev := range e.events {
		found = found || ev.Type == "challenge.invalid"
	}
	if !found {
		t.Fatal("challenge.invalid event not emitted")
	}
}
