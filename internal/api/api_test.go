package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/davidemaggi/conrad/internal/audit"
	"github.com/davidemaggi/conrad/internal/auth"
	"github.com/davidemaggi/conrad/internal/ca"
	"github.com/davidemaggi/conrad/internal/crypto/signer"
	"github.com/davidemaggi/conrad/internal/notify"
	"github.com/davidemaggi/conrad/internal/store"
)

type client struct {
	t    *testing.T
	srv  *httptest.Server
	http *http.Client
	csrf string
}

func (c *client) do(method, path string, body any, out any) int {
	c.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, c.srv.URL+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if c.csrf != "" {
		req.Header.Set(auth.CSRFHeader, c.csrf)
	}
	res, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	if out != nil {
		_ = json.NewDecoder(res.Body).Decode(out)
	}
	return res.StatusCode
}

func setupAPI(t *testing.T) (*client, *SetupToken, *store.Store) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	svc := ca.New(st, signer.NewSoftware(), "https://conrad.test", nil)
	tok := NewSetupToken()
	a := New(Deps{Store: st, CA: svc, Sessions: auth.NewSessions(st, false), OIDC: auth.NewOIDC(st, "https://conrad.test/api/v1/auth/oidc/callback"),
		Audit: audit.New(st, nil), Notifier: notify.New(st, "https://conrad.test", nil), Setup: tok, BaseURL: "https://conrad.test", Version: "test"})
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return &client{t: t, srv: srv, http: &http.Client{Jar: jar}}, tok, st
}

func doSetup(t *testing.T, c *client, tok string) {
	t.Helper()
	body := map[string]any{
		"token": tok,
		"admin": map[string]any{"username": "hermes", "password": "bureaucrat grade 36", "language": "it"},
		"ca": map[string]any{"passphrase": "a very long passphrase", "subject": map[string]any{"commonName": "Conrad Root"},
			"algorithm": "ecdsa-p256", "validityYears": 10, "issuer": map[string]any{"slug": "homelab", "name": "Homelab", "validityYears": 3}},
	}
	var out struct{ CSRFToken string }
	if code := c.do("POST", "/api/v1/setup", body, &out); code != 201 {
		t.Fatalf("setup: %d", code)
	}
	c.csrf = out.CSRFToken
}

func TestSetupLoginAndCSRF(t *testing.T) {
	c, tok, _ := setupAPI(t)
	var st map[string]any
	c.do("GET", "/api/v1/system/status", nil, &st)
	if st["setupRequired"] != true {
		t.Fatal("setup should be required")
	}
	if code := c.do("POST", "/api/v1/setup", map[string]any{"token": "wrong"}, nil); code != 403 {
		t.Fatalf("bad token: %d", code)
	}
	doSetup(t, c, tok.Value())
	if tok.Value() != "" {
		t.Fatal("token not consumed")
	}
	if code := c.do("POST", "/api/v1/setup", map[string]any{"token": "x"}, nil); code != 409 {
		t.Fatalf("second setup: %d", code)
	}
	var me map[string]any
	if code := c.do("GET", "/api/v1/auth/me", nil, &me); code != 200 {
		t.Fatalf("me: %d", code)
	}

	// CSRF: unsafe request without header is rejected.
	csrf := c.csrf
	c.csrf = ""
	if code := c.do("POST", "/api/v1/auth/logout", nil, nil); code != 403 {
		t.Fatalf("logout without csrf: %d", code)
	}
	c.csrf = csrf
	if code := c.do("POST", "/api/v1/auth/logout", nil, nil); code != 204 {
		t.Fatalf("logout: %d", code)
	}
	if code := c.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Fatalf("me after logout: %d", code)
	}
	if code := c.do("POST", "/api/v1/auth/login", map[string]any{"username": "hermes", "password": "nope nope nope"}, nil); code != 401 {
		t.Fatalf("bad login: %d", code)
	}
	var lo struct{ CSRFToken string }
	if code := c.do("POST", "/api/v1/auth/login", map[string]any{"username": "Hermes", "password": "bureaucrat grade 36"}, &lo); code != 200 {
		t.Fatalf("login: %d", code)
	}
	c.csrf = lo.CSRFToken
	if code := c.do("PUT", "/api/v1/settings/auth", map[string]any{"passwordLoginEnabled": false}, nil); code != 400 {
		t.Fatalf("disabling only login method should fail: %d", code)
	}
}

func TestAuthoritiesAndCertificates(t *testing.T) {
	c, tok, _ := setupAPI(t)
	doSetup(t, c, tok.Value())

	var list struct{ Items []authorityView }
	c.do("GET", "/api/v1/authorities", nil, &list)
	if len(list.Items) != 2 {
		t.Fatalf("want root+issuer, got %d", len(list.Items))
	}
	var created authorityView
	if code := c.do("POST", "/api/v1/authorities", map[string]any{"slug": "lab2", "name": "Lab 2", "validityYears": 2, "clonePolicyFrom": "homelab"}, &created); code != 201 {
		t.Fatalf("create issuer: %d", code)
	}
	if created.DirectoryURL != "https://conrad.test/acme/lab2/directory" || created.Algorithm == "" {
		t.Fatalf("bad view: %+v", created)
	}
	if code := c.do("POST", "/api/v1/authorities", map[string]any{"slug": "lab2", "name": "dup"}, nil); code != 409 {
		t.Fatalf("dup slug: %d", code)
	}

	var pol map[string]any
	c.do("GET", "/api/v1/authorities/"+created.ID+"/policy", nil, &pol)
	pol["requireEab"] = true
	if code := c.do("PUT", "/api/v1/authorities/"+created.ID+"/policy", pol, nil); code != 200 {
		t.Fatalf("put policy: %d", code)
	}
	var eab struct{ Kid, Hmac string }
	if code := c.do("POST", "/api/v1/authorities/"+created.ID+"/eab-keys", map[string]any{"name": "nas"}, &eab); code != 201 || eab.Hmac == "" {
		t.Fatalf("eab: %d", code)
	}

	var issued struct {
		Certificate store.Certificate
		KeyPem, Pfx string
	}
	if code := c.do("POST", "/api/v1/certificates", map[string]any{"issuer": "lab2", "names": []string{"nas.home.lab", "10.0.0.5"}, "pfxPassword": "secret"}, &issued); code != 201 {
		t.Fatalf("issue: %d", code)
	}
	if issued.KeyPem == "" || issued.Pfx == "" || len(issued.Certificate.SANs) != 2 {
		t.Fatalf("bad issue response: %+v", issued.Certificate)
	}
	var certs struct {
		Items []store.Certificate
		Total int
	}
	c.do("GET", "/api/v1/certificates?q=nas", nil, &certs)
	if certs.Total != 1 {
		t.Fatalf("list: %d", certs.Total)
	}
	if code := c.do("POST", "/api/v1/certificates/"+issued.Certificate.ID+"/revoke", map[string]any{"reason": 4}, nil); code != 200 {
		t.Fatalf("revoke: %d", code)
	}
	if code := c.do("POST", "/api/v1/authorities/"+created.ID+"/revoke", map[string]any{"confirm": "nope"}, nil); code != 400 {
		t.Fatalf("revoke confirm: %d", code)
	}
	if code := c.do("POST", "/api/v1/authorities/"+created.ID+"/revoke", map[string]any{"confirm": "lab2"}, nil); code != 200 {
		t.Fatalf("revoke issuer: %d", code)
	}
	var dash map[string]any
	if code := c.do("GET", "/api/v1/dashboard", nil, &dash); code != 200 {
		t.Fatalf("dashboard: %d", code)
	}
	var aud struct{ Total int }
	c.do("GET", "/api/v1/audit?action=issuer.", nil, &aud)
	if aud.Total < 2 {
		t.Fatalf("audit entries: %d", aud.Total)
	}
	res, _ := c.http.Get(c.srv.URL + "/api/v1/system/backup")
	if res.StatusCode != 200 {
		t.Fatalf("backup: %d", res.StatusCode)
	}
	res.Body.Close()
}

func TestNotificationChannels(t *testing.T) {
	c, tok, _ := setupAPI(t)
	doSetup(t, c, tok.Value())
	hits := 0
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer hook.Close()

	var ch map[string]any
	if code := c.do("POST", "/api/v1/notifications/channels", map[string]any{"kind": "webhook", "name": "ntfy", "enabled": true,
		"webhook": map[string]any{"url": hook.URL, "secret": "s3cret"}}, &ch); code != 201 {
		t.Fatalf("create channel: %d %v", code, ch)
	}
	id := ch["id"].(string)
	var list struct{ Items []map[string]any }
	c.do("GET", "/api/v1/notifications/channels", nil, &list)
	wh := list.Items[0]["webhook"].(map[string]any)
	if wh["secret"] != nil || list.Items[0]["secretSet"] != true {
		t.Fatalf("secret leaked or not flagged: %v", list.Items[0])
	}
	if code := c.do("POST", "/api/v1/notifications/channels/"+id+"/test", nil, nil); code != 200 || hits != 1 {
		t.Fatalf("test: %d hits=%d", code, hits)
	}
	if code := c.do("POST", "/api/v1/notifications/channels", map[string]any{"kind": "smtp", "name": "x", "smtp": map[string]any{"host": "m"}}, nil); code != 400 {
		t.Fatalf("invalid smtp accepted: %d", code)
	}
	if code := c.do("PUT", "/api/v1/notifications/settings", map[string]any{"thresholdsDays": []int{21, 3}}, nil); code != 200 {
		t.Fatalf("thresholds: %d", code)
	}
	if code := c.do("DELETE", "/api/v1/notifications/channels/"+id, nil, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
}
