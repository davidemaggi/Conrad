package policy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"
)

func TestCheckIdentifier(t *testing.T) {
	p := Default()
	p.AllowedDomains = []string{"*.home.lab", "router.lan"}
	cases := []struct {
		typ, v string
		ok     bool
	}{
		{"dns", "nas.home.lab", true},
		{"dns", "a.b.home.lab", true},
		{"dns", "home.lab", false},
		{"dns", "*.home.lab", true},
		{"dns", "*.k8s.home.lab", true},
		{"dns", "router.lan", true},
		{"dns", "x.router.lan", false},
		{"dns", "evilhome.lab", false},
		{"dns", "google.com", false},
		{"dns", "bad_name.home.lab", false},
		{"dns", "a.*.home.lab", false},
		{"ip", "192.168.1.10", false},
	}
	for _, c := range cases {
		err := p.CheckIdentifier(c.typ, c.v)
		if (err == nil) != c.ok {
			t.Errorf("%s %s: ok=%v err=%v", c.typ, c.v, c.ok, err)
		}
		if err != nil && !errors.Is(err, ErrRejected) {
			t.Errorf("error should wrap ErrRejected: %v", err)
		}
	}
	p.AllowIPs = true
	if err := p.CheckIdentifier("ip", "192.168.1.10"); err != nil {
		t.Error(err)
	}
	if err := p.CheckIdentifier("ip", "8.8.8.8"); err == nil {
		t.Error("public IP must be rejected")
	}
	p.AllowWildcards = false
	if err := p.CheckIdentifier("dns", "*.home.lab"); err == nil {
		t.Error("wildcards disabled")
	}
}

func TestChallengesFor(t *testing.T) {
	p := Default()
	if got := p.ChallengesFor("dns", true); len(got) != 1 || got[0] != DNS01 {
		t.Errorf("wildcard => dns-01 only, got %v", got)
	}
	if got := p.ChallengesFor("ip", false); len(got) != 2 {
		t.Errorf("ip => no dns-01, got %v", got)
	}
}

func TestCheckKeyAndValidity(t *testing.T) {
	p := Default()
	p.KeyTypes = []string{"ecdsa-p256"}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := p.CheckKey(&ec.PublicKey); err != nil {
		t.Error(err)
	}
	r, _ := rsa.GenerateKey(rand.Reader, 2048)
	if err := p.CheckKey(&r.PublicKey); err == nil {
		t.Error("rsa should be rejected")
	}
	if v := p.Validity(0); v != 90*24*time.Hour {
		t.Errorf("default validity %v", v)
	}
	if v := p.Validity(1000 * 24 * time.Hour); v != 397*24*time.Hour {
		t.Errorf("clamped validity %v", v)
	}
}

func TestValidate(t *testing.T) {
	p := Default()
	p.AllowedDomains = []string{" *.Home.Lab ", ""}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if p.AllowedDomains[0] != "*.home.lab" || len(p.AllowedDomains) != 1 {
		t.Errorf("normalized = %v", p.AllowedDomains)
	}
	p.Challenges = []string{"bogus"}
	if err := p.Validate(); err == nil {
		t.Error("bad challenge accepted")
	}
}
