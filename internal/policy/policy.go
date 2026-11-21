// Package policy decides which identifiers, keys and lifetimes an issuer accepts.
package policy

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/davidemaggi/conrad/internal/store"
)

// Challenge types.
const (
	HTTP01    = "http-01"
	DNS01     = "dns-01"
	TLSALPN01 = "tls-alpn-01"
)

// Key types accepted in CSRs.
var AllKeyTypes = []string{"rsa-2048", "rsa-3072", "rsa-4096", "ecdsa-p256", "ecdsa-p384", "ed25519"}

// ErrRejected wraps every identifier rejection.
var ErrRejected = errors.New("identifier rejected by policy")

// Policy is stored per issuer slug.
type Policy struct {
	AllowedDomains      []string  `json:"allowedDomains"`
	AllowWildcards      bool      `json:"allowWildcards"`
	AllowIPs            bool      `json:"allowIPs"`
	DefaultValidityDays int       `json:"defaultValidityDays"`
	MaxValidityDays     int       `json:"maxValidityDays"`
	KeyTypes            []string  `json:"keyTypes"`
	Challenges          []string  `json:"challenges"`
	RequireEAB          bool      `json:"requireEAB"`
	ClientAuth          bool      `json:"clientAuth"`
	RateLimits          RateLimit `json:"rateLimits"`
}

// RateLimit caps ACME activity; zero means unlimited.
type RateLimit struct {
	OrdersPerAccountPerHour int `json:"ordersPerAccountPerHour"`
	NewAccountsPerIPPerHour int `json:"newAccountsPerIPPerHour"`
}

// Default returns the policy used for new issuers.
func Default() Policy {
	return Policy{
		AllowedDomains:      []string{"*.home.lab", "*.lan", "*.internal"},
		AllowWildcards:      true,
		AllowIPs:            false,
		DefaultValidityDays: 90,
		MaxValidityDays:     397,
		KeyTypes:            append([]string{}, AllKeyTypes...),
		Challenges:          []string{HTTP01, DNS01, TLSALPN01},
		RateLimits:          RateLimit{OrdersPerAccountPerHour: 300, NewAccountsPerIPPerHour: 50},
	}
}

// Validate normalizes and checks the policy.
func (p *Policy) Validate() error {
	var errs []error
	var doms []string
	for _, d := range p.AllowedDomains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		base := strings.TrimPrefix(d, "*.")
		if !validDNSName(base) {
			errs = append(errs, fmt.Errorf("invalid allowed domain %q", d))
		}
		doms = append(doms, d)
	}
	p.AllowedDomains = doms
	if p.DefaultValidityDays < 1 {
		errs = append(errs, errors.New("defaultValidityDays must be >= 1"))
	}
	if p.MaxValidityDays < p.DefaultValidityDays || p.MaxValidityDays > 3650 {
		errs = append(errs, errors.New("maxValidityDays must be between defaultValidityDays and 3650"))
	}
	for _, k := range p.KeyTypes {
		if !in(AllKeyTypes, k) {
			errs = append(errs, fmt.Errorf("unknown key type %q", k))
		}
	}
	if len(p.KeyTypes) == 0 {
		errs = append(errs, errors.New("at least one key type is required"))
	}
	for _, c := range p.Challenges {
		if c != HTTP01 && c != DNS01 && c != TLSALPN01 {
			errs = append(errs, fmt.Errorf("unknown challenge %q", c))
		}
	}
	if len(p.Challenges) == 0 {
		errs = append(errs, errors.New("at least one challenge type is required"))
	}
	return errors.Join(errs...)
}

// CheckIdentifier verifies an ACME identifier (type "dns" or "ip").
func (p Policy) CheckIdentifier(typ, value string) error {
	switch typ {
	case "dns":
		v := strings.ToLower(strings.TrimSuffix(value, "."))
		wildcard := strings.HasPrefix(v, "*.")
		base := strings.TrimPrefix(v, "*.")
		if !validDNSName(base) || strings.Contains(base, "*") {
			return fmt.Errorf("%w: %q is not a valid DNS name", ErrRejected, value)
		}
		probe := base
		if wildcard {
			if !p.AllowWildcards {
				return fmt.Errorf("%w: wildcards are not allowed", ErrRejected)
			}
			probe = "wildcard-probe." + base
		}
		if !p.domainAllowed(probe) {
			return fmt.Errorf("%w: %q is outside the allowed domains", ErrRejected, value)
		}
		return nil
	case "ip":
		ip := net.ParseIP(value)
		if ip == nil {
			return fmt.Errorf("%w: %q is not an IP address", ErrRejected, value)
		}
		if !p.AllowIPs {
			return fmt.Errorf("%w: IP identifiers are not allowed", ErrRejected)
		}
		if !ip.IsPrivate() && !ip.IsLoopback() {
			return fmt.Errorf("%w: only private IP addresses are allowed", ErrRejected)
		}
		return nil
	}
	return fmt.Errorf("%w: unsupported identifier type %q", ErrRejected, typ)
}

func (p Policy) domainAllowed(name string) bool {
	for _, pat := range p.AllowedDomains {
		if strings.HasPrefix(pat, "*.") {
			if strings.HasSuffix(name, pat[1:]) && len(name) > len(pat)-1 {
				return true
			}
		} else if name == pat {
			return true
		}
	}
	return false
}

// ChallengesFor returns the challenge types offered for an identifier.
func (p Policy) ChallengesFor(typ string, wildcard bool) []string {
	var out []string
	for _, c := range p.Challenges {
		switch {
		case wildcard && c != DNS01:
		case typ == "ip" && c == DNS01:
		default:
			out = append(out, c)
		}
	}
	return out
}

// CheckKey verifies the CSR public key type.
func (p Policy) CheckKey(pub crypto.PublicKey) error {
	var t string
	switch k := pub.(type) {
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		switch {
		case bits >= 4096:
			t = "rsa-4096"
		case bits >= 3072:
			t = "rsa-3072"
		case bits >= 2048:
			t = "rsa-2048"
		default:
			return errors.New("RSA keys must be at least 2048 bits")
		}
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			t = "ecdsa-p256"
		case elliptic.P384():
			t = "ecdsa-p384"
		default:
			return errors.New("unsupported ECDSA curve")
		}
	case ed25519.PublicKey:
		t = "ed25519"
	default:
		return errors.New("unsupported key type")
	}
	if !in(p.KeyTypes, t) {
		return fmt.Errorf("key type %s is not allowed by policy", t)
	}
	return nil
}

// Validity clamps a requested lifetime to the policy.
func (p Policy) Validity(requested time.Duration) time.Duration {
	def := time.Duration(p.DefaultValidityDays) * 24 * time.Hour
	max := time.Duration(p.MaxValidityDays) * 24 * time.Hour
	if requested <= 0 {
		return def
	}
	if requested > max {
		return max
	}
	return requested
}

// Load returns the policy for slug, or Default() if none is stored.
func Load(ctx context.Context, st *store.Store, slug string) (Policy, error) {
	raw, err := st.GetPolicyJSON(ctx, slug)
	if errors.Is(err, store.ErrNotFound) {
		return Default(), nil
	}
	if err != nil {
		return Policy{}, err
	}
	p := Default()
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// Save validates and stores the policy for slug.
func Save(ctx context.Context, st *store.Store, slug string, p Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	b, _ := json.Marshal(p)
	return st.SetPolicyJSON(ctx, slug, string(b))
}

func validDNSName(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		// Single-label names (e.g. "nas") are allowed for homelabs only via exact match.
		return validLabel(s)
	}
	for _, l := range labels {
		if !validLabel(l) {
			return false
		}
	}
	return true
}

func validLabel(l string) bool {
	if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for _, r := range l {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func in(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
