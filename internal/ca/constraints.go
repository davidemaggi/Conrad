package ca

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/davidemaggi/conrad/internal/store"
)

// ErrNameNotPermitted means a DNS name falls outside the name constraints of
// the issuer or its root. Browsers reject such certificates outright.
var ErrNameNotPermitted = errors.New("name is outside the CA's name constraints")

// constraintSets returns the permitted DNS domains of every CA certificate in
// the issuer's chain that carries constraints. A name must satisfy all sets.
func (s *Service) constraintSets(ctx context.Context, issuer *store.Authority) [][]string {
	var sets [][]string
	for a := issuer; a != nil; {
		if c, err := s.certOf(a); err == nil && len(c.PermittedDNSDomains) > 0 {
			sets = append(sets, c.PermittedDNSDomains)
		}
		if a.ParentID == "" || a.ParentID == a.ID {
			break
		}
		p, err := s.store.GetAuthority(ctx, a.ParentID)
		if err != nil {
			break
		}
		a = p
	}
	return sets
}

// domainPermitted applies RFC 5280 dNSName constraint matching. A wildcard
// name is checked by its base domain.
func domainPermitted(domains []string, name string) bool {
	name = strings.TrimPrefix(strings.ToLower(strings.TrimSuffix(name, ".")), "*.")
	for _, d := range domains {
		d = strings.ToLower(d)
		if strings.HasPrefix(d, ".") {
			if strings.HasSuffix(name, d) {
				return true
			}
		} else if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

func checkConstraints(sets [][]string, dns []string) error {
	for _, n := range dns {
		for _, set := range sets {
			if !domainPermitted(set, n) {
				return fmt.Errorf("%w: %s (allowed: %s)", ErrNameNotPermitted, n, strings.Join(set, ", "))
			}
		}
	}
	return nil
}

// PermittedNames splits names (DNS names or IPs) into those the issuer can
// sign and those its name constraints forbid. IPs are always allowed: Conrad
// only sets DNS constraints.
func (s *Service) PermittedNames(ctx context.Context, slug string, names []string) (ok, rejected []string, err error) {
	issuer, err := s.Issuer(ctx, slug)
	if err != nil {
		return nil, nil, err
	}
	sets := s.constraintSets(ctx, issuer)
	for _, n := range names {
		if net.ParseIP(n) != nil || checkConstraints(sets, []string{n}) == nil {
			ok = append(ok, n)
		} else {
			rejected = append(rejected, n)
		}
	}
	return ok, rejected, nil
}
