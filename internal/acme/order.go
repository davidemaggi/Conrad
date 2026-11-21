package acme

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/davidemaggi/conrad/internal/ca"
	"github.com/davidemaggi/conrad/internal/policy"
	"github.com/davidemaggi/conrad/internal/store"
)

type ident = store.Identifier

type orderJSON struct {
	Status         string   `json:"status"`
	Expires        string   `json:"expires"`
	Identifiers    []ident  `json:"identifiers"`
	NotBefore      string   `json:"notBefore,omitempty"`
	NotAfter       string   `json:"notAfter,omitempty"`
	Error          *Problem `json:"error,omitempty"`
	Authorizations []string `json:"authorizations"`
	Finalize       string   `json:"finalize"`
	Certificate    string   `json:"certificate,omitempty"`
	Replaces       string   `json:"replaces,omitempty"`
}

type authzJSON struct {
	Identifier ident      `json:"identifier"`
	Status     string     `json:"status"`
	Expires    string     `json:"expires"`
	Challenges []chalJSON `json:"challenges"`
	Wildcard   bool       `json:"wildcard,omitempty"`
}

type chalJSON struct {
	Type      string   `json:"type"`
	URL       string   `json:"url"`
	Status    string   `json:"status"`
	Token     string   `json:"token"`
	Validated string   `json:"validated,omitempty"`
	Error     *Problem `json:"error,omitempty"`
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func normalizeIdent(id ident) (ident, *Problem) {
	switch id.Type {
	case "dns":
		v := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(id.Value), "."))
		return ident{Type: "dns", Value: v}, nil
	case "ip":
		ip := net.ParseIP(strings.TrimSpace(id.Value))
		if ip == nil {
			return id, malformed("invalid IP identifier %q", id.Value)
		}
		return ident{Type: "ip", Value: ip.String()}, nil
	}
	return id, prob(400, "unsupportedIdentifier", "identifier type %q is not supported", id.Type)
}

func (s *Server) newOrder(w http.ResponseWriter, r *http.Request, slug string) *Problem {
	req, p := s.verify(w, r, slug, needKID)
	if p != nil {
		return p
	}
	var in struct {
		Identifiers []ident `json:"identifiers"`
		NotBefore   string  `json:"notBefore"`
		NotAfter    string  `json:"notAfter"`
		Replaces    string  `json:"replaces"`
	}
	if p := req.decode(&in); p != nil {
		return p
	}
	if len(in.Identifiers) == 0 {
		return malformed("at least one identifier is required")
	}
	if len(in.Identifiers) > 100 {
		return rejectedID("at most 100 identifiers per order")
	}
	ctx := r.Context()
	now := s.Store.Now()
	pol, err := policy.Load(ctx, s.Store, slug)
	if err != nil {
		return serverErr("%v", err)
	}
	if lim := pol.RateLimits.OrdersPerAccountPerHour; lim > 0 {
		n, err := s.Store.CountOrdersSince(ctx, req.account.ID, now.Add(-time.Hour))
		if err != nil {
			return serverErr("%v", err)
		}
		if n >= lim {
			w.Header().Set("Retry-After", "3600")
			return prob(429, "rateLimited", "too many orders for this account in the last hour")
		}
	}

	seen := map[ident]bool{}
	var ids []ident
	var subs []*Problem
	for _, raw := range in.Identifiers {
		id, p := normalizeIdent(raw)
		if p != nil {
			return p
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		if err := pol.CheckIdentifier(id.Type, id.Value); err != nil {
			sp := rejectedID("%v", err)
			sp.Identifier = &ident{Type: id.Type, Value: id.Value}
			subs = append(subs, sp)
			continue
		}
		if id.Type == "dns" {
			if _, bad, err := s.CA.PermittedNames(ctx, slug, []string{id.Value}); err == nil && len(bad) > 0 {
				sp := rejectedID("%s is outside the CA's name constraints", id.Value)
				sp.Identifier = &ident{Type: id.Type, Value: id.Value}
				subs = append(subs, sp)
				continue
			}
		}
		wc := strings.HasPrefix(id.Value, "*.")
		if len(pol.ChallengesFor(id.Type, wc)) == 0 {
			sp := rejectedID("no challenge type is enabled for %s", id.Value)
			sp.Identifier = &ident{Type: id.Type, Value: id.Value}
			subs = append(subs, sp)
			continue
		}
		ids = append(ids, id)
	}
	if len(subs) > 0 {
		p := rejectedID("one or more identifiers are not allowed by the %q issuer policy", slug)
		p.Subproblems = subs
		return p
	}

	o := &store.Order{AccountID: req.account.ID, IssuerSlug: slug, Status: "pending", Identifiers: ids, ExpiresAt: now.Add(OrderTTL)}
	if in.NotBefore != "" {
		if o.NotBefore, err = time.Parse(time.RFC3339, in.NotBefore); err != nil {
			return malformed("invalid notBefore")
		}
	}
	if in.NotAfter != "" {
		if o.NotAfter, err = time.Parse(time.RFC3339, in.NotAfter); err != nil {
			return malformed("invalid notAfter")
		}
		start := o.NotBefore
		if start.IsZero() {
			start = now
		}
		if !o.NotAfter.After(start) {
			return malformed("notAfter must be after notBefore")
		}
		if o.NotAfter.Sub(start) > time.Duration(pol.MaxValidityDays)*24*time.Hour {
			return malformed("requested validity exceeds the policy maximum of %d days", pol.MaxValidityDays)
		}
	}
	if in.Replaces != "" {
		cert, p := s.certByARIID(ctx, in.Replaces)
		if p != nil {
			return p
		}
		if cert.AccountID != req.account.ID {
			return unauthorized("replaced certificate belongs to another account")
		}
		o.Replaces = in.Replaces
	}

	var authzs []*store.Authz
	var chals [][]*store.Challenge
	for _, id := range ids {
		wc := strings.HasPrefix(id.Value, "*.")
		a := &store.Authz{AccountID: req.account.ID, IDType: id.Type, IDValue: strings.TrimPrefix(id.Value, "*."), Wildcard: wc, Status: "pending", ExpiresAt: o.ExpiresAt}
		var cs []*store.Challenge
		for _, t := range pol.ChallengesFor(id.Type, wc) {
			cs = append(cs, &store.Challenge{Type: t, Token: randToken(), Status: "pending"})
		}
		authzs = append(authzs, a)
		chals = append(chals, cs)
	}
	if err := s.Store.CreateOrder(ctx, o, authzs, chals); err != nil {
		return serverErr("%v", err)
	}
	s.emit(ctx, Event{Type: "order.created", IssuerSlug: slug, AccountID: o.AccountID, Target: o.ID, Detail: map[string]any{"identifiers": ids}})
	return s.writeOrder(w, ctx, o, http.StatusCreated)
}

func (s *Server) writeOrder(w http.ResponseWriter, ctx context.Context, o *store.Order, status int) *Problem {
	authzs, err := s.Store.AuthzsForOrder(ctx, o.ID)
	if err != nil {
		return serverErr("%v", err)
	}
	b := s.base(o.IssuerSlug)
	out := orderJSON{
		Status: o.Status, Expires: rfc3339(o.ExpiresAt), Identifiers: o.Identifiers,
		NotBefore: rfc3339(o.NotBefore), NotAfter: rfc3339(o.NotAfter), Error: parseProblem(o.Error),
		Finalize: b + "/order/" + o.ID + "/finalize", Replaces: o.Replaces, Authorizations: []string{},
	}
	for _, a := range authzs {
		out.Authorizations = append(out.Authorizations, b+"/authz/"+a.ID)
	}
	if o.CertificateID != "" {
		out.Certificate = b + "/cert/" + o.CertificateID
	}
	w.Header().Set("Location", b+"/order/"+o.ID)
	writeJSON(w, status, out)
	return nil
}

// refreshOrder applies expiry and authorization state to a pending/ready order.
func (s *Server) refreshOrder(ctx context.Context, o *store.Order) error {
	now := s.Store.Now()
	if o.Status != "pending" && o.Status != "ready" {
		return nil
	}
	if now.After(o.ExpiresAt) {
		o.Status, o.Error = "invalid", malformed("order expired").json()
		return s.Store.UpdateOrder(ctx, o)
	}
	if o.Status == "ready" {
		return nil
	}
	authzs, err := s.Store.AuthzsForOrder(ctx, o.ID)
	if err != nil {
		return err
	}
	all := true
	for _, a := range authzs {
		if a.Status == "pending" && now.After(a.ExpiresAt) {
			a.Status = "expired"
			_ = s.Store.UpdateAuthzStatus(ctx, a.ID, a.Status)
		}
		switch a.Status {
		case "valid":
		case "pending":
			all = false
		default:
			o.Status = "invalid"
			if o.Error == "" {
				o.Error = unauthorized("authorization for %s is %s", a.IDValue, a.Status).json()
			}
			return s.Store.UpdateOrder(ctx, o)
		}
	}
	if all {
		if ok, err := s.Store.TransitionOrder(ctx, o.ID, "pending", "ready"); err != nil {
			return err
		} else if ok {
			o.Status = "ready"
		}
	}
	return nil
}

func (s *Server) ownedOrder(ctx context.Context, req *request, id string) (*store.Order, *Problem) {
	o, err := s.Store.GetOrder(ctx, id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && (o.AccountID != req.account.ID || o.IssuerSlug != req.slug)) {
		return nil, notFoundP("order not found")
	}
	if err != nil {
		return nil, serverErr("%v", err)
	}
	if err := s.refreshOrder(ctx, o); err != nil {
		return nil, serverErr("%v", err)
	}
	return o, nil
}

func (s *Server) order(w http.ResponseWriter, r *http.Request, slug string) *Problem {
	req, p := s.verify(w, r, slug, needKID)
	if p != nil {
		return p
	}
	o, p := s.ownedOrder(r.Context(), req, r.PathValue("id"))
	if p != nil {
		return p
	}
	if o.Status == "processing" {
		w.Header().Set("Retry-After", "1")
	}
	return s.writeOrder(w, r.Context(), o, http.StatusOK)
}

func (s *Server) ownedAuthz(ctx context.Context, req *request, id string) (*store.Authz, *Problem) {
	a, err := s.Store.GetAuthz(ctx, id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && a.AccountID != req.account.ID) {
		return nil, notFoundP("authorization not found")
	}
	if err != nil {
		return nil, serverErr("%v", err)
	}
	if a.Status == "pending" && s.Store.Now().After(a.ExpiresAt) {
		a.Status = "expired"
		_ = s.Store.UpdateAuthzStatus(ctx, a.ID, a.Status)
	}
	return a, nil
}

func (s *Server) authz(w http.ResponseWriter, r *http.Request, slug string) *Problem {
	req, p := s.verify(w, r, slug, needKID)
	if p != nil {
		return p
	}
	ctx := r.Context()
	a, p := s.ownedAuthz(ctx, req, r.PathValue("id"))
	if p != nil {
		return p
	}
	if !req.postAsGet() {
		var in struct {
			Status string `json:"status"`
		}
		if p := req.decode(&in); p != nil {
			return p
		}
		if in.Status != "deactivated" {
			return malformed("only status \"deactivated\" may be set")
		}
		if a.Status != "pending" && a.Status != "valid" {
			return malformed("authorization is %s", a.Status)
		}
		a.Status = "deactivated"
		if err := s.Store.UpdateAuthzStatus(ctx, a.ID, a.Status); err != nil {
			return serverErr("%v", err)
		}
	}
	return s.writeAuthz(w, ctx, slug, a)
}

func (s *Server) chalJSON(slug string, c *store.Challenge) chalJSON {
	return chalJSON{Type: c.Type, URL: s.base(slug) + "/chall/" + c.ID, Status: c.Status, Token: c.Token,
		Validated: rfc3339(c.ValidatedAt), Error: parseProblem(c.Error)}
}

func (s *Server) writeAuthz(w http.ResponseWriter, ctx context.Context, slug string, a *store.Authz) *Problem {
	chals, err := s.Store.ChallengesForAuthz(ctx, a.ID)
	if err != nil {
		return serverErr("%v", err)
	}
	out := authzJSON{Identifier: ident{Type: a.IDType, Value: a.IDValue}, Status: a.Status, Expires: rfc3339(a.ExpiresAt), Wildcard: a.Wildcard, Challenges: []chalJSON{}}
	for _, c := range chals {
		// Once validated, only the successful challenge is listed (RFC 8555 §7.1.4).
		if a.Status == "valid" && c.Status != "valid" {
			continue
		}
		out.Challenges = append(out.Challenges, s.chalJSON(slug, c))
	}
	writeJSON(w, 200, out)
	return nil
}

func (s *Server) challenge(w http.ResponseWriter, r *http.Request, slug string) *Problem {
	req, p := s.verify(w, r, slug, needKID)
	if p != nil {
		return p
	}
	ctx := r.Context()
	c, err := s.Store.GetChallenge(ctx, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		return notFoundP("challenge not found")
	} else if err != nil {
		return serverErr("%v", err)
	}
	a, p := s.ownedAuthz(ctx, req, c.AuthzID)
	if p != nil {
		return p
	}
	if !req.postAsGet() && c.Status == "pending" {
		if a.Status != "pending" {
			return malformed("authorization is %s", a.Status)
		}
		ok, err := s.Store.TransitionChallenge(ctx, c.ID, "pending", "processing")
		if err != nil {
			return serverErr("%v", err)
		}
		if ok {
			c.Status = "processing"
			s.enqueue(c.ID)
		}
	}
	w.Header().Add("Link", `<`+s.base(slug)+"/authz/"+a.ID+`>;rel="up"`)
	if c.Status == "processing" {
		w.Header().Set("Retry-After", "2")
	}
	writeJSON(w, 200, s.chalJSON(slug, c))
	return nil
}

func (s *Server) finalize(w http.ResponseWriter, r *http.Request, slug string) *Problem {
	req, p := s.verify(w, r, slug, needKID)
	if p != nil {
		return p
	}
	var in struct {
		CSR string `json:"csr"`
	}
	if p := req.decode(&in); p != nil {
		return p
	}
	ctx := r.Context()
	o, p := s.ownedOrder(ctx, req, r.PathValue("id"))
	if p != nil {
		return p
	}
	if o.Status != "ready" {
		return prob(403, "orderNotReady", "order is %s", o.Status)
	}
	der, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(in.CSR, "="))
	if err != nil {
		return prob(400, "badCSR", "csr is not base64url")
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return prob(400, "badCSR", "cannot parse CSR: %v", err)
	}
	ireq, err := ca.FromCSR(csr)
	if err != nil {
		return prob(400, "badCSR", "%v", err)
	}
	if p := matchCSR(o.Identifiers, csr); p != nil {
		return p
	}
	pol, err := policy.Load(ctx, s.Store, slug)
	if err != nil {
		return serverErr("%v", err)
	}
	if err := pol.CheckKey(csr.PublicKey); err != nil {
		return prob(400, "badCSR", "%v", err)
	}
	if tp, err := thumbprint(&jose.JSONWebKey{Key: csr.PublicKey}); err == nil && tp == req.account.JWKThumbprint {
		return prob(400, "badCSR", "certificate key must differ from the account key")
	}
	if ok, err := s.Store.TransitionOrder(ctx, o.ID, "ready", "processing"); err != nil {
		return serverErr("%v", err)
	} else if !ok {
		return prob(403, "orderNotReady", "order is being finalized")
	}

	start := o.NotBefore
	if start.IsZero() {
		start = s.Store.Now()
	}
	var requested time.Duration
	if !o.NotAfter.IsZero() {
		requested = o.NotAfter.Sub(start)
	}
	ireq.NotBefore = o.NotBefore
	ireq.Validity = pol.Validity(requested)
	ireq.ClientAuth = pol.ClientAuth
	ireq.Source, ireq.AccountID, ireq.OrderID = "acme", o.AccountID, o.ID
	cert, err := s.CA.Issue(ctx, slug, ireq)
	if err != nil {
		if errors.Is(err, ca.ErrLocked) {
			_, _ = s.Store.TransitionOrder(ctx, o.ID, "processing", "ready")
			w.Header().Set("Retry-After", "300")
			return prob(503, "serverInternal", "the CA is locked; an administrator must unlock it")
		}
		o.Status, o.Error = "invalid", prob(400, "badCSR", "issuance failed: %v", err).json()
		_ = s.Store.UpdateOrder(ctx, o)
		s.emit(ctx, Event{Type: "order.invalid", IssuerSlug: slug, AccountID: o.AccountID, Target: o.ID, Detail: map[string]any{"error": err.Error()}})
		return prob(400, "badCSR", "issuance failed: %v", err)
	}
	o.Status, o.CertificateID = "valid", cert.ID
	if err := s.Store.UpdateOrder(ctx, o); err != nil {
		return serverErr("%v", err)
	}
	s.emit(ctx, Event{Type: "cert.issued", IssuerSlug: slug, AccountID: o.AccountID, Target: cert.ID,
		Detail: map[string]any{"serial": cert.Serial, "sans": cert.SANs, "notAfter": cert.NotAfter, "replaces": o.Replaces}})
	return s.writeOrder(w, ctx, o, http.StatusOK)
}

// matchCSR requires the CSR names to equal the order identifiers exactly.
func matchCSR(ids []ident, csr *x509.CertificateRequest) *Problem {
	want := map[string]bool{}
	for _, id := range ids {
		want[id.Type+":"+id.Value] = true
	}
	got := map[string]bool{}
	for _, n := range csr.DNSNames {
		got["dns:"+strings.ToLower(strings.TrimSuffix(n, "."))] = true
	}
	for _, ip := range csr.IPAddresses {
		got["ip:"+ip.String()] = true
	}
	if cn := csr.Subject.CommonName; cn != "" {
		if ip := net.ParseIP(cn); ip != nil {
			got["ip:"+ip.String()] = true
		} else {
			got["dns:"+strings.ToLower(cn)] = true
		}
	}
	if len(got) != len(want) {
		return prob(400, "badCSR", "CSR identifiers %v do not match the order %v", keys(got), keys(want))
	}
	for k := range got {
		if !want[k] {
			return prob(400, "badCSR", "CSR identifiers %v do not match the order %v", keys(got), keys(want))
		}
	}
	return nil
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (s *Server) certificate(w http.ResponseWriter, r *http.Request, slug string) *Problem {
	req, p := s.verify(w, r, slug, needKID)
	if p != nil {
		return p
	}
	c, err := s.Store.GetCertificate(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) || (err == nil && (c.AccountID != req.account.ID || c.IssuerSlug != slug)) {
		return notFoundP("certificate not found")
	} else if err != nil {
		return serverErr("%v", err)
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(200)
	// ChainPEM is already the full chain: leaf first, then the issuers.
	fmt.Fprint(w, strings.TrimSpace(c.ChainPEM)+"\n")
	return nil
}
