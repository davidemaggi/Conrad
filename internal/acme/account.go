package acme

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"strings"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/davidemaggi/conrad/internal/policy"
	"github.com/davidemaggi/conrad/internal/store"
)

type accountJSON struct {
	Status                 string          `json:"status"`
	Contact                []string        `json:"contact"`
	Orders                 string          `json:"orders"`
	ExternalAccountBinding json.RawMessage `json:"externalAccountBinding,omitempty"`
}

func (s *Server) accountURL(a *store.Account) string {
	return s.base(a.IssuerSlug) + "/account/" + a.ID
}

func (s *Server) writeAccount(w http.ResponseWriter, a *store.Account, status int) {
	w.Header().Set("Location", s.accountURL(a))
	writeJSON(w, status, accountJSON{Status: a.Status, Contact: nonNil(a.Contacts), Orders: s.accountURL(a) + "/orders"})
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func validateContacts(cs []string) *Problem {
	if len(cs) > 10 {
		return prob(400, "invalidContact", "too many contacts")
	}
	for _, c := range cs {
		if !strings.HasPrefix(c, "mailto:") {
			return prob(400, "unsupportedContact", "only mailto: contacts are supported")
		}
		addr := strings.TrimPrefix(c, "mailto:")
		if strings.ContainsAny(addr, ",?") {
			return prob(400, "invalidContact", "invalid contact %q", c)
		}
		if _, err := mail.ParseAddress(addr); err != nil {
			return prob(400, "invalidContact", "invalid contact %q", c)
		}
	}
	return nil
}

func (s *Server) newAccount(w http.ResponseWriter, r *http.Request, slug string) *Problem {
	req, p := s.verify(w, r, slug, needJWK)
	if p != nil {
		return p
	}
	var in struct {
		Contact                []string        `json:"contact"`
		TermsOfServiceAgreed   bool            `json:"termsOfServiceAgreed"`
		OnlyReturnExisting     bool            `json:"onlyReturnExisting"`
		ExternalAccountBinding json.RawMessage `json:"externalAccountBinding"`
	}
	if p := req.decode(&in); p != nil {
		return p
	}
	thumb, err := thumbprint(req.jwk)
	if err != nil {
		return prob(400, "badPublicKey", "%v", err)
	}
	ctx := r.Context()
	if existing, err := s.Store.AccountByThumbprint(ctx, slug, thumb); err == nil {
		s.writeAccount(w, existing, http.StatusOK)
		return nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return serverErr("%v", err)
	}
	if in.OnlyReturnExisting {
		return prob(400, "accountDoesNotExist", "no account exists for this key")
	}
	if p := validateContacts(in.Contact); p != nil {
		return p
	}
	pol, err := policy.Load(ctx, s.Store, slug)
	if err != nil {
		return serverErr("%v", err)
	}
	if !s.limiter.allow(slug+"|"+clientIP(r), pol.RateLimits.NewAccountsPerIPPerHour, s.Store.Now()) {
		return prob(429, "rateLimited", "too many new accounts from this IP; try again later")
	}
	acct := &store.Account{IssuerSlug: slug, JWKThumbprint: thumb, Contacts: in.Contact, Status: "valid"}
	if len(in.ExternalAccountBinding) > 0 && string(in.ExternalAccountBinding) != "null" {
		kid, p := s.verifyEAB(ctx, slug, req.url, in.ExternalAccountBinding, req.jwk)
		if p != nil {
			return p
		}
		acct.EABKeyID = kid
	} else if pol.RequireEAB {
		return prob(400, "externalAccountRequired", "this directory requires external account binding")
	}
	pub := req.jwk.Public()
	jwkJSON, err := pub.MarshalJSON()
	if err != nil {
		return serverErr("%v", err)
	}
	acct.JWKJSON = string(jwkJSON)
	if err := s.Store.InsertAccount(ctx, acct); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return unauthorized("external account key already used")
		}
		return serverErr("%v", err)
	}
	s.emit(ctx, Event{Type: "account.created", IssuerSlug: slug, AccountID: acct.ID, Target: acct.ID,
		Detail: map[string]any{"contacts": acct.Contacts, "eab": acct.EABKeyID, "ip": clientIP(r)}})
	s.writeAccount(w, acct, http.StatusCreated)
	return nil
}

func (s *Server) account(w http.ResponseWriter, r *http.Request, slug string) *Problem {
	req, p := s.verify(w, r, slug, needKID)
	if p != nil {
		return p
	}
	acct := req.account
	if acct.ID != r.PathValue("id") {
		return unauthorized("account URL does not match kid")
	}
	if !req.postAsGet() {
		var in struct {
			Status  string    `json:"status"`
			Contact *[]string `json:"contact"`
		}
		if p := req.decode(&in); p != nil {
			return p
		}
		if in.Contact != nil {
			if p := validateContacts(*in.Contact); p != nil {
				return p
			}
			acct.Contacts = *in.Contact
		}
		switch in.Status {
		case "", "valid":
		case "deactivated":
			acct.Status = "deactivated"
		default:
			return malformed("invalid status %q", in.Status)
		}
		if err := s.Store.UpdateAccount(r.Context(), acct); err != nil {
			return serverErr("%v", err)
		}
		if acct.Status == "deactivated" {
			s.emit(r.Context(), Event{Type: "account.deactivated", IssuerSlug: slug, AccountID: acct.ID, Target: acct.ID})
		}
	}
	s.writeAccount(w, acct, http.StatusOK)
	return nil
}

func (s *Server) accountOrders(w http.ResponseWriter, r *http.Request, slug string) *Problem {
	req, p := s.verify(w, r, slug, needKID)
	if p != nil {
		return p
	}
	if req.account.ID != r.PathValue("id") {
		return unauthorized("account URL does not match kid")
	}
	ids, err := s.Store.ListOrderIDs(r.Context(), req.account.ID)
	if err != nil {
		return serverErr("%v", err)
	}
	urls := make([]string, 0, len(ids))
	for _, id := range ids {
		urls = append(urls, s.base(slug)+"/order/"+id)
	}
	writeJSON(w, 200, map[string]any{"orders": urls})
	return nil
}

// keyChange implements RFC 8555 §7.3.5.
func (s *Server) keyChange(w http.ResponseWriter, r *http.Request, slug string) *Problem {
	req, p := s.verify(w, r, slug, needKID)
	if p != nil {
		return p
	}
	inner, err := jose.ParseSigned(string(req.payload), signatureAlgs)
	if err != nil || len(inner.Signatures) != 1 {
		return malformed("invalid inner JWS")
	}
	h := inner.Signatures[0].Protected
	if h.JSONWebKey == nil || h.KeyID != "" || !h.JSONWebKey.IsPublic() || !h.JSONWebKey.Valid() {
		return malformed("inner JWS must contain a public jwk")
	}
	if u, _ := h.ExtraHeaders["url"].(string); u != req.url {
		return malformed("inner JWS url mismatch")
	}
	if h.Nonce != "" {
		return malformed("inner JWS must not contain a nonce")
	}
	payload, err := inner.Verify(h.JSONWebKey)
	if err != nil {
		return malformed("inner JWS signature invalid")
	}
	var in struct {
		Account string          `json:"account"`
		OldKey  json.RawMessage `json:"oldKey"`
	}
	if err := json.Unmarshal(payload, &in); err != nil {
		return malformed("invalid inner payload")
	}
	acct := req.account
	if in.Account != s.accountURL(acct) {
		return unauthorized("account mismatch")
	}
	var old jose.JSONWebKey
	if err := old.UnmarshalJSON(in.OldKey); err != nil {
		return malformed("invalid oldKey")
	}
	if tp, _ := thumbprint(&old); tp != acct.JWKThumbprint {
		return unauthorized("oldKey does not match the account key")
	}
	newThumb, err := thumbprint(h.JSONWebKey)
	if err != nil {
		return prob(400, "badPublicKey", "%v", err)
	}
	if other, err := s.Store.AccountByThumbprint(r.Context(), slug, newThumb); err == nil {
		w.Header().Set("Location", s.accountURL(other))
		return prob(409, "conflict", "new key is already in use by another account")
	}
	pub := h.JSONWebKey.Public()
	jwkJSON, _ := pub.MarshalJSON()
	acct.JWKThumbprint, acct.JWKJSON = newThumb, string(jwkJSON)
	if err := s.Store.UpdateAccount(r.Context(), acct); err != nil {
		return serverErr("%v", err)
	}
	s.emit(r.Context(), Event{Type: "account.keychange", IssuerSlug: slug, AccountID: acct.ID, Target: acct.ID})
	s.writeAccount(w, acct, http.StatusOK)
	return nil
}
