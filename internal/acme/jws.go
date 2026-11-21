package acme

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/davidemaggi/conrad/internal/store"
)

var signatureAlgs = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512, jose.EdDSA,
}

var macAlgs = []jose.SignatureAlgorithm{jose.HS256, jose.HS384, jose.HS512}

// request is a verified ACME POST.
type request struct {
	slug    string
	url     string
	payload []byte
	jwk     *jose.JSONWebKey // set when signed with an embedded key
	account *store.Account   // set when signed with a kid
}

func (r *request) postAsGet() bool { return len(r.payload) == 0 }

func (r *request) decode(v any) *Problem {
	if r.postAsGet() {
		return malformed("payload required")
	}
	if err := json.Unmarshal(r.payload, v); err != nil {
		return malformed("invalid JSON payload: %v", err)
	}
	return nil
}

func thumbprint(k *jose.JSONWebKey) (string, error) {
	tp, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

// keyMode says which key reference a resource accepts.
type keyMode int

const (
	needKID keyMode = iota
	needJWK
	anyKey
)

// verify parses and authenticates a JWS POST to slug.
func (s *Server) verify(w http.ResponseWriter, r *http.Request, slug string, mode keyMode) (*request, *Problem) {
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct != "application/jose+json" {
		return nil, prob(http.StatusUnsupportedMediaType, "malformed", "Content-Type must be application/jose+json")
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		return nil, malformed("cannot read body: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(body)), "{") {
		return nil, malformed("JWS must use the flattened JSON serialization")
	}
	jws, err := jose.ParseSigned(string(body), signatureAlgs)
	if err != nil {
		return nil, prob(400, "badSignatureAlgorithm", "invalid JWS: %v", err)
	}
	if len(jws.Signatures) != 1 {
		return nil, malformed("JWS must have exactly one signature")
	}
	h := jws.Signatures[0].Protected
	u, _ := h.ExtraHeaders["url"].(string)
	want := s.BaseURL + r.URL.Path
	if u != want {
		return nil, unauthorized("JWS url %q does not match request URL %q", u, want)
	}
	if h.Nonce == "" {
		return nil, prob(400, "badNonce", "missing nonce")
	}
	ok, err := s.Store.ConsumeNonce(r.Context(), h.Nonce)
	if err != nil {
		return nil, serverErr("nonce store: %v", err)
	}
	if !ok {
		return nil, prob(400, "badNonce", "invalid or expired nonce")
	}

	req := &request{slug: slug, url: u}
	var key *jose.JSONWebKey
	switch {
	case h.JSONWebKey != nil && h.KeyID != "":
		return nil, malformed("JWS must not contain both jwk and kid")
	case h.JSONWebKey != nil:
		if mode == needKID {
			return nil, malformed("this resource requires a kid")
		}
		if !h.JSONWebKey.Valid() || !h.JSONWebKey.IsPublic() {
			return nil, prob(400, "badPublicKey", "jwk must be a valid public key")
		}
		key = h.JSONWebKey
		req.jwk = key
	case h.KeyID != "":
		if mode == needJWK {
			return nil, malformed("this resource requires a jwk")
		}
		acct, p := s.accountFromKID(r.Context(), slug, h.KeyID)
		if p != nil {
			return nil, p
		}
		key = &jose.JSONWebKey{}
		if err := key.UnmarshalJSON([]byte(acct.JWKJSON)); err != nil {
			return nil, serverErr("stored account key: %v", err)
		}
		req.account = acct
	default:
		return nil, malformed("JWS needs a jwk or kid")
	}
	payload, err := jws.Verify(key)
	if err != nil {
		return nil, malformed("JWS signature verification failed")
	}
	req.payload = payload
	return req, nil
}

func (s *Server) accountFromKID(ctx context.Context, slug, kid string) (*store.Account, *Problem) {
	prefix := s.base(slug) + "/account/"
	if !strings.HasPrefix(kid, prefix) {
		return nil, prob(400, "accountDoesNotExist", "kid %q does not belong to this directory", kid)
	}
	acct, err := s.Store.GetAccount(ctx, strings.TrimPrefix(kid, prefix))
	if errors.Is(err, store.ErrNotFound) || (err == nil && acct.IssuerSlug != slug) {
		return nil, prob(400, "accountDoesNotExist", "account does not exist")
	}
	if err != nil {
		return nil, serverErr("%v", err)
	}
	if acct.Status != "valid" {
		return nil, unauthorized("account is %s", acct.Status)
	}
	return acct, nil
}

// verifyEAB checks an externalAccountBinding JWS against the outer account key.
func (s *Server) verifyEAB(ctx context.Context, slug, url string, raw json.RawMessage, outer *jose.JSONWebKey) (string, *Problem) {
	eab, err := jose.ParseSigned(string(raw), macAlgs)
	if err != nil || len(eab.Signatures) != 1 {
		return "", malformed("invalid externalAccountBinding")
	}
	h := eab.Signatures[0].Protected
	if u, _ := h.ExtraHeaders["url"].(string); u != url {
		return "", unauthorized("externalAccountBinding url mismatch")
	}
	if h.Nonce != "" {
		return "", malformed("externalAccountBinding must not contain a nonce")
	}
	key, err := s.Store.GetEABKey(ctx, h.KeyID)
	if err != nil || key.IssuerSlug != slug || !key.RevokedAt.IsZero() || key.BoundAccountID != "" {
		return "", unauthorized("external account key is unknown, revoked or already used")
	}
	payload, err := eab.Verify(key.HMACKey)
	if err != nil {
		return "", unauthorized("externalAccountBinding signature invalid")
	}
	var inner jose.JSONWebKey
	if err := inner.UnmarshalJSON(payload); err != nil {
		return "", malformed("externalAccountBinding payload must be a JWK")
	}
	a, _ := thumbprint(&inner)
	b, _ := thumbprint(outer)
	if a == "" || a != b {
		return "", unauthorized("externalAccountBinding key does not match the account key")
	}
	return key.ID, nil
}
