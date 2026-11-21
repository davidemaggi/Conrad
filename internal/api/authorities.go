package api

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/davidemaggi/conrad/internal/ca"
	"github.com/davidemaggi/conrad/internal/crypto/signer"
	"github.com/davidemaggi/conrad/internal/policy"
	"github.com/davidemaggi/conrad/internal/store"
)

// authorityView is the JSON shape of a root or issuer.
type authorityView struct {
	ID              string    `json:"id"`
	Slug            string    `json:"slug,omitempty"`
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	Kind            string    `json:"kind"`
	ParentID        string    `json:"parentId,omitempty"`
	Status          string    `json:"status"`
	IsDefault       bool      `json:"isDefault"`
	Subject         string    `json:"subject"`
	Algorithm       string    `json:"algorithm"`
	Serial          string    `json:"serial"`
	Fingerprint     string    `json:"fingerprintSha256"`
	NotBefore       time.Time `json:"notBefore"`
	NotAfter        time.Time `json:"notAfter"`
	RevokedAt       time.Time `json:"revokedAt"`
	CreatedAt       time.Time `json:"createdAt"`
	NameConstraints []string  `json:"nameConstraints,omitempty"`
	CertPEM         string    `json:"certPem"`
	DirectoryURL    string    `json:"directoryUrl,omitempty"`
	DownloadURL     string    `json:"downloadUrl"`
	CRLURL          string    `json:"crlUrl,omitempty"`
	CRLUpdatedAt    time.Time `json:"crlUpdatedAt"`
	ActiveCerts     int       `json:"activeCertificates"`
}

func keyAlgorithm(pub any) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return "ecdsa-p" + strings.TrimPrefix(k.Curve.Params().Name, "P-")
	case *rsa.PublicKey:
		return fmt.Sprintf("rsa-%d", k.N.BitLen())
	case ed25519.PublicKey:
		return "ed25519"
	}
	return "unknown"
}

func (a *API) view(x *store.Authority, counts map[string]int) authorityView {
	v := authorityView{
		ID: x.ID, Slug: x.Slug, Name: x.Name, Description: x.Description, Kind: x.Kind, ParentID: x.ParentID,
		Status: x.Status, IsDefault: x.IsDefault, Serial: x.Serial, NotBefore: x.NotBefore, NotAfter: x.NotAfter,
		RevokedAt: x.RevokedAt, CreatedAt: x.CreatedAt, CertPEM: x.CertPEM, CRLUpdatedAt: x.CRLUpdatedAt,
		ActiveCerts: counts[x.ID],
	}
	if cs, err := ca.ParseCertificatesPEM([]byte(x.CertPEM)); err == nil && len(cs) > 0 {
		c := cs[0]
		v.Subject = c.Subject.String()
		v.Algorithm = keyAlgorithm(c.PublicKey)
		v.Fingerprint = ca.Fingerprint(c.Raw)
		v.NameConstraints = c.PermittedDNSDomains
	}
	base := strings.TrimRight(a.BaseURL, "/")
	if x.Kind == "root" {
		v.DownloadURL = base + "/roots/" + x.ID + ".crt"
	} else {
		v.DownloadURL = base + "/issuers/" + x.ID + ".crt"
		v.CRLURL = base + "/crl/" + x.ID + ".crl"
		if x.Status == "active" {
			v.DirectoryURL = base + "/acme/" + x.Slug + "/directory"
		}
	}
	return v
}

func (a *API) listAuthorities(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	list, err := a.CA.Authorities(ctx)
	if err != nil {
		a.failErr(w, err)
		return
	}
	counts, _ := a.Store.CountByIssuer(ctx)
	out := make([]authorityView, 0, len(list))
	for _, x := range list {
		out = append(out, a.view(x, counts))
	}
	writeJSON(w, 200, map[string]any{"items": out})
}

func (a *API) authority(w http.ResponseWriter, r *http.Request) (*store.Authority, bool) {
	x, err := a.Store.GetAuthority(r.Context(), r.PathValue("id"))
	if err != nil {
		a.failErr(w, err)
		return nil, false
	}
	return x, true
}

func (a *API) issuerOnly(w http.ResponseWriter, r *http.Request) (*store.Authority, bool) {
	x, ok := a.authority(w, r)
	if ok && x.Kind == "root" {
		fail(w, http.StatusBadRequest, "issuer.is_root", "this operation applies to issuers only")
		return nil, false
	}
	return x, ok
}

func (a *API) getAuthority(w http.ResponseWriter, r *http.Request) {
	x, ok := a.authority(w, r)
	if !ok {
		return
	}
	counts, _ := a.Store.CountByIssuer(r.Context())
	writeJSON(w, 200, a.view(x, counts))
}

func (a *API) createIssuer(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Slug            string     `json:"slug"`
		Name            string     `json:"name"`
		Description     string     `json:"description"`
		Subject         ca.Subject `json:"subject"`
		Algorithm       string     `json:"algorithm"`
		ValidityYears   int        `json:"validityYears"`
		NameConstraints []string   `json:"nameConstraints"`
		Default         bool       `json:"default"`
		ClonePolicyFrom string     `json:"clonePolicyFrom"`
	}
	if !decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	iss, err := a.CA.CreateIssuer(ctx, ca.IssuerRequest{
		Slug: in.Slug, Name: in.Name, Description: in.Description, Subject: in.Subject,
		Algorithm: signer.Algorithm(in.Algorithm), Validity: years(in.ValidityYears),
		NameConstraints: in.NameConstraints, Default: in.Default,
	})
	if err != nil {
		a.failCA(w, err)
		return
	}
	if in.ClonePolicyFrom != "" {
		if p, err := policy.Load(ctx, a.Store, in.ClonePolicyFrom); err == nil {
			_ = policy.Save(ctx, a.Store, iss.Slug, p)
		}
	}
	a.audit(r, "issuer.created", iss.ID, map[string]any{"slug": iss.Slug})
	writeJSON(w, http.StatusCreated, a.view(iss, nil))
}

// failCA maps known errors and reports other CA failures (bad input) as 400.
func (a *API) failCA(w http.ResponseWriter, err error) {
	if errors.Is(err, ca.ErrNameNotPermitted) {
		fail(w, http.StatusBadRequest, "cert.name_not_permitted", err.Error())
		return
	}
	for _, known := range []error{ca.ErrLocked, ca.ErrNotInitialized, ca.ErrIssuerNotFound, ca.ErrIssuerInactive,
		ca.ErrSlugTaken, ca.ErrInvalidSlug, ca.ErrCannotRevokeDef, store.ErrNotFound} {
		if errors.Is(err, known) {
			a.failErr(w, err)
			return
		}
	}
	fail(w, http.StatusBadRequest, "ca.failed", err.Error())
}

func (a *API) successorRoot(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ValidityYears int `json:"validityYears"`
	}
	if !decode(w, r, &in) {
		return
	}
	root, err := a.CA.SuccessorRoot(r.Context(), years(in.ValidityYears))
	if err != nil {
		a.failCA(w, err)
		return
	}
	a.audit(r, "root.successor_created", root.ID, nil)
	writeJSON(w, http.StatusCreated, a.view(root, nil))
}

func (a *API) updateAuthority(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if !decode(w, r, &in) {
		return
	}
	x, err := a.CA.UpdateIssuerInfo(r.Context(), r.PathValue("id"), in.Name, in.Description)
	if err != nil {
		a.failCA(w, err)
		return
	}
	a.audit(r, "authority.updated", x.ID, map[string]any{"name": in.Name})
	writeJSON(w, 200, a.view(x, nil))
}

func (a *API) setDefault(w http.ResponseWriter, r *http.Request) {
	x, ok := a.issuerOnly(w, r)
	if !ok {
		return
	}
	if err := a.CA.SetDefault(r.Context(), x.Slug); err != nil {
		a.failCA(w, err)
		return
	}
	a.audit(r, "issuer.default_changed", x.ID, map[string]any{"slug": x.Slug})
	a.caReady(r.Context()) // the server TLS certificate follows the default issuer
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) rotateIssuer(w http.ResponseWriter, r *http.Request) {
	x, ok := a.issuerOnly(w, r)
	if !ok {
		return
	}
	n, err := a.CA.RotateIssuer(r.Context(), x.Slug)
	if err != nil {
		a.failCA(w, err)
		return
	}
	a.audit(r, "issuer.rotated", n.ID, map[string]any{"slug": x.Slug, "previous": x.ID})
	writeJSON(w, http.StatusCreated, a.view(n, nil))
}

func (a *API) revokeIssuer(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Confirm string `json:"confirm"`
	}
	if !decode(w, r, &in) {
		return
	}
	x, ok := a.issuerOnly(w, r)
	if !ok {
		return
	}
	if in.Confirm != x.Slug {
		fail(w, http.StatusBadRequest, "issuer.confirm_mismatch", "type the issuer slug to confirm")
		return
	}
	if err := a.CA.RevokeIssuer(r.Context(), x.ID); err != nil {
		a.failCA(w, err)
		return
	}
	a.audit(r, "issuer.revoked", x.ID, map[string]any{"slug": x.Slug})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) getPolicy(w http.ResponseWriter, r *http.Request) {
	x, ok := a.issuerOnly(w, r)
	if !ok {
		return
	}
	p, err := policy.Load(r.Context(), a.Store, x.Slug)
	if err != nil {
		a.failErr(w, err)
		return
	}
	writeJSON(w, 200, p)
}

func (a *API) putPolicy(w http.ResponseWriter, r *http.Request) {
	x, ok := a.issuerOnly(w, r)
	if !ok {
		return
	}
	var p policy.Policy
	if !decode(w, r, &p) {
		return
	}
	if err := policy.Save(r.Context(), a.Store, x.Slug, p); err != nil {
		fail(w, http.StatusBadRequest, "policy.invalid", err.Error())
		return
	}
	a.audit(r, "policy.updated", x.Slug, nil)
	writeJSON(w, 200, p)
}

func (a *API) listEAB(w http.ResponseWriter, r *http.Request) {
	x, ok := a.issuerOnly(w, r)
	if !ok {
		return
	}
	keys, err := a.Store.ListEABKeys(r.Context(), x.Slug)
	if err != nil {
		a.failErr(w, err)
		return
	}
	if keys == nil {
		keys = []*store.EABKey{}
	}
	writeJSON(w, 200, map[string]any{"items": keys})
}

func (a *API) createEAB(w http.ResponseWriter, r *http.Request) {
	x, ok := a.issuerOnly(w, r)
	if !ok {
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Name) == "" {
		fail(w, http.StatusBadRequest, "validation", "name is required")
		return
	}
	k, err := a.Store.CreateEABKey(r.Context(), x.Slug, strings.TrimSpace(in.Name))
	if err != nil {
		a.failErr(w, err)
		return
	}
	a.audit(r, "eab.created", k.ID, map[string]any{"issuer": x.Slug, "name": k.Name})
	dir := strings.TrimRight(a.BaseURL, "/") + "/acme/" + x.Slug + "/directory"
	// The HMAC is only ever returned here.
	writeJSON(w, http.StatusCreated, map[string]any{"key": k, "kid": k.ID, "hmac": k.EncodedHMAC(), "directoryUrl": dir})
}

func (a *API) revokeEAB(w http.ResponseWriter, r *http.Request) {
	x, ok := a.issuerOnly(w, r)
	if !ok {
		return
	}
	k, err := a.Store.GetEABKey(r.Context(), r.PathValue("kid"))
	if err != nil || k.IssuerSlug != x.Slug {
		fail(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	if err := a.Store.RevokeEABKey(r.Context(), k.ID); err != nil {
		a.failErr(w, err)
		return
	}
	a.audit(r, "eab.revoked", k.ID, map[string]any{"issuer": x.Slug})
	writeJSON(w, http.StatusNoContent, nil)
}
