package api

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/davidemaggi/conrad/internal/ca"
	"github.com/davidemaggi/conrad/internal/crypto/signer"
	"github.com/davidemaggi/conrad/internal/policy"
	"github.com/davidemaggi/conrad/internal/store"
)

func (a *API) listCertificates(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.CertFilter{
		Status: q.Get("status"), IssuerSlug: q.Get("issuer"), AccountID: q.Get("account"), Query: q.Get("q"),
		Within: time.Duration(intQuery(r, "withinDays", 30)) * 24 * time.Hour,
		Limit:  min(max(intQuery(r, "limit", 50), 1), 500), Offset: max(intQuery(r, "offset", 0), 0),
	}
	items, total, err := a.Store.ListCertificates(r.Context(), f)
	if err != nil {
		a.failErr(w, err)
		return
	}
	if items == nil {
		items = []*store.Certificate{}
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total})
}

func (a *API) getCertificate(w http.ResponseWriter, r *http.Request) {
	c, err := a.Store.GetCertificate(r.Context(), r.PathValue("id"))
	if err != nil {
		a.failErr(w, err)
		return
	}
	writeJSON(w, 200, c)
}

func (a *API) revokeCertificate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Reason int `json:"reason"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !ca.ValidReason(in.Reason) {
		fail(w, http.StatusBadRequest, "validation", "invalid revocation reason")
		return
	}
	id := r.PathValue("id")
	if err := a.CA.Revoke(r.Context(), id, in.Reason); err != nil {
		a.failCA(w, err)
		return
	}
	a.audit(r, "cert.revoked", id, map[string]any{"reason": in.Reason})
	writeJSON(w, 200, map[string]any{"ok": true})
}

type issueRequest struct {
	Issuer       string   `json:"issuer"`
	CSR          string   `json:"csr"`          // PEM; if empty the server generates the key
	Names        []string `json:"names"`        // DNS names and/or IPs (ignored with a CSR)
	KeyAlgorithm string   `json:"keyAlgorithm"` // for server-generated keys
	ValidityDays int      `json:"validityDays"`
	ClientAuth   bool     `json:"clientAuth"`
	PFXPassword  string   `json:"pfxPassword"` // optional: also return a PKCS#12 bundle
}

func (a *API) issueCertificate(w http.ResponseWriter, r *http.Request) {
	var in issueRequest
	if !decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	iss, err := a.CA.Issuer(ctx, in.Issuer)
	if err != nil {
		a.failErr(w, err)
		return
	}
	pol, err := policy.Load(ctx, a.Store, iss.Slug)
	if err != nil {
		a.failErr(w, err)
		return
	}
	var req ca.IssueRequest
	if strings.TrimSpace(in.CSR) != "" {
		blk, _ := pem.Decode([]byte(in.CSR))
		if blk == nil || blk.Type != "CERTIFICATE REQUEST" && blk.Type != "NEW CERTIFICATE REQUEST" {
			fail(w, http.StatusBadRequest, "cert.bad_csr", "csr must be a PEM CERTIFICATE REQUEST")
			return
		}
		csr, err := x509.ParseCertificateRequest(blk.Bytes)
		if err == nil {
			req, err = ca.FromCSR(csr)
		}
		if err != nil {
			fail(w, http.StatusBadRequest, "cert.bad_csr", err.Error())
			return
		}
	} else {
		for _, n := range in.Names {
			n = strings.ToLower(strings.TrimSpace(n))
			if n == "" {
				continue
			}
			if ip := net.ParseIP(n); ip != nil {
				req.IPs = append(req.IPs, ip)
			} else {
				req.DNSNames = append(req.DNSNames, n)
			}
		}
		if len(req.DNSNames)+len(req.IPs) == 0 {
			fail(w, http.StatusBadRequest, "validation", "at least one name is required")
			return
		}
	}
	req.Source = "manual"
	req.ClientAuth = in.ClientAuth || pol.ClientAuth
	req.Validity = pol.Validity(time.Duration(in.ValidityDays) * 24 * time.Hour)

	var (
		cert *store.Certificate
		key  any
	)
	if req.PublicKey != nil {
		cert, err = a.CA.Issue(ctx, iss.Slug, req)
	} else {
		var k any
		cert, k, err = issueWithKey(a.CA, ctx, iss.Slug, in.KeyAlgorithm, req)
		key = k
	}
	if err != nil {
		a.failCA(w, err)
		return
	}
	resp := map[string]any{"certificate": cert}
	if key != nil {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			a.failErr(w, err)
			return
		}
		resp["keyPem"] = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
		if in.PFXPassword != "" {
			pfx, err := a.pfx(cert, key, in.PFXPassword)
			if err != nil {
				a.failErr(w, err)
				return
			}
			resp["pfx"] = base64.StdEncoding.EncodeToString(pfx)
		}
	}
	c := cert
	a.audit(r, "cert.issued", c.ID, map[string]any{"issuer": iss.Slug, "sans": c.SANs, "source": "manual"})
	writeJSON(w, http.StatusCreated, resp)
}

func issueWithKey(s *ca.Service, ctx context.Context, slug, alg string, req ca.IssueRequest) (*store.Certificate, any, error) {
	c, k, err := s.IssueWithKey(ctx, slug, signer.Algorithm(alg), req)
	return c, k, err
}

func (a *API) pfx(c *store.Certificate, key any, password string) ([]byte, error) {
	leaf, err := ca.ParseCertificatesPEM([]byte(c.CertPEM))
	if err != nil {
		return nil, err
	}
	chain, _ := ca.ParseCertificatesPEM([]byte(c.ChainPEM))
	return pkcs12.Modern.Encode(key, leaf[0], chain, password)
}

func (a *API) listAccounts(w http.ResponseWriter, r *http.Request) {
	list, err := a.Store.ListAccounts(r.Context(), r.URL.Query().Get("issuer"))
	if err != nil {
		a.failErr(w, err)
		return
	}
	if list == nil {
		list = []*store.Account{}
	}
	writeJSON(w, 200, map[string]any{"items": list})
}

func (a *API) deactivateAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	acc, err := a.Store.GetAccount(ctx, r.PathValue("id"))
	if err != nil {
		a.failErr(w, err)
		return
	}
	acc.Status = "deactivated"
	if err := a.Store.UpdateAccount(ctx, acc); err != nil {
		a.failErr(w, err)
		return
	}
	a.audit(r, "account.deactivated", acc.ID, map[string]any{"issuer": acc.IssuerSlug})
	writeJSON(w, 200, acc)
}

func (a *API) dashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	window := time.Duration(intQuery(r, "withinDays", 30)) * 24 * time.Hour
	stats, err := a.Store.CertificateStats(ctx, window)
	if err != nil {
		a.failErr(w, err)
		return
	}
	accounts, _ := a.Store.CountAccounts(ctx)
	expiring, _, _ := a.Store.ListCertificates(ctx, store.CertFilter{Status: "expiring", Within: window, Limit: 10})
	if expiring == nil {
		expiring = []*store.Certificate{}
	}
	recent, _, _ := a.Store.ListAudit(ctx, "", 10, 0)
	if recent == nil {
		recent = []*store.AuditEntry{}
	}
	var issuers []authorityView
	if list, err := a.CA.Authorities(ctx); err == nil {
		counts, _ := a.Store.CountByIssuer(ctx)
		for _, x := range list {
			if x.Status == "active" {
				issuers = append(issuers, a.view(x, counts))
			}
		}
	}
	writeJSON(w, 200, map[string]any{
		"stats": stats, "accounts": accounts, "expiring": expiring, "recentActivity": recent,
		"authorities": issuers, "caLocked": a.CA.Locked(),
	})
}

func (a *API) listAudit(w http.ResponseWriter, r *http.Request) {
	items, total, err := a.Store.ListAudit(r.Context(), r.URL.Query().Get("action"),
		min(max(intQuery(r, "limit", 50), 1), 500), max(intQuery(r, "offset", 0), 0))
	if err != nil {
		a.failErr(w, err)
		return
	}
	if items == nil {
		items = []*store.AuditEntry{}
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total})
}

func (a *API) systemInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"version":     a.Version,
		"goVersion":   runtime.Version(),
		"os":          runtime.GOOS + "/" + runtime.GOARCH,
		"uptimeSec":   int(time.Since(a.started).Seconds()),
		"startedAt":   a.started,
		"baseUrl":     a.BaseURL,
		"dataDir":     a.DataDir,
		"keyProvider": a.CA.Provider().Name(),
		"caLocked":    a.CA.Locked(),
	})
}

func (a *API) backup(w http.ResponseWriter, r *http.Request) {
	dir, err := os.MkdirTemp("", "conrad-backup-")
	if err != nil {
		a.failErr(w, err)
		return
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "conrad.db")
	if err := a.Store.Backup(r.Context(), path); err != nil {
		a.failErr(w, err)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		a.failErr(w, err)
		return
	}
	defer f.Close()
	a.audit(r, "system.backup", "", nil)
	name := "conrad-" + time.Now().UTC().Format("20060102-150405") + ".db"
	w.Header().Set("Content-Type", "application/vnd.sqlite3")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, name, time.Time{}, f)
}
