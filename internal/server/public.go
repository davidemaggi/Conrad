package server

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/davidemaggi/conrad/internal/ca"
	"github.com/davidemaggi/conrad/internal/store"
)

// public registers unauthenticated PKI endpoints (served on both listeners).
func (s *Server) public(mux *http.ServeMux) {
	mux.HandleFunc("GET /roots/{file}", s.rootFile)
	mux.HandleFunc("GET /issuers/{file}", s.issuerFile)
	mux.HandleFunc("GET /crl/{file}", s.crlFile)
	mux.HandleFunc("POST /ocsp/{id}", s.ocsp)
	mux.HandleFunc("GET /ocsp/{id}/{req...}", s.ocsp)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.HandleFunc("GET /metrics", s.metrics)
}

func splitExt(file string) (id, ext string) {
	i := strings.LastIndex(file, ".")
	if i < 0 {
		return file, ""
	}
	return file[:i], file[i+1:]
}

// rootFile serves /roots/{id|current}.{crt|der|pem|mobileconfig} and /roots/{id}.cross.pem.
func (s *Server) rootFile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ext := splitExt(r.PathValue("file"))
	if strings.HasSuffix(id, ".cross") && ext == "pem" {
		p, err := s.CA.CrossCertificate(ctx, strings.TrimSuffix(id, ".cross"))
		if err != nil || p == "" {
			http.NotFound(w, r)
			return
		}
		sendFile(w, "application/x-pem-file", id+".pem", []byte(p))
		return
	}
	var a *store.Authority
	var err error
	if id == "current" || id == "root" {
		a, err = s.CA.Root(ctx)
	} else {
		a, err = s.Store.GetAuthority(ctx, id)
	}
	if err != nil || a.Kind != "root" {
		http.NotFound(w, r)
		return
	}
	s.certFile(w, r, a, ext, true)
}

func (s *Server) issuerFile(w http.ResponseWriter, r *http.Request) {
	id, ext := splitExt(r.PathValue("file"))
	a, err := s.Store.GetAuthority(r.Context(), id)
	if err != nil || a.Kind == "root" {
		http.NotFound(w, r)
		return
	}
	s.certFile(w, r, a, ext, false)
}

func (s *Server) certFile(w http.ResponseWriter, r *http.Request, a *store.Authority, ext string, root bool) {
	blk, _ := pem.Decode([]byte(a.CertPEM))
	if blk == nil {
		http.Error(w, "bad certificate", http.StatusInternalServerError)
		return
	}
	name := "conrad-" + a.ID
	if root {
		name = "conrad-root-ca"
	} else if a.Slug != "" {
		name = "conrad-" + a.Slug
	}
	switch ext {
	case "crt", "der", "cer":
		sendFile(w, "application/pkix-cert", name+"."+ext, blk.Bytes)
	case "pem":
		sendFile(w, "application/x-pem-file", name+".pem", []byte(a.CertPEM))
	case "mobileconfig":
		if !root {
			http.NotFound(w, r)
			return
		}
		b, err := ca.MobileConfig(a.Name, blk.Bytes)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sendFile(w, "application/x-apple-aspen-config", name+".mobileconfig", b)
	default:
		http.NotFound(w, r)
	}
}

func sendFile(w http.ResponseWriter, ctype, name string, b []byte) {
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(b)
}

func (s *Server) crlFile(w http.ResponseWriter, r *http.Request) {
	id, ext := splitExt(r.PathValue("file"))
	if ext != "crl" {
		http.NotFound(w, r)
		return
	}
	der, err := s.CA.CRL(r.Context(), id)
	if err != nil {
		if errorsIsNotFound(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "CRL unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Cache-Control", "public, max-age=600")
	_, _ = w.Write(der)
}

func (s *Server) ocsp(w http.ResponseWriter, r *http.Request) {
	var req []byte
	var err error
	if r.Method == http.MethodPost {
		req, err = io.ReadAll(http.MaxBytesReader(w, r.Body, 10<<10))
	} else {
		// RFC 6960 A.1: base64 (standard alphabet, URL-encoded) of the DER request.
		raw := r.PathValue("req")
		req, err = base64.StdEncoding.DecodeString(raw)
		if err != nil {
			req, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(raw, "="))
		}
	}
	if err != nil || len(req) == 0 {
		http.Error(w, "bad OCSP request", http.StatusBadRequest)
		return
	}
	resp, err := s.CA.OCSPRespond(r.Context(), r.PathValue("id"), req)
	if err != nil {
		if errorsIsNotFound(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "OCSP unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	if r.Method == http.MethodGet {
		w.Header().Set("Cache-Control", "public, max-age=300")
	}
	_, _ = w.Write(resp)
}

func errorsIsNotFound(err error) bool {
	return errors.Is(err, store.ErrNotFound) || errors.Is(err, ca.ErrIssuerNotFound)
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.Store.Ping(ctx); err != nil {
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	if init, _ := s.CA.Initialized(ctx); !init {
		http.Error(w, "CA not initialized", http.StatusServiceUnavailable)
		return
	}
	if s.CA.Locked() {
		http.Error(w, "CA locked", http.StatusServiceUnavailable)
		return
	}
	_, _ = io.WriteString(w, "ready\n")
}

// metrics writes Prometheus text exposition by hand (no client library).
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	gauge := func(name, help string) { fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name) }
	b2i := func(b bool) int {
		if b {
			return 1
		}
		return 0
	}
	gauge("conrad_build_info", "Build information.")
	fmt.Fprintf(w, "conrad_build_info{version=%q} 1\n", s.Version)
	gauge("conrad_ca_locked", "1 if the CA keys are locked.")
	fmt.Fprintf(w, "conrad_ca_locked %d\n", b2i(s.CA.Locked()))
	if st, err := s.Store.CertificateStats(ctx, 30*24*time.Hour); err == nil {
		gauge("conrad_certificates", "Certificates by state (expiring = within 30 days).")
		fmt.Fprintf(w, "conrad_certificates{state=\"active\"} %d\n", st.Active)
		fmt.Fprintf(w, "conrad_certificates{state=\"expiring\"} %d\n", st.Expiring)
		fmt.Fprintf(w, "conrad_certificates{state=\"expired\"} %d\n", st.Expired)
		fmt.Fprintf(w, "conrad_certificates{state=\"revoked\"} %d\n", st.Revoked)
	}
	if n, err := s.Store.CountAccounts(ctx); err == nil {
		gauge("conrad_acme_accounts", "Registered ACME accounts.")
		fmt.Fprintf(w, "conrad_acme_accounts %d\n", n)
	}
	if list, err := s.CA.Authorities(ctx); err == nil {
		gauge("conrad_authority_not_after_seconds", "Expiry of CA certificates (unix seconds).")
		for _, a := range list {
			fmt.Fprintf(w, "conrad_authority_not_after_seconds{id=%q,kind=%q,slug=%q,status=%q} %d\n", a.ID, a.Kind, a.Slug, a.Status, a.NotAfter.Unix())
		}
	}
	if c := s.tls.cert.Load(); c != nil && c.Leaf != nil {
		gauge("conrad_server_cert_not_after_seconds", "Expiry of Conrad's own TLS certificate.")
		fmt.Fprintf(w, "conrad_server_cert_not_after_seconds %d\n", c.Leaf.NotAfter.Unix())
	}
}
