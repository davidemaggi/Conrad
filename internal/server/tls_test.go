package server

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"testing"

	"github.com/davidemaggi/conrad/internal/ca"
	"github.com/davidemaggi/conrad/internal/config"
	"github.com/davidemaggi/conrad/internal/crypto/signer"
	"github.com/davidemaggi/conrad/internal/store"
)

func TestServerCertificateFollowsHostsAndConstraints(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()

	// The setup scenario from the field: external URL outside the root's constraint.
	s := &Server{
		Cfg:     &config.Config{TLSMode: config.TLSSelf, Hostnames: []string{"ca.dm.lab"}},
		Log:     log,
		Store:   st,
		BaseURL: "https://ca.example.casa",
	}
	s.CA = ca.New(st, signer.NewSoftware(), s.BaseURL, log)
	if _, _, err := s.CA.Init(ctx, ca.InitRequest{
		Secret:          "a very long passphrase",
		Subject:         ca.Subject{CommonName: "DM Lab Root CA"},
		NameConstraints: []string{"dm.lab"},
		Issuer:          ca.IssuerRequest{Slug: "default", Name: "DM Lab Issuer"},
	}); err != nil {
		t.Fatal(err)
	}
	s.tls = tlsManager{s: s, dir: t.TempDir()}

	names := func() []string {
		t.Helper()
		c := s.tls.cert.Load()
		if c == nil || c.Leaf == nil {
			t.Fatal("no certificate loaded")
		}
		return leafNames(c.Leaf)
	}

	if err := s.tls.refresh(ctx, true); err != nil {
		t.Fatal(err)
	}
	if got := names(); !slices.Equal(got, []string{"ca.dm.lab"}) {
		t.Fatalf("names = %v, want only ca.dm.lab (the external host violates the constraint)", got)
	}

	// Restart with an extra allowed hostname: the persisted certificate must be replaced.
	s.Cfg.Hostnames = []string{"ca.dm.lab", "conrad.dm.lab"}
	s.tls = tlsManager{s: s, dir: s.tls.dir}
	if err := s.tls.refresh(ctx, false); err != nil {
		t.Fatal(err)
	}
	if got := names(); !sameNames(got, []string{"ca.dm.lab", "conrad.dm.lab"}) {
		t.Fatalf("names = %v after adding a hostname", got)
	}

	// Restart with a hostname removed: the extra name must disappear too.
	s.Cfg.Hostnames = []string{"ca.dm.lab"}
	s.tls = tlsManager{s: s, dir: s.tls.dir}
	if err := s.tls.refresh(ctx, false); err != nil {
		t.Fatal(err)
	}
	if got := names(); !slices.Equal(got, []string{"ca.dm.lab"}) {
		t.Fatalf("names = %v after removing a hostname", got)
	}

	// Unchanged config: the certificate on disk is reused, not re-issued.
	before := s.tls.cert.Load().Leaf.SerialNumber
	s.tls = tlsManager{s: s, dir: s.tls.dir}
	if err := s.tls.refresh(ctx, false); err != nil {
		t.Fatal(err)
	}
	if s.tls.cert.Load().Leaf.SerialNumber.Cmp(before) != 0 {
		t.Fatal("certificate re-issued although the hostnames did not change")
	}
}
