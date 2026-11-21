package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFileThenEnv(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "conrad.yaml")
	os.WriteFile(p, []byte("data_dir: /from/file\nexternal_url: https://conrad.home.lab\nhostnames: [conrad.home.lab]\n"), 0o600)
	secret := filepath.Join(dir, "pass")
	os.WriteFile(secret, []byte("s3cret\n"), 0o600)

	t.Setenv("CONRAD_DATA_DIR", "/from/env")
	t.Setenv("CONRAD_CA_PASSPHRASE_FILE", secret)
	t.Setenv("CONRAD_HTTP_ADDR", "none")

	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.DataDir != "/from/env" {
		t.Errorf("env should override file, got %q", c.DataDir)
	}
	if c.CAPassphrase != "s3cret" {
		t.Errorf("passphrase from file = %q", c.CAPassphrase)
	}
	if c.HTTPAddr != "" {
		t.Errorf("HTTP listener should be disabled, got %q", c.HTTPAddr)
	}
	if len(c.Hostnames) != 1 || c.Hostnames[0] != "conrad.home.lab" {
		t.Errorf("hostnames = %v", c.Hostnames)
	}
}

func TestValidate(t *testing.T) {
	c := Default()
	c.ExternalURL = "conrad.home.lab"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for relative external_url")
	}
	c.ExternalURL = "https://conrad.home.lab"
	c.TLSMode = "bogus"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for bad tls_mode")
	}
}
