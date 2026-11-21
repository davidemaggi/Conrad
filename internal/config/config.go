// Package config loads Conrad's configuration from an optional YAML file
// and CONRAD_* environment variables (env wins).
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// TLSMode controls how Conrad serves its own HTTPS listener.
type TLSMode string

const (
	// TLSSelf serves HTTPS with a certificate issued by Conrad's default issuer.
	TLSSelf TLSMode = "self"
	// TLSOff serves plain HTTP on HTTPSAddr (use behind a TLS-terminating proxy).
	TLSOff TLSMode = "off"
)

type Config struct {
	DataDir     string   `yaml:"data_dir"`
	ExternalURL string   `yaml:"external_url"`
	HTTPSAddr   string   `yaml:"https_addr"`
	HTTPAddr    string   `yaml:"http_addr"`
	TLSMode     TLSMode  `yaml:"tls_mode"`
	Hostnames   []string `yaml:"hostnames"`

	CAPassphrase     string `yaml:"-"`
	CAPassphraseFile string `yaml:"ca_passphrase_file"`

	DNSResolvers []string `yaml:"dns_resolvers"`

	Log struct {
		Level  string `yaml:"level"`
		Format string `yaml:"format"`
	} `yaml:"log"`

	PKCS11 struct {
		Module     string `yaml:"module"`
		TokenLabel string `yaml:"token_label"`
		PIN        string `yaml:"-"`
		PINFile    string `yaml:"pin_file"`
	} `yaml:"pkcs11"`

	// ChallengePorts overrides the ports used by validators. Production uses
	// 80/443 as mandated by RFC 8555/8737; tests override them.
	ChallengePorts struct {
		HTTP int `yaml:"http"`
		TLS  int `yaml:"tls"`
	} `yaml:"-"`
}

// Default returns a Config with sane defaults.
func Default() *Config {
	c := &Config{
		DataDir:   "./data",
		HTTPSAddr: ":443",
		HTTPAddr:  ":80",
		TLSMode:   TLSSelf,
	}
	c.Log.Level = "info"
	c.Log.Format = "text"
	c.ChallengePorts.HTTP = 80
	c.ChallengePorts.TLS = 443
	return c
}

// Load reads the YAML file at path (optional, may be empty) then applies env.
func Load(path string) (*Config, error) {
	c := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		if err := yaml.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}
	c.applyEnv(os.Getenv)
	if err := c.resolveSecrets(); err != nil {
		return nil, err
	}
	return c, c.Validate()
}

func (c *Config) applyEnv(get func(string) string) {
	set := func(dst *string, key string) {
		if v := get("CONRAD_" + key); v != "" {
			*dst = v
		}
	}
	set(&c.DataDir, "DATA_DIR")
	set(&c.ExternalURL, "EXTERNAL_URL")
	set(&c.HTTPSAddr, "HTTPS_ADDR")
	set(&c.HTTPAddr, "HTTP_ADDR")
	var mode string
	set(&mode, "TLS_MODE")
	if mode != "" {
		c.TLSMode = TLSMode(mode)
	}
	var hosts, resolvers string
	set(&hosts, "HOSTNAMES")
	if hosts != "" {
		c.Hostnames = splitList(hosts)
	}
	set(&resolvers, "DNS_RESOLVERS")
	if resolvers != "" {
		c.DNSResolvers = splitList(resolvers)
	}
	set(&c.CAPassphrase, "CA_PASSPHRASE")
	set(&c.CAPassphraseFile, "CA_PASSPHRASE_FILE")
	set(&c.Log.Level, "LOG_LEVEL")
	set(&c.Log.Format, "LOG_FORMAT")
	set(&c.PKCS11.Module, "PKCS11_MODULE")
	set(&c.PKCS11.TokenLabel, "PKCS11_TOKEN_LABEL")
	set(&c.PKCS11.PIN, "PKCS11_PIN")
	set(&c.PKCS11.PINFile, "PKCS11_PIN_FILE")
	// "none" disables the plain HTTP listener.
	if c.HTTPAddr == "none" {
		c.HTTPAddr = ""
	}
}

func (c *Config) resolveSecrets() error {
	read := func(dst *string, file string) error {
		if *dst != "" || file == "" {
			return nil
		}
		b, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("read secret %s: %w", file, err)
		}
		*dst = strings.TrimRight(string(b), "\r\n")
		return nil
	}
	if err := read(&c.CAPassphrase, c.CAPassphraseFile); err != nil {
		return err
	}
	return read(&c.PKCS11.PIN, c.PKCS11.PINFile)
}

// Validate checks the configuration for obvious mistakes.
func (c *Config) Validate() error {
	var errs []error
	if c.DataDir == "" {
		errs = append(errs, errors.New("data_dir is required"))
	}
	if c.TLSMode != TLSSelf && c.TLSMode != TLSOff {
		errs = append(errs, fmt.Errorf("tls_mode must be %q or %q", TLSSelf, TLSOff))
	}
	if c.ExternalURL != "" {
		u, err := url.Parse(c.ExternalURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			errs = append(errs, fmt.Errorf("external_url %q must be an absolute http(s) URL", c.ExternalURL))
		}
	}
	return errors.Join(errs...)
}

// DBPath returns the SQLite database path.
func (c *Config) DBPath() string { return filepath.Join(c.DataDir, "conrad.db") }

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
