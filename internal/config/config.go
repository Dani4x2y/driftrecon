// Package config loads runtime settings from defaults, an optional YAML file
// and the environment.
package config

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Dani4x2y/driftrecon/internal/version"
)

const (
	dirName      = "driftrecon"
	fileName     = "config.yaml"
	databaseName = "driftrecon.db"
	projectURL   = "https://github.com/Dani4x2y/driftrecon"

	// TokenEnv names the environment variable holding the optional Cert
	// Spotter API token. Secrets are deliberately not read from the file.
	TokenEnv = "CERTSPOTTER_TOKEN"
)

// Config holds every tunable of a scan.
type Config struct {
	Database    string        `yaml:"database"`
	UserAgent   string        `yaml:"user_agent"`
	Resolvers   []string      `yaml:"resolvers"`
	Concurrency int           `yaml:"concurrency"`
	Rate        float64       `yaml:"rate"`
	Timeout     time.Duration `yaml:"timeout"`
	ScanTimeout time.Duration `yaml:"scan_timeout"`
	MaxHosts    int           `yaml:"max_hosts"`
	Sources     Sources       `yaml:"sources"`

	CertSpotterToken string `yaml:"-"`
}

// Sources toggles the passive discovery sources.
type Sources struct {
	CrtSh       Source `yaml:"crtsh"`
	CertSpotter Source `yaml:"certspotter"`
}

// Source is the configuration shared by all discovery sources.
type Source struct {
	Enabled bool `yaml:"enabled"`
}

// Default returns the built-in settings.
func Default() Config {
	return Config{
		UserAgent:   fmt.Sprintf("driftrecon/%s (+%s)", version.String(), projectURL),
		Resolvers:   []string{"1.1.1.1:53", "9.9.9.9:53", "8.8.8.8:53"},
		Concurrency: 20,
		Rate:        50,
		Timeout:     5 * time.Second,
		ScanTimeout: 30 * time.Minute,
		MaxHosts:    5000,
		Sources: Sources{
			CrtSh:       Source{Enabled: true},
			CertSpotter: Source{Enabled: true},
		},
	}
}

// Dir returns the directory holding the default config file and database.
func Dir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("config: locate user config directory: %w", err)
	}
	return filepath.Join(base, dirName), nil
}

// Load returns the defaults overlaid with the file at path. An empty path
// selects config.yaml in Dir, which is allowed to be missing.
func Load(path string) (Config, error) {
	cfg := Default()

	explicit := path != ""
	if !explicit {
		dir, err := Dir()
		if err != nil {
			return Config{}, err
		}
		path = filepath.Join(dir, fileName)
	}

	switch err := decodeFile(path, &cfg); {
	case err == nil:
	case !explicit && errors.Is(err, fs.ErrNotExist):
	default:
		return Config{}, err
	}

	cfg.CertSpotterToken = os.Getenv(TokenEnv)

	if cfg.Database == "" {
		dir, err := Dir()
		if err != nil {
			return Config{}, err
		}
		cfg.Database = filepath.Join(dir, databaseName)
	}
	for i, r := range cfg.Resolvers {
		addr, err := normalizeResolver(r)
		if err != nil {
			return Config{}, err
		}
		cfg.Resolvers[i] = addr
	}
	return cfg, cfg.Validate()
}

// Validate reports settings that would make a scan unsafe or meaningless.
func (c Config) Validate() error {
	switch {
	case c.Concurrency < 1 || c.Concurrency > 256:
		return errors.New("config: concurrency must be between 1 and 256")
	case c.Rate <= 0:
		return errors.New("config: rate must be positive")
	case c.Timeout <= 0:
		return errors.New("config: timeout must be positive")
	case c.ScanTimeout <= 0:
		return errors.New("config: scan_timeout must be positive")
	case c.MaxHosts < 1:
		return errors.New("config: max_hosts must be positive")
	case len(c.Resolvers) == 0:
		return errors.New("config: at least one resolver is required")
	case c.UserAgent == "":
		return errors.New("config: user_agent must not be empty")
	}
	for _, r := range c.Resolvers {
		if _, err := netip.ParseAddrPort(r); err != nil {
			return fmt.Errorf("config: resolver %q is not an ip:port address", r)
		}
	}
	return nil
}

func decodeFile(path string, cfg *Config) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("config: %s: %w", path, err)
	}
	return nil
}

// normalizeResolver accepts a bare IP address or ip:port. Hostnames are
// refused: resolving the resolver would need a resolver.
func normalizeResolver(r string) (string, error) {
	if addr, err := netip.ParseAddr(r); err == nil {
		return netip.AddrPortFrom(addr, 53).String(), nil
	}
	if ap, err := netip.ParseAddrPort(r); err == nil {
		return ap.String(), nil
	}
	return "", fmt.Errorf("config: resolver %q is not an IP address", r)
}
