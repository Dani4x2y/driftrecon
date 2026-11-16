// Package config loads runtime settings from defaults, an optional YAML file
// and the environment.
package config

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
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
	Probe       Probe         `yaml:"probe"`

	CertSpotterToken string `yaml:"-"`
}

// maxProbePorts bounds how many ports a scan checks on every host. The tool
// looks for web services where they are expected, it does not scan ports.
const maxProbePorts = 10

// Probe configures how the HTTP services of a host are examined.
type Probe struct {
	// HTTPPorts and HTTPSPorts are the ports checked on every host that
	// resolves. With both lists empty a scan stops at name resolution.
	HTTPPorts  []int `yaml:"http_ports"`
	HTTPSPorts []int `yaml:"https_ports"`
	// Rate caps the connections opened per second across all hosts,
	// HostRate the ones to any single host.
	Rate     float64 `yaml:"rate"`
	HostRate float64 `yaml:"host_rate"`
	// Timeout bounds each phase of a request.
	Timeout time.Duration `yaml:"timeout"`
	// AllowPrivate lets the probe connect to loopback, private and other
	// non-public addresses. It is meant for scanning internal zones.
	AllowPrivate bool `yaml:"allow_private"`
}

func (p Probe) validate() error {
	switch {
	case p.Rate <= 0:
		return errors.New("rate must be positive")
	case p.HostRate <= 0:
		return errors.New("host_rate must be positive")
	case p.Timeout <= 0:
		return errors.New("timeout must be positive")
	case len(p.HTTPPorts)+len(p.HTTPSPorts) > maxProbePorts:
		return fmt.Errorf("at most %d ports can be checked per host", maxProbePorts)
	}
	seen := make(map[int]bool)
	for _, port := range slices.Concat(p.HTTPPorts, p.HTTPSPorts) {
		switch {
		case port < 1 || port > 65535:
			return fmt.Errorf("port %d is out of range", port)
		case seen[port]:
			return fmt.Errorf("port %d is listed more than once", port)
		}
		seen[port] = true
	}
	return nil
}

// Sources toggles the passive discovery sources.
type Sources struct {
	CrtSh       Source `yaml:"crtsh"`
	CertSpotter Source `yaml:"certspotter"`
}

// Source is the configuration shared by all discovery sources.
type Source struct {
	Enabled bool `yaml:"enabled"`
	// URL replaces the public endpoint, for example with a self-hosted
	// mirror.
	URL string `yaml:"url"`
}

func (s Source) validate() error {
	if s.URL == "" {
		return nil
	}
	u, err := url.Parse(s.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("url %q must be an absolute http or https URL", s.URL)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("url %q must not carry a query or fragment", s.URL)
	}
	return nil
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
		Probe: Probe{
			HTTPPorts:  []int{80},
			HTTPSPorts: []int{443},
			Rate:       20,
			HostRate:   2,
			Timeout:    10 * time.Second,
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
	if err := c.Sources.CrtSh.validate(); err != nil {
		return fmt.Errorf("config: sources.crtsh: %w", err)
	}
	if err := c.Sources.CertSpotter.validate(); err != nil {
		return fmt.Errorf("config: sources.certspotter: %w", err)
	}
	if err := c.Probe.validate(); err != nil {
		return fmt.Errorf("config: probe: %w", err)
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
