package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// isolateHome points every platform's user config directory at a temp dir.
func isolateHome(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AppData", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
}

func TestDefaultIsValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("default config is invalid: %v", err)
	}
}

func TestLoadOverlaysFile(t *testing.T) {
	isolateHome(t)
	t.Setenv(TokenEnv, "s3cret")

	path := writeConfig(t, `
database: /var/lib/driftrecon/acme.db
resolvers: [192.0.2.53, "192.0.2.54:5353", "2001:db8::53"]
concurrency: 4
timeout: 1500ms
sources:
  crtsh:
    enabled: false
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Database != "/var/lib/driftrecon/acme.db" {
		t.Errorf("database = %q", cfg.Database)
	}
	want := []string{"192.0.2.53:53", "192.0.2.54:5353", "[2001:db8::53]:53"}
	if !slices.Equal(cfg.Resolvers, want) {
		t.Errorf("resolvers = %v, want %v", cfg.Resolvers, want)
	}
	if cfg.Concurrency != 4 {
		t.Errorf("concurrency = %d, want 4", cfg.Concurrency)
	}
	if cfg.Timeout != 1500*time.Millisecond {
		t.Errorf("timeout = %v, want 1.5s", cfg.Timeout)
	}
	if cfg.Sources.CrtSh.Enabled {
		t.Error("crtsh should be disabled by the file")
	}

	def := Default()
	if !cfg.Sources.CertSpotter.Enabled {
		t.Error("certspotter should keep its default")
	}
	if cfg.Rate != def.Rate || cfg.MaxHosts != def.MaxHosts || cfg.ScanTimeout != def.ScanTimeout {
		t.Errorf("unset keys lost their defaults: %+v", cfg)
	}
	if cfg.CertSpotterToken != "s3cret" {
		t.Errorf("token = %q, want value from environment", cfg.CertSpotterToken)
	}
}

func TestLoadWithoutFileUsesDefaults(t *testing.T) {
	isolateHome(t)

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(cfg.Database) != databaseName {
		t.Errorf("database = %q, want a file named %s", cfg.Database, databaseName)
	}
	if !slices.Equal(cfg.Resolvers, Default().Resolvers) {
		t.Errorf("resolvers = %v", cfg.Resolvers)
	}
}

func TestLoadEmptyFile(t *testing.T) {
	isolateHome(t)

	cfg, err := Load(writeConfig(t, "# nothing set\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Concurrency != Default().Concurrency {
		t.Errorf("concurrency = %d", cfg.Concurrency)
	}
}

func TestLoadErrors(t *testing.T) {
	isolateHome(t)

	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("explicit path to a missing file should fail")
	}

	cases := map[string]string{
		"unknown key":        "concurency: 5\n",
		"secret in file":     "sources:\n  certspotter:\n    token: abc\n",
		"hostname resolver":  "resolvers: [dns.example.com]\n",
		"zero concurrency":   "concurrency: 0\n",
		"huge concurrency":   "concurrency: 10000\n",
		"negative rate":      "rate: -1\n",
		"zero timeout":       "timeout: 0s\n",
		"no resolvers":       "resolvers: []\n",
		"zero max hosts":     "max_hosts: 0\n",
		"malformed duration": "timeout: soon\n",
		"empty user agent":   "user_agent: \"\"\n",
	}
	for name, body := range cases {
		if _, err := Load(writeConfig(t, body)); err == nil {
			t.Errorf("%s: Load succeeded, want error", name)
		}
	}
}

func TestDefaultUserAgentIdentifiesTool(t *testing.T) {
	ua := Default().UserAgent
	if !strings.HasPrefix(ua, "driftrecon/") || !strings.Contains(ua, projectURL) {
		t.Errorf("user agent %q does not identify the tool", ua)
	}
}
