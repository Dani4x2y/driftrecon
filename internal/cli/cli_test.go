package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Dani4x2y/driftrecon/internal/dnstest"
	"github.com/Dani4x2y/driftrecon/internal/model"
	"github.com/Dani4x2y/driftrecon/internal/storage"
)

type env struct {
	t      *testing.T
	db     string
	config string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvWithConfig(t, "")
}

func newEnvWithConfig(t *testing.T, config string) *env {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return &env{t: t, db: filepath.Join(dir, "test.db"), config: cfg}
}

// squeeze collapses runs of whitespace so that assertions do not depend on
// column widths.
func squeeze(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = strings.Join(strings.Fields(line), " ")
	}
	return strings.Join(lines, "\n")
}

func assertContains(t *testing.T, out string, wants ...string) {
	t.Helper()
	squeezed := squeeze(out)
	for _, want := range wants {
		if !strings.Contains(squeezed, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
	}
}

func (e *env) run(args ...string) (string, error) {
	e.t.Helper()
	var out bytes.Buffer
	cmd := New()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(append([]string{"--db", e.db, "--config", e.config}, args...))
	err := cmd.ExecuteContext(e.t.Context())
	return out.String(), err
}

func (e *env) mustRun(args ...string) string {
	e.t.Helper()
	out, err := e.run(args...)
	if err != nil {
		e.t.Fatalf("driftrecon %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// seedScan stores a completed scan without touching the network.
func (e *env) seedScan() {
	e.t.Helper()
	ctx := e.t.Context()

	store, err := storage.Open(ctx, e.db)
	if err != nil {
		e.t.Fatal(err)
	}
	defer store.Close()

	target, err := store.GetTarget(ctx, "acme")
	if err != nil {
		e.t.Fatal(err)
	}
	at := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	scan, err := store.BeginScan(ctx, target.ID, model.ProfileStandard, "cfg", 1, at)
	if err != nil {
		e.t.Fatal(err)
	}

	snap := func(host string, state model.State, dns *model.DNS, sources ...string) storage.Snapshot {
		data, err := json.Marshal(model.HostObservation{Host: host, DNS: dns})
		if err != nil {
			e.t.Fatal(err)
		}
		return storage.Snapshot{
			Kind:       model.KindHost,
			Key:        host,
			Host:       host,
			State:      state,
			FP:         "fp-" + host,
			Data:       data,
			ObservedAt: at,
			Sources:    sources,
			Seen:       true,
		}
	}
	_, err = store.SaveSnapshots(ctx, scan, []storage.Snapshot{
		snap("www.example.com", model.StateLive, &model.DNS{
			Rcode: "NOERROR",
			CNAME: []string{"edge.cdn.example.net"},
			A:     []string{"198.51.100.1", "198.51.100.2"},
			AAAA:  []string{"2001:db8::1"},
		}, "certspotter", "crtsh"),
		snap("example.com", model.StateLive, &model.DNS{Rcode: "NOERROR", A: []string{"192.0.2.1"}}),
		snap("old.example.com", model.StateUnresolved, &model.DNS{
			Rcode: "NXDOMAIN",
			CNAME: []string{"gone.hosting.example.net"},
		}, "crtsh"),
		snap("api.example.com", model.StateError, nil, "crtsh"),
	})
	if err != nil {
		e.t.Fatal(err)
	}
	if err := store.FinishScan(ctx, scan, storage.ScanCompleted, model.ScanStats{Hosts: 4}, at.Add(time.Minute)); err != nil {
		e.t.Fatal(err)
	}
}

// hostColumn returns the first column of every table row in out.
func hostColumn(t *testing.T, out string) []string {
	t.Helper()
	_, table, ok := strings.Cut(out, "\n\n")
	if !ok {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(table), "\n")
	if !strings.HasPrefix(lines[0], "HOST") {
		t.Fatalf("missing table header in:\n%s", out)
	}
	var hosts []string
	for _, line := range lines[1:] {
		hosts = append(hosts, strings.Fields(line)[0])
	}
	return hosts
}

func TestVersion(t *testing.T) {
	if out := newEnv(t).mustRun("version"); !strings.HasPrefix(out, "driftrecon ") {
		t.Errorf("version output = %q", out)
	}
}

func TestTargetAddRequiresAuthorisation(t *testing.T) {
	e := newEnv(t)

	_, err := e.run("target", "add", "acme", "--root", "example.com")
	if err == nil || !strings.Contains(err.Error(), "--authorized") {
		t.Fatalf("err = %v, want a refusal that names --authorized", err)
	}
	if out := e.mustRun("target", "ls"); !strings.Contains(out, "no targets yet") {
		t.Errorf("a refused target was stored:\n%s", out)
	}
}

func TestTargetAddValidatesInput(t *testing.T) {
	cases := map[string][]string{
		"upper case name": {"target", "add", "Acme", "--root", "example.com", "--authorized"},
		"name with space": {"target", "add", "acme corp", "--root", "example.com", "--authorized"},
		"missing name":    {"target", "add", "--root", "example.com", "--authorized"},
		"missing root":    {"target", "add", "acme", "--authorized"},
		"public suffix":   {"target", "add", "acme", "--root", "co.uk", "--authorized"},
		"ip address":      {"target", "add", "acme", "--root", "192.0.2.1", "--authorized"},
		"bad pattern":     {"target", "add", "acme", "--root", "example.com", "--exclude", "[", "--authorized"},
	}
	for name, args := range cases {
		e := newEnv(t)
		if out, err := e.run(args...); err == nil {
			t.Errorf("%s: accepted, output:\n%s", name, out)
		}
		if out := e.mustRun("target", "ls"); !strings.Contains(out, "no targets yet") {
			t.Errorf("%s: a rejected target was stored:\n%s", name, out)
		}
	}
}

func TestTargetLifecycle(t *testing.T) {
	e := newEnv(t)

	out := e.mustRun("target", "add", "acme",
		"--root", "Example.COM,example.org", "--exclude", "*.corp.example.com", "--authorized")
	if want := `target "acme" added: example.com, example.org`; !strings.Contains(out, want) {
		t.Errorf("output = %q, want it to contain %q", out, want)
	}

	if _, err := e.run("target", "add", "acme", "--root", "example.net", "--authorized"); !errors.Is(err, storage.ErrExists) {
		t.Errorf("duplicate target: err = %v, want ErrExists", err)
	}

	e.mustRun("target", "add", "beta", "--root", "example.net", "--authorized")
	lines := strings.Split(strings.TrimSpace(e.mustRun("target", "ls")), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "NAME") {
		t.Fatalf("listing:\n%s", strings.Join(lines, "\n"))
	}
	for _, want := range []string{"acme", "example.com, example.org", "never"} {
		if !strings.Contains(lines[1], want) {
			t.Errorf("row %q does not contain %q", lines[1], want)
		}
	}
	if !strings.HasPrefix(lines[2], "beta") {
		t.Errorf("targets are not sorted by name:\n%s", strings.Join(lines, "\n"))
	}
}

func TestScanRejectsBadInputBeforeScanning(t *testing.T) {
	e := newEnv(t)
	e.mustRun("target", "add", "acme", "--root", "example.com", "--authorized")

	if _, err := e.run("scan", "nope"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("unknown target: err = %v, want ErrNotFound", err)
	}
	cases := map[string][]string{
		"unknown profile":  {"scan", "acme", "--profile", "aggressive"},
		"zero concurrency": {"scan", "acme", "--concurrency", "0"},
		"negative rate":    {"scan", "acme", "--rate", "-1"},
		"zero host limit":  {"scan", "acme", "--max-hosts", "0"},
		"missing target":   {"scan"},
	}
	for name, args := range cases {
		if out, err := e.run(args...); err == nil {
			t.Errorf("%s: accepted, output:\n%s", name, out)
		}
	}
	if out := e.mustRun("target", "ls"); !strings.Contains(out, "never") {
		t.Errorf("a rejected scan left a scan record:\n%s", out)
	}
}

// TestScanEndToEnd drives the real commands against a local CT endpoint and
// a local resolver.
func TestScanEndToEnd(t *testing.T) {
	zone := dnstest.NewZone(
		"example.test. 60 IN A 192.0.2.1",
		"www.example.test. 60 IN A 192.0.2.10",
		"wild.example.test. 60 IN A 192.0.2.1",
		"*.wild.example.test. 60 IN A 192.0.2.99",
	)
	resolver := dnstest.Start(t, zone)

	var (
		mu    sync.Mutex
		names = []string{"www.example.test", "ghost.example.test", "a.wild.example.test", "www.other.test"}
	)
	ct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.UserAgent(), "driftrecon/") {
			t.Errorf("user agent = %q, want the tool to identify itself", r.UserAgent())
		}
		type entry struct {
			NameValue string `json:"name_value"`
		}
		mu.Lock()
		entries := make([]entry, len(names))
		for i, name := range names {
			entries[i] = entry{NameValue: name}
		}
		mu.Unlock()
		json.NewEncoder(w).Encode(entries)
	}))
	t.Cleanup(ct.Close)

	e := newEnvWithConfig(t, fmt.Sprintf(`
resolvers: ["%s"]
timeout: 2s
sources:
  crtsh:
    url: %s
  certspotter:
    enabled: false
`, resolver.Addr, ct.URL))
	e.mustRun("target", "add", "acme", "--root", "example.test", "--authorized")

	out := e.mustRun("scan", "acme")
	assertContains(t, out,
		"scan #1 of acme completed",
		"(profile: standard)",
		"hosts: 4 in scope, 4 new",
		"live 2",
		"wildcard 1",
		"unresolved 1",
		"source crtsh (example.test): 3 names",
	)
	if resolver.Queried("www.other.test") {
		t.Error("a host outside the target was resolved")
	}

	out = e.mustRun("assets", "acme")
	wantHosts := []string{"example.test", "ghost.example.test", "a.wild.example.test", "www.example.test"}
	if got := hostColumn(t, out); strings.Join(got, " ") != strings.Join(wantHosts, " ") {
		t.Errorf("hosts = %v, want %v", got, wantHosts)
	}
	assertContains(t, out,
		"www.example.test live 192.0.2.10 crtsh",
		"a.wild.example.test wildcard 192.0.2.99 crtsh",
		"ghost.example.test unresolved crtsh",
	)

	zone.Add("staging.example.test. 60 IN A 192.0.2.30")
	mu.Lock()
	names = append(names, "staging.example.test")
	mu.Unlock()

	out = e.mustRun("scan", "acme")
	assertContains(t, out, "scan #2 of acme completed", "hosts: 5 in scope, 1 new", "live 3")

	before := resolver.Queries()
	out = e.mustRun("scan", "acme", "--profile", "passive")
	assertContains(t, out, "scan #3 of acme completed", "(profile: passive)", "hosts: 5 in scope, 0 new", "discovered 5")
	if sent := resolver.Queries() - before; sent != 0 {
		t.Errorf("a passive scan sent %d DNS queries", sent)
	}

	assertContains(t, e.mustRun("assets", "acme"), "scan #3 of acme (passive", "staging.example.test discovered")
	assertContains(t, e.mustRun("assets", "acme", "--scan", "2"), "staging.example.test live 192.0.2.30 crtsh")
	assertContains(t, e.mustRun("target", "ls"), "acme example.test 5 3")
}

func TestAssetsWithoutScan(t *testing.T) {
	e := newEnv(t)
	e.mustRun("target", "add", "acme", "--root", "example.com", "--authorized")

	_, err := e.run("assets", "acme")
	if err == nil || !strings.Contains(err.Error(), "driftrecon scan acme") {
		t.Errorf("err = %v, want a hint to run a scan first", err)
	}
	if _, err := e.run("assets", "nope"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("unknown target: err = %v, want ErrNotFound", err)
	}
}

func TestAssets(t *testing.T) {
	e := newEnv(t)
	e.mustRun("target", "add", "acme", "--root", "example.com", "--authorized")
	e.seedScan()

	out := e.mustRun("assets", "acme")
	header, _, _ := strings.Cut(out, "\n")
	if want := "scan #1 of acme (standard, 2026-03-01 12:00 UTC): 4 of 4 hosts"; header != want {
		t.Errorf("header = %q, want %q", header, want)
	}
	wantHosts := []string{"example.com", "api.example.com", "old.example.com", "www.example.com"}
	if got := hostColumn(t, out); strings.Join(got, " ") != strings.Join(wantHosts, " ") {
		t.Errorf("hosts = %v, want %v with the parent domain first", got, wantHosts)
	}
	for _, want := range []string{
		"198.51.100.1, 198.51.100.2 (+1)",
		"edge.cdn.example.net",
		"gone.hosting.example.net",
		"certspotter,crtsh",
		"2026-03-01",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
	}

	out = e.mustRun("assets", "acme", "--state", "LIVE", "--state", "error")
	if got := hostColumn(t, out); len(got) != 3 || !strings.HasPrefix(out, "scan #1 of acme") || !strings.Contains(out, "3 of 4 hosts") {
		t.Errorf("filtered listing:\n%s", out)
	}

	out = e.mustRun("assets", "acme", "--state", "wildcard", "--scan", "1")
	if strings.Contains(out, "HOST") || !strings.Contains(out, "0 of 4 hosts") {
		t.Errorf("empty listing should have no table:\n%s", out)
	}

	if _, err := e.run("assets", "acme", "--state", "bogus"); err == nil {
		t.Error("an unknown state was accepted")
	}
	if _, err := e.run("assets", "acme", "--scan", "999"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("unknown scan: err = %v, want ErrNotFound", err)
	}
}

func TestDomainKeyGroupsSubdomains(t *testing.T) {
	cases := map[string]string{
		"example.com":           "com.example",
		"www.example.com":       "com.example.www",
		"a.b.example.co.uk":     "uk.co.example.b.a",
		"xn--bcher-kva.example": "example.xn--bcher-kva",
	}
	for in, want := range cases {
		if got := domainKey(in); got != want {
			t.Errorf("domainKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAbbreviate(t *testing.T) {
	cases := []struct {
		values []string
		want   string
	}{
		{nil, ""},
		{[]string{"a"}, "a"},
		{[]string{"a", "b"}, "a, b"},
		{[]string{"a", "b", "c", "d"}, "a, b (+2)"},
	}
	for _, tc := range cases {
		if got := abbreviate(tc.values, 2); got != tc.want {
			t.Errorf("abbreviate(%v) = %q, want %q", tc.values, got, tc.want)
		}
	}
}
