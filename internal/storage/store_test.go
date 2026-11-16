package storage

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/Dani4x2y/driftrecon/internal/model"
	"github.com/Dani4x2y/driftrecon/internal/scope"
)

var t0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func openStore(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func newStore(t *testing.T) *Store {
	t.Helper()
	return openStore(t, filepath.Join(t.TempDir(), "test.db"))
}

func newTarget(t *testing.T, s *Store, name string) *Target {
	t.Helper()
	target, err := s.CreateTarget(t.Context(), name, scope.Rules{Roots: []string{name + ".example"}}, t0)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func newScan(t *testing.T, s *Store, target *Target, at time.Time) *Scan {
	t.Helper()
	scan, err := s.BeginScan(t.Context(), target.ID, model.ProfileStandard, "cfg", 1, at)
	if err != nil {
		t.Fatal(err)
	}
	return scan
}

func hostSnapshot(host, data string, at time.Time) Snapshot {
	return Snapshot{
		Kind:       model.KindHost,
		Key:        host,
		Host:       host,
		State:      model.StateLive,
		FP:         "fp-" + data,
		FPDNS:      "dns-" + data,
		Data:       []byte(data),
		ObservedAt: at,
		Seen:       true,
	}
}

func count(t *testing.T, s *Store, table string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRowContext(t.Context(), "SELECT count(*) FROM "+table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestOpenIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", "test.db")

	first := openStore(t, path)
	newTarget(t, first, "acme")
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second := openStore(t, path)
	if _, err := second.GetTarget(t.Context(), "acme"); err != nil {
		t.Fatalf("data lost across reopen: %v", err)
	}

	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	got, err := second.schemaVersion(t.Context(), second.db)
	if err != nil {
		t.Fatal(err)
	}
	if want := migrations[len(migrations)-1].version; got != want {
		t.Errorf("schema version = %d, want %d", got, want)
	}
}

func TestOpenRejectsNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	s := openStore(t, path)
	if _, err := s.db.ExecContext(t.Context(), "PRAGMA user_version = 9999"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(t.Context(), path); err == nil {
		t.Fatal("opening a database from a newer build should fail")
	}
}

func TestOpenRejectsAmbiguousPath(t *testing.T) {
	if _, err := Open(t.Context(), filepath.Join(t.TempDir(), "a?b.db")); err == nil {
		t.Fatal("a path with a query separator should be rejected")
	}
}

func TestDatabaseFileIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not meaningful on windows")
	}
	path := filepath.Join(t.TempDir(), "test.db")
	openStore(t, path)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("database mode = %o, want 600", perm)
	}
}

func TestForeignKeysAreEnforced(t *testing.T) {
	s := newStore(t)
	orphan := &Scan{ID: 4242, TargetID: 4242}

	_, err := s.SaveSnapshots(t.Context(), orphan, []Snapshot{hostSnapshot("a.acme.example", "x", t0)})
	if err == nil {
		t.Fatal("snapshot for a missing scan was accepted")
	}
}

func TestTargets(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	rules := scope.Rules{
		Roots:   []string{"example.com", "example.org"},
		Include: []string{"*.prod.example.com"},
		Exclude: []string{"vpn.example.com"},
	}
	created, err := s.CreateTarget(ctx, "acme", rules, t0.Add(1500*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.GetTarget(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != created.ID || !got.CreatedAt.Equal(created.CreatedAt) || !got.AuthorizedAt.Equal(t0.Add(time.Second)) {
		t.Errorf("stored target %+v does not match created %+v", got, created)
	}
	if !slices.Equal(got.Rules.Roots, rules.Roots) ||
		!slices.Equal(got.Rules.Include, rules.Include) ||
		!slices.Equal(got.Rules.Exclude, rules.Exclude) {
		t.Errorf("rules = %+v, want %+v", got.Rules, rules)
	}

	if _, err := s.CreateTarget(ctx, "acme", rules, t0); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate create: err = %v, want ErrExists", err)
	}
	if _, err := s.GetTarget(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing target: err = %v, want ErrNotFound", err)
	}
}

func TestListTargets(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	if list, err := s.ListTargets(ctx); err != nil || len(list) != 0 {
		t.Fatalf("empty store: %v, %v", list, err)
	}

	zeta := newTarget(t, s, "zeta")
	newTarget(t, s, "acme")

	scan := newScan(t, s, zeta, t0.Add(time.Hour))
	if _, err := s.SaveSnapshots(ctx, scan, []Snapshot{
		hostSnapshot("a.zeta.example", "1", t0),
		hostSnapshot("b.zeta.example", "2", t0),
	}); err != nil {
		t.Fatal(err)
	}
	newScan(t, s, zeta, t0.Add(2*time.Hour))

	list, err := s.ListTargets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Name != "acme" || list[1].Name != "zeta" {
		t.Fatalf("targets = %+v, want acme then zeta", list)
	}
	if a := list[0]; a.Scans != 0 || a.Hosts != 0 || !a.LastScanAt.IsZero() {
		t.Errorf("unscanned target summary = %+v", a)
	}
	if z := list[1]; z.Scans != 2 || z.Hosts != 2 || !z.LastScanAt.Equal(t0.Add(2*time.Hour)) {
		t.Errorf("scanned target summary = %+v", z)
	}
}

func TestScanLifecycle(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	target := newTarget(t, s, "acme")

	if _, err := s.LatestScan(ctx, target.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no scans yet: err = %v, want ErrNotFound", err)
	}

	first := newScan(t, s, target, t0)
	if first.Status != ScanRunning {
		t.Errorf("new scan status = %s", first.Status)
	}
	if _, err := s.LatestScan(ctx, target.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("a running scan must not count as latest: err = %v", err)
	}

	stats := model.ScanStats{
		Hosts:    3,
		States:   map[model.State]int{model.StateLive: 2, model.StateUnresolved: 1},
		NewHosts: 3,
		Sources:  []model.SourceStat{{Source: "crtsh", Domain: "acme.example", Names: 3}},
	}
	if err := s.FinishScan(ctx, first, ScanCompleted, stats, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	aborted := newScan(t, s, target, t0.Add(time.Hour))
	if err := s.FinishScan(ctx, aborted, ScanAborted, model.ScanStats{Reason: "interrupted"}, t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}

	latest, err := s.LatestScan(ctx, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if latest.ID != first.ID {
		t.Fatalf("latest scan = %d, want the completed scan %d", latest.ID, first.ID)
	}
	if latest.Status != ScanCompleted || latest.Profile != model.ProfileStandard ||
		!latest.StartedAt.Equal(t0) || !latest.FinishedAt.Equal(t0.Add(time.Minute)) {
		t.Errorf("latest scan = %+v", latest)
	}
	if latest.Stats.Hosts != 3 || latest.Stats.States[model.StateLive] != 2 || len(latest.Stats.Sources) != 1 {
		t.Errorf("stats = %+v", latest.Stats)
	}

	got, err := s.GetScan(ctx, target.ID, aborted.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != ScanAborted || got.Stats.Reason != "interrupted" {
		t.Errorf("aborted scan = %+v", got)
	}

	other := newTarget(t, s, "other")
	if _, err := s.GetScan(ctx, other.ID, first.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("scan of another target: err = %v, want ErrNotFound", err)
	}
}

func TestSnapshotsAreContentAddressed(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	target := newTarget(t, s, "acme")

	first := newScan(t, s, target, t0)
	a := hostSnapshot("a.acme.example", "A1", t0)
	a.Sources = []string{"crtsh"}
	b := hostSnapshot("b.acme.example", "B1", t0)
	created, err := s.SaveSnapshots(ctx, first, []Snapshot{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if created[model.KindHost] != 2 {
		t.Errorf("first scan created %v assets, want 2 hosts", created)
	}

	later := t0.Add(24 * time.Hour)
	second := newScan(t, s, target, later)
	a2 := hostSnapshot("a.acme.example", "A1", later)
	a2.Sources = []string{"certspotter", "crtsh"}
	b2 := hostSnapshot("b.acme.example", "B2", later)
	b2.State = model.StateUnresolved
	b2.Seen = false
	created, err = s.SaveSnapshots(ctx, second, []Snapshot{a2, b2})
	if err != nil {
		t.Fatal(err)
	}
	if len(created) != 0 {
		t.Errorf("second scan created %v assets, want none", created)
	}

	if n := count(t, s, "assets"); n != 2 {
		t.Errorf("assets = %d, want 2", n)
	}
	if n := count(t, s, "snapshots"); n != 4 {
		t.Errorf("snapshots = %d, want 4", n)
	}
	if n := count(t, s, "blobs"); n != 3 {
		t.Errorf("blobs = %d, want 3: unchanged content must be stored once", n)
	}

	snaps, err := s.Snapshots(ctx, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(snaps) != 2 || snaps[0].Key != "a.acme.example" || snaps[1].Key != "b.acme.example" {
		t.Fatalf("snapshots = %+v", snaps)
	}

	gotA, gotB := snaps[0], snaps[1]
	if string(gotA.Data) != "A1" || gotA.State != model.StateLive || gotA.FP != "fp-A1" || gotA.FPDNS != "dns-A1" {
		t.Errorf("snapshot a = %+v", gotA)
	}
	if want := []string{"certspotter", "crtsh"}; !slices.Equal(gotA.Sources, want) {
		t.Errorf("sources = %v, want %v", gotA.Sources, want)
	}
	if !gotA.FirstSeenAt.Equal(t0) || !gotA.LastSeenAt.Equal(later) || !gotA.ObservedAt.Equal(later) {
		t.Errorf("snapshot a times = first %v, last %v, observed %v", gotA.FirstSeenAt, gotA.LastSeenAt, gotA.ObservedAt)
	}

	if string(gotB.Data) != "B2" || gotB.State != model.StateUnresolved || gotB.Sources != nil {
		t.Errorf("snapshot b = %+v", gotB)
	}
	if !gotB.LastSeenAt.Equal(t0) {
		t.Errorf("last seen = %v, want %v: an asset that was not seen must keep its date", gotB.LastSeenAt, t0)
	}

	keys, err := s.AssetKeys(ctx, target.ID, model.KindHost)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a.acme.example", "b.acme.example"}; !slices.Equal(keys, want) {
		t.Errorf("asset keys = %v, want %v", keys, want)
	}
}

func TestSaveSnapshotsIsAtomic(t *testing.T) {
	s := newStore(t)
	target := newTarget(t, s, "acme")
	scan := newScan(t, s, target, t0)

	broken := hostSnapshot("b.acme.example", "", t0)
	_, err := s.SaveSnapshots(t.Context(), scan, []Snapshot{hostSnapshot("a.acme.example", "A", t0), broken})
	if err == nil {
		t.Fatal("a snapshot without data was accepted")
	}
	for _, table := range []string{"assets", "blobs", "snapshots"} {
		if n := count(t, s, table); n != 0 {
			t.Errorf("%s = %d rows after a failed batch, want 0", table, n)
		}
	}
}

func TestAssetsAreScopedToTarget(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	acme, other := newTarget(t, s, "acme"), newTarget(t, s, "other")

	for _, target := range []*Target{acme, other} {
		scan := newScan(t, s, target, t0)
		created, err := s.SaveSnapshots(ctx, scan, []Snapshot{hostSnapshot("shared.example", "S", t0)})
		if err != nil {
			t.Fatal(err)
		}
		if created[model.KindHost] != 1 {
			t.Errorf("target %s: created = %v, want 1 host", target.Name, created)
		}
	}
	if n := count(t, s, "assets"); n != 2 {
		t.Errorf("assets = %d, want one per target", n)
	}
	if n := count(t, s, "blobs"); n != 1 {
		t.Errorf("blobs = %d, want identical content shared across targets", n)
	}
}

func serviceSnapshot(key, host, data string, at time.Time) Snapshot {
	return Snapshot{
		Kind:       model.KindService,
		Key:        key,
		Host:       host,
		State:      model.StateLive,
		FP:         "fp-" + data,
		FPTLS:      "tls-" + data,
		FPHeaders:  "headers-" + data,
		FPRedirect: "redirect-" + data,
		FPDOM:      "dom-" + data,
		Data:       []byte(data),
		ObservedAt: at,
		Sources:    []string{"probe"},
		Seen:       true,
	}
}

func certificate(digest, cn string) model.Certificate {
	return model.Certificate{
		SHA256:     digest,
		SubjectCN:  cn,
		IssuerCN:   "R11",
		IssuerOrg:  "Let's Encrypt",
		Serial:     "04d2",
		SANs:       []string{cn, "alt." + cn},
		SPKISHA256: "spki-" + digest,
		NotBefore:  t0.AddDate(0, -1, 0),
		NotAfter:   t0.AddDate(0, 2, 0),
		KeyAlg:     "ECDSA-P-256",
	}
}

func TestServiceSnapshots(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	target := newTarget(t, s, "acme")
	scan := newScan(t, s, target, t0)

	leaf := certificate("leaf", "www.acme.example")
	issuer := certificate("issuer", "R11")
	issuer.IsCA, issuer.SANs = true, nil

	// The top bit is set: the value does not fit a signed integer as is.
	simhash := model.SimHash(0xfedcba9876543210)
	favicon := int32(-1874651529)

	secure := serviceSnapshot("https://www.acme.example:443", "www.acme.example", "S1", t0)
	secure.DOMSimHash, secure.FaviconMMH3 = &simhash, &favicon
	secure.Certs = []model.Certificate{leaf, issuer}

	alias := serviceSnapshot("https://acme.example:443", "acme.example", "S2", t0)
	alias.Certs = []model.Certificate{leaf, issuer}

	plain := serviceSnapshot("http://www.acme.example:80", "www.acme.example", "S3", t0)
	plain.FPTLS = ""

	created, err := s.SaveSnapshots(ctx, scan, []Snapshot{
		hostSnapshot("www.acme.example", "H1", t0),
		hostSnapshot("acme.example", "H2", t0),
		secure, alias, plain,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created[model.KindHost] != 2 || created[model.KindService] != 3 {
		t.Errorf("created = %v, want 2 hosts and 3 services", created)
	}
	if n := count(t, s, "certificates"); n != 2 {
		t.Errorf("certificates = %d, want each stored once", n)
	}

	snaps, err := s.HostSnapshots(ctx, scan.ID, "www.acme.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(snaps) != 3 || snaps[0].Kind != model.KindHost || snaps[1].Key != plain.Key || snaps[2].Key != secure.Key {
		t.Fatalf("snapshots of the host = %+v, want the host followed by its services", snaps)
	}

	host, gotPlain, gotSecure := snaps[0], snaps[1], snaps[2]
	if gotSecure.FP != "fp-S1" || gotSecure.FPTLS != "tls-S1" || gotSecure.FPHeaders != "headers-S1" ||
		gotSecure.FPRedirect != "redirect-S1" || gotSecure.FPDOM != "dom-S1" || gotSecure.FPDNS != "" {
		t.Errorf("fingerprints = %+v", gotSecure)
	}
	if gotSecure.DOMSimHash == nil || *gotSecure.DOMSimHash != simhash {
		t.Errorf("simhash = %v, want %v", gotSecure.DOMSimHash, simhash)
	}
	if gotSecure.FaviconMMH3 == nil || *gotSecure.FaviconMMH3 != favicon {
		t.Errorf("favicon = %v, want %d", gotSecure.FaviconMMH3, favicon)
	}
	if gotSecure.CertSHA256 != "leaf" || !slices.Equal(gotSecure.Sources, []string{"probe"}) || gotSecure.Host != "www.acme.example" {
		t.Errorf("secure service = %+v", gotSecure)
	}
	if gotPlain.CertSHA256 != "" || gotPlain.DOMSimHash != nil || gotPlain.FaviconMMH3 != nil || gotPlain.FPTLS != "" {
		t.Errorf("plain service = %+v, want no certificate and no optional values", gotPlain)
	}
	if host.FPDNS != "dns-H1" || host.FPTLS != "" || host.CertSHA256 != "" {
		t.Errorf("host = %+v", host)
	}

	all, err := s.Snapshots(ctx, scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	kinds := make([]model.AssetKind, len(all))
	for i, snap := range all {
		kinds[i] = snap.Kind
	}
	want := []model.AssetKind{model.KindHost, model.KindHost, model.KindService, model.KindService, model.KindService}
	if !slices.Equal(kinds, want) {
		t.Errorf("kinds = %v, want hosts before services", kinds)
	}

	keys, err := s.AssetKeys(ctx, target.ID, model.KindService)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{plain.Key, alias.Key, secure.Key}; !slices.Equal(keys, want) {
		t.Errorf("service keys = %v, want %v", keys, want)
	}
}

func TestCertificates(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	scan := newScan(t, s, newTarget(t, s, "acme"), t0)

	leaf := certificate("leaf", "www.acme.example")
	root := certificate("root", "Example Root")
	root.IsCA, root.SelfSigned, root.SANs, root.IssuerOrg = true, true, nil, ""

	snap := serviceSnapshot("https://www.acme.example:443", "www.acme.example", "S1", t0)
	snap.Certs = []model.Certificate{leaf, root}
	if _, err := s.SaveSnapshots(ctx, scan, []Snapshot{snap}); err != nil {
		t.Fatal(err)
	}

	got, err := s.Certificates(ctx, "leaf", "root", "unknown")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("certificates = %v, want the two on record", got)
	}

	l := got["leaf"]
	if l.SubjectCN != leaf.SubjectCN || l.IssuerCN != leaf.IssuerCN || l.IssuerOrg != leaf.IssuerOrg || l.Serial != leaf.Serial ||
		!slices.Equal(l.SANs, leaf.SANs) || l.SPKISHA256 != leaf.SPKISHA256 || l.KeyAlg != leaf.KeyAlg ||
		!l.NotBefore.Equal(leaf.NotBefore) || !l.NotAfter.Equal(leaf.NotAfter) || l.IsCA || l.SelfSigned {
		t.Errorf("leaf = %+v\nwant   %+v", l, leaf)
	}
	if r := got["root"]; !r.IsCA || !r.SelfSigned || r.SANs != nil || r.IssuerOrg != "" {
		t.Errorf("root = %+v", r)
	}

	none, err := s.Certificates(ctx)
	if err != nil || len(none) != 0 {
		t.Errorf("no digests: %v, %v", none, err)
	}
}

func TestTargetsWithHost(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	for _, name := range []string{"zeta", "acme"} {
		target := newTarget(t, s, name)
		scan := newScan(t, s, target, t0)
		batch := []Snapshot{
			hostSnapshot("shared.example", "H", t0),
			serviceSnapshot("https://shared.example:443", "shared.example", "S", t0),
		}
		if name == "acme" {
			batch = append(batch, hostSnapshot("only.acme.example", "O", t0))
		}
		if _, err := s.SaveSnapshots(ctx, scan, batch); err != nil {
			t.Fatal(err)
		}
	}

	cases := map[string][]string{
		"shared.example":    {"acme", "zeta"},
		"only.acme.example": {"acme"},
		"unknown.example":   nil,
	}
	for host, want := range cases {
		got, err := s.TargetsWithHost(ctx, host)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s: targets = %v, want %v", host, got, want)
		}
	}
}

// A database written under the first schema has to open under the current
// one with everything it held intact.
func TestUpgradeFromFirstSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite", path+"?_foreign_keys=1")
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		migrations[0].sql,
		`PRAGMA user_version = 1`,
		`INSERT INTO targets (id, name, roots, scope, authorized_at, created_at)
		 VALUES (1, 'acme', '["acme.example"]', '{}', '2026-03-01T12:00:00Z', '2026-03-01T12:00:00Z')`,
		`INSERT INTO scans (id, target_id, profile, status, config_hash, fp_version, started_at, finished_at, stats)
		 VALUES (1, 1, 'standard', 'completed', 'cfg', 1, '2026-03-01T12:00:00Z', '2026-03-01T12:01:00Z', '{"hosts":1}')`,
		`INSERT INTO assets (id, target_id, kind, key, host, first_seen_at, last_seen_at)
		 VALUES (1, 1, 'host', 'www.acme.example', 'www.acme.example', '2026-03-01T12:00:00Z', '2026-03-01T12:00:00Z')`,
		`INSERT INTO blobs (hash, data) VALUES ('h1', '{"host":"www.acme.example"}')`,
		`INSERT INTO snapshots (scan_id, asset_id, state, fp, fp_dns, blob_hash, observed_at)
		 VALUES (1, 1, 'live', 'fp-old', 'dns-old', 'h1', '2026-03-01T12:00:30Z')`,
	} {
		if _, err := db.ExecContext(t.Context(), stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s := openStore(t, path)
	ctx := t.Context()

	version, err := s.schemaVersion(ctx, s.db)
	if err != nil {
		t.Fatal(err)
	}
	if want := migrations[len(migrations)-1].version; version != want {
		t.Errorf("schema version = %d, want %d", version, want)
	}

	target, err := s.GetTarget(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	scan, err := s.LatestScan(ctx, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if scan.Stats.Hosts != 1 {
		t.Errorf("stats = %+v", scan.Stats)
	}

	snaps, err := s.Snapshots(ctx, scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(snaps) != 1 {
		t.Fatalf("snapshots = %+v", snaps)
	}
	old := snaps[0]
	if old.FP != "fp-old" || old.FPDNS != "dns-old" || string(old.Data) != `{"host":"www.acme.example"}` {
		t.Errorf("snapshot = %+v, want the stored values", old)
	}
	if old.FPTLS != "" || old.FPHeaders != "" || old.FPRedirect != "" || old.FPDOM != "" ||
		old.DOMSimHash != nil || old.FaviconMMH3 != nil || old.CertSHA256 != "" {
		t.Errorf("snapshot = %+v, want the new columns empty", old)
	}

	// The upgraded database accepts what the current schema adds.
	next := newScan(t, s, target, t0.Add(time.Hour))
	snap := serviceSnapshot("https://www.acme.example:443", "www.acme.example", "S1", t0.Add(time.Hour))
	snap.Certs = []model.Certificate{certificate("leaf", "www.acme.example")}
	if _, err := s.SaveSnapshots(ctx, next, []Snapshot{snap}); err != nil {
		t.Fatal(err)
	}
}
