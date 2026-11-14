package storage

import (
	"context"
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
		Hosts:     3,
		States:    map[model.State]int{model.StateLive: 2, model.StateUnresolved: 1},
		NewAssets: 3,
		Sources:   []model.SourceStat{{Source: "crtsh", Domain: "acme.example", Names: 3}},
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
	if created != 2 {
		t.Errorf("first scan created %d assets, want 2", created)
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
	if created != 0 {
		t.Errorf("second scan created %d assets, want 0", created)
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
		if created != 1 {
			t.Errorf("target %s: created = %d, want 1", target.Name, created)
		}
	}
	if n := count(t, s, "assets"); n != 2 {
		t.Errorf("assets = %d, want one per target", n)
	}
	if n := count(t, s, "blobs"); n != 1 {
		t.Errorf("blobs = %d, want identical content shared across targets", n)
	}
}
