package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Dani4x2y/driftrecon/internal/model"
)

// Snapshot is the state of one asset as observed by one scan.
type Snapshot struct {
	Kind  model.AssetKind
	Key   string
	Host  string
	State model.State

	// FP is the composite fingerprint. The others hold one layer each and
	// are empty for layers that were not observed.
	FP         string
	FPDNS      string
	FPTLS      string
	FPHeaders  string
	FPRedirect string
	FPDOM      string

	// DOMSimHash and FaviconMMH3 repeat values from the observation.
	DOMSimHash  *model.SimHash
	FaviconMMH3 *int32
	// Certs are the certificates the observation refers to. The first one
	// is recorded as the certificate of the asset.
	Certs []model.Certificate

	Data       []byte
	ObservedAt time.Time

	// Sources lists the discovery sources that reported the asset in this
	// scan. They accumulate on the asset across scans.
	Sources []string
	// Seen marks the asset as positively observed, as opposed to carried
	// over from an earlier scan without fresh evidence.
	Seen bool
}

// AssetSnapshot joins a snapshot with the asset it describes.
type AssetSnapshot struct {
	AssetID     int64
	Kind        model.AssetKind
	Key         string
	Host        string
	FirstSeenAt time.Time
	LastSeenAt  time.Time
	Sources     []string
	State       model.State

	FP         string
	FPDNS      string
	FPTLS      string
	FPHeaders  string
	FPRedirect string
	FPDOM      string

	DOMSimHash  *model.SimHash
	FaviconMMH3 *int32
	// CertSHA256 identifies the certificate of the asset, if it has one.
	CertSHA256 string

	Data       []byte
	ObservedAt time.Time
}

// SaveSnapshots stores a batch atomically and returns how many assets of
// each kind were recorded for the first time.
func (s *Store) SaveSnapshots(ctx context.Context, scan *Scan, batch []Snapshot) (map[model.AssetKind]int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}
	defer tx.Rollback()

	created := make(map[model.AssetKind]int)
	for i := range batch {
		isNew, err := saveSnapshot(ctx, tx, scan, &batch[i])
		if err != nil {
			return nil, fmt.Errorf("storage: save snapshot %s: %w", batch[i].Key, err)
		}
		if isNew {
			created[batch[i].Kind]++
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("storage: save snapshots: %w", err)
	}
	return created, nil
}

func saveSnapshot(ctx context.Context, tx *sql.Tx, scan *Scan, snap *Snapshot) (created bool, err error) {
	if len(snap.Data) == 0 {
		return false, errors.New("empty observation")
	}
	observed := formatTime(snap.ObservedAt)

	var assetID int64
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM assets WHERE target_id = ? AND kind = ? AND key = ?`,
		scan.TargetID, snap.Kind, snap.Key).Scan(&assetID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		res, err := tx.ExecContext(ctx,
			`INSERT INTO assets (target_id, kind, key, host, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)`,
			scan.TargetID, snap.Kind, snap.Key, snap.Host, observed, observed)
		if err != nil {
			return false, err
		}
		if assetID, err = res.LastInsertId(); err != nil {
			return false, err
		}
		created = true
	case err != nil:
		return false, err
	case snap.Seen:
		if _, err := tx.ExecContext(ctx, `UPDATE assets SET last_seen_at = ? WHERE id = ?`, observed, assetID); err != nil {
			return false, err
		}
	}

	for _, source := range snap.Sources {
		_, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO asset_sources (asset_id, source, first_seen_at) VALUES (?, ?, ?)`,
			assetID, source, observed)
		if err != nil {
			return false, err
		}
	}

	var cert sql.NullString
	if len(snap.Certs) > 0 {
		if err := saveCertificates(ctx, tx, snap.Certs); err != nil {
			return false, err
		}
		cert = sql.NullString{String: snap.Certs[0].SHA256, Valid: true}
	}

	sum := sha256.Sum256(snap.Data)
	hash := hex.EncodeToString(sum[:])
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO blobs (hash, data) VALUES (?, ?)`, hash, snap.Data); err != nil {
		return false, err
	}

	// SQLite integers are signed, so the SimHash is stored as the signed
	// number with the same 64 bits.
	var simhash, favicon sql.NullInt64
	if snap.DOMSimHash != nil {
		simhash = sql.NullInt64{Int64: int64(*snap.DOMSimHash), Valid: true}
	}
	if snap.FaviconMMH3 != nil {
		favicon = sql.NullInt64{Int64: int64(*snap.FaviconMMH3), Valid: true}
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO snapshots (scan_id, asset_id, state, fp, fp_dns, fp_tls, fp_headers, fp_redirect, fp_dom,
		                       dom_simhash, favicon_mmh3, cert_sha256, blob_hash, observed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		scan.ID, assetID, snap.State, snap.FP, snap.FPDNS, snap.FPTLS, snap.FPHeaders, snap.FPRedirect, snap.FPDOM,
		simhash, favicon, cert, hash, observed)
	if err != nil {
		return false, err
	}
	return created, nil
}

// Snapshots returns every snapshot of a scan, hosts first, ordered by key.
func (s *Store) Snapshots(ctx context.Context, scanID int64) ([]AssetSnapshot, error) {
	return s.snapshots(ctx, `s.scan_id = ?`, scanID)
}

// HostSnapshots returns the snapshots a scan holds for one host: the host
// itself and the services on it.
func (s *Store) HostSnapshots(ctx context.Context, scanID int64, host string) ([]AssetSnapshot, error) {
	return s.snapshots(ctx, `s.scan_id = ? AND a.host = ?`, scanID, host)
}

func (s *Store) snapshots(ctx context.Context, where string, args ...any) ([]AssetSnapshot, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id, a.kind, a.key, a.host, a.first_seen_at, a.last_seen_at,
		       (SELECT group_concat(source, ',' ORDER BY source) FROM asset_sources WHERE asset_id = a.id),
		       s.state, s.fp, s.fp_dns, s.fp_tls, s.fp_headers, s.fp_redirect, s.fp_dom,
		       s.dom_simhash, s.favicon_mmh3, s.cert_sha256, b.data, s.observed_at
		FROM snapshots s
		JOIN assets a ON a.id = s.asset_id
		JOIN blobs b ON b.hash = s.blob_hash
		WHERE `+where+`
		ORDER BY a.kind, a.key`, args...)
	if err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}
	defer rows.Close()

	var out []AssetSnapshot
	for rows.Next() {
		var (
			snap                        AssetSnapshot
			firstSeen, lastSeen, observ string
			sources, cert               sql.NullString
			simhash, favicon            sql.NullInt64
		)
		err := rows.Scan(&snap.AssetID, &snap.Kind, &snap.Key, &snap.Host, &firstSeen, &lastSeen,
			&sources, &snap.State, &snap.FP, &snap.FPDNS, &snap.FPTLS, &snap.FPHeaders, &snap.FPRedirect, &snap.FPDOM,
			&simhash, &favicon, &cert, &snap.Data, &observ)
		if err != nil {
			return nil, fmt.Errorf("storage: %w", err)
		}
		if snap.FirstSeenAt, err = parseTime(firstSeen); err != nil {
			return nil, err
		}
		if snap.LastSeenAt, err = parseTime(lastSeen); err != nil {
			return nil, err
		}
		if snap.ObservedAt, err = parseTime(observ); err != nil {
			return nil, err
		}
		if sources.Valid && sources.String != "" {
			snap.Sources = strings.Split(sources.String, ",")
		}
		if simhash.Valid {
			snap.DOMSimHash = new(model.SimHash(simhash.Int64))
		}
		if favicon.Valid {
			snap.FaviconMMH3 = new(int32(favicon.Int64))
		}
		snap.CertSHA256 = cert.String
		out = append(out, snap)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}
	return out, nil
}

// AssetKeys returns the keys of all assets of one kind known for a target,
// regardless of which scan found them.
func (s *Store) AssetKeys(ctx context.Context, targetID int64, kind model.AssetKind) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT key FROM assets WHERE target_id = ? AND kind = ? ORDER BY key`, targetID, kind)
	if err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, fmt.Errorf("storage: %w", err)
		}
		out = append(out, key)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}
	return out, nil
}

// TargetsWithHost returns the names of the targets that track host, sorted.
func (s *Store) TargetsWithHost(ctx context.Context, host string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT t.name
		FROM assets a
		JOIN targets t ON t.id = a.target_id
		WHERE a.host = ?
		ORDER BY t.name`, host)
	if err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("storage: %w", err)
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}
	return out, nil
}
