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
	Kind       model.AssetKind
	Key        string
	Host       string
	State      model.State
	FP         string
	FPDNS      string
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
	FP          string
	FPDNS       string
	Data        []byte
	ObservedAt  time.Time
}

// SaveSnapshots stores a batch atomically and returns how many assets were
// recorded for the first time.
func (s *Store) SaveSnapshots(ctx context.Context, scan *Scan, batch []Snapshot) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("storage: %w", err)
	}
	defer tx.Rollback()

	created := 0
	for i := range batch {
		isNew, err := saveSnapshot(ctx, tx, scan, &batch[i])
		if err != nil {
			return 0, fmt.Errorf("storage: save snapshot %s: %w", batch[i].Key, err)
		}
		if isNew {
			created++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("storage: save snapshots: %w", err)
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

	sum := sha256.Sum256(snap.Data)
	hash := hex.EncodeToString(sum[:])
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO blobs (hash, data) VALUES (?, ?)`, hash, snap.Data); err != nil {
		return false, err
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO snapshots (scan_id, asset_id, state, fp, fp_dns, blob_hash, observed_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		scan.ID, assetID, snap.State, snap.FP, snap.FPDNS, hash, observed)
	if err != nil {
		return false, err
	}
	return created, nil
}

// Snapshots returns every snapshot of a scan, ordered by asset key.
func (s *Store) Snapshots(ctx context.Context, scanID int64) ([]AssetSnapshot, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id, a.kind, a.key, a.host, a.first_seen_at, a.last_seen_at,
		       (SELECT group_concat(source, ',' ORDER BY source) FROM asset_sources WHERE asset_id = a.id),
		       s.state, s.fp, s.fp_dns, b.data, s.observed_at
		FROM snapshots s
		JOIN assets a ON a.id = s.asset_id
		JOIN blobs b ON b.hash = s.blob_hash
		WHERE s.scan_id = ?
		ORDER BY a.key`, scanID)
	if err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}
	defer rows.Close()

	var out []AssetSnapshot
	for rows.Next() {
		var (
			snap                        AssetSnapshot
			firstSeen, lastSeen, observ string
			sources                     sql.NullString
		)
		err := rows.Scan(&snap.AssetID, &snap.Kind, &snap.Key, &snap.Host, &firstSeen, &lastSeen,
			&sources, &snap.State, &snap.FP, &snap.FPDNS, &snap.Data, &observ)
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
