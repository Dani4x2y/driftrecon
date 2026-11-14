package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Dani4x2y/driftrecon/internal/model"
)

// ScanStatus is the lifecycle state of a scan.
type ScanStatus string

const (
	ScanRunning   ScanStatus = "running"
	ScanCompleted ScanStatus = "completed"
	// ScanAborted marks a scan that was interrupted or ran out of time. Its
	// snapshots are incomplete and must not serve as a baseline.
	ScanAborted ScanStatus = "aborted"
	ScanFailed  ScanStatus = "failed"
)

// Scan is one run of the pipeline against a target.
type Scan struct {
	ID         int64
	TargetID   int64
	Profile    model.Profile
	Status     ScanStatus
	ConfigHash string
	FPVersion  int
	StartedAt  time.Time
	FinishedAt time.Time
	Stats      model.ScanStats
}

const scanColumns = `id, target_id, profile, status, config_hash, fp_version, started_at, finished_at, stats`

// BeginScan records the start of a scan.
func (s *Store) BeginScan(ctx context.Context, targetID int64, profile model.Profile, configHash string, fpVersion int, now time.Time) (*Scan, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO scans (target_id, profile, status, config_hash, fp_version, started_at) VALUES (?, ?, ?, ?, ?, ?)`,
		targetID, profile, ScanRunning, configHash, fpVersion, formatTime(now))
	if err != nil {
		return nil, fmt.Errorf("storage: begin scan: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("storage: begin scan: %w", err)
	}
	return &Scan{
		ID:         id,
		TargetID:   targetID,
		Profile:    profile,
		Status:     ScanRunning,
		ConfigHash: configHash,
		FPVersion:  fpVersion,
		StartedAt:  now.UTC().Truncate(time.Second),
	}, nil
}

// FinishScan closes a scan and updates scan to match what was stored.
func (s *Store) FinishScan(ctx context.Context, scan *Scan, status ScanStatus, stats model.ScanStats, now time.Time) error {
	doc, err := json.Marshal(stats)
	if err != nil {
		return fmt.Errorf("storage: finish scan: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE scans SET status = ?, finished_at = ?, stats = ? WHERE id = ?`,
		status, formatTime(now), string(doc), scan.ID)
	if err != nil {
		return fmt.Errorf("storage: finish scan: %w", err)
	}
	scan.Status = status
	scan.FinishedAt = now.UTC().Truncate(time.Second)
	scan.Stats = stats
	return nil
}

// GetScan returns one scan of a target.
func (s *Store) GetScan(ctx context.Context, targetID, scanID int64) (*Scan, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+scanColumns+` FROM scans WHERE target_id = ? AND id = ?`, targetID, scanID)
	scan, err := scanScan(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("scan %d: %w", scanID, ErrNotFound)
	}
	return scan, err
}

// LatestScan returns the most recent completed scan of a target.
func (s *Store) LatestScan(ctx context.Context, targetID int64) (*Scan, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+scanColumns+` FROM scans WHERE target_id = ? AND status = ? ORDER BY id DESC LIMIT 1`,
		targetID, ScanCompleted)
	scan, err := scanScan(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("completed scan: %w", ErrNotFound)
	}
	return scan, err
}

func scanScan(row *sql.Row) (*Scan, error) {
	var (
		scan            Scan
		started         string
		finished, stats sql.NullString
	)
	err := row.Scan(&scan.ID, &scan.TargetID, &scan.Profile, &scan.Status, &scan.ConfigHash,
		&scan.FPVersion, &started, &finished, &stats)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}

	if scan.StartedAt, err = parseTime(started); err != nil {
		return nil, err
	}
	if finished.Valid {
		if scan.FinishedAt, err = parseTime(finished.String); err != nil {
			return nil, err
		}
	}
	if stats.Valid {
		if err := json.Unmarshal([]byte(stats.String), &scan.Stats); err != nil {
			return nil, fmt.Errorf("storage: scan %d: malformed stats: %w", scan.ID, err)
		}
	}
	return &scan, nil
}
