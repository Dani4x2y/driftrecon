package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Dani4x2y/driftrecon/internal/scope"
)

// Target is a named set of root domains with scope rules.
type Target struct {
	ID           int64
	Name         string
	Rules        scope.Rules
	AuthorizedAt time.Time
	CreatedAt    time.Time
}

// TargetSummary adds scan activity to a target for listings.
type TargetSummary struct {
	Target
	Scans      int
	Hosts      int
	LastScanAt time.Time
}

type scopeDoc struct {
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}

const targetColumns = `id, name, roots, scope, authorized_at, created_at`

// CreateTarget stores a new target. The caller asserts being authorised to
// assess the roots; now is recorded as the time of that assertion.
func (s *Store) CreateTarget(ctx context.Context, name string, rules scope.Rules, now time.Time) (*Target, error) {
	roots, err := json.Marshal(rules.Roots)
	if err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}
	doc, err := json.Marshal(scopeDoc{Include: rules.Include, Exclude: rules.Exclude})
	if err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}
	defer tx.Rollback()

	var exists bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM targets WHERE name = ?)`, name).Scan(&exists)
	if err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("target %q: %w", name, ErrExists)
	}

	ts := formatTime(now)
	res, err := tx.ExecContext(ctx,
		`INSERT INTO targets (name, roots, scope, authorized_at, created_at) VALUES (?, ?, ?, ?, ?)`,
		name, string(roots), string(doc), ts, ts)
	if err != nil {
		return nil, fmt.Errorf("storage: create target: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("storage: create target: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("storage: create target: %w", err)
	}

	stored := now.UTC().Truncate(time.Second)
	return &Target{ID: id, Name: name, Rules: rules, AuthorizedAt: stored, CreatedAt: stored}, nil
}

// GetTarget looks a target up by name.
func (s *Store) GetTarget(ctx context.Context, name string) (*Target, error) {
	var (
		t                               Target
		roots, doc, authorized, created string
	)
	err := s.db.QueryRowContext(ctx, `SELECT `+targetColumns+` FROM targets WHERE name = ?`, name).
		Scan(&t.ID, &t.Name, &roots, &doc, &authorized, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("target %q: %w", name, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}
	if err := decodeTarget(&t, roots, doc, authorized, created); err != nil {
		return nil, err
	}
	return &t, nil
}

// ListTargets returns all targets ordered by name.
func (s *Store) ListTargets(ctx context.Context) ([]TargetSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+targetColumns+`,
		       (SELECT count(*) FROM scans WHERE target_id = targets.id),
		       (SELECT count(*) FROM assets WHERE target_id = targets.id AND kind = 'host'),
		       (SELECT max(started_at) FROM scans WHERE target_id = targets.id)
		FROM targets
		ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}
	defer rows.Close()

	var out []TargetSummary
	for rows.Next() {
		var (
			t                               TargetSummary
			roots, doc, authorized, created string
			lastScan                        sql.NullString
		)
		err := rows.Scan(&t.ID, &t.Name, &roots, &doc, &authorized, &created, &t.Scans, &t.Hosts, &lastScan)
		if err != nil {
			return nil, fmt.Errorf("storage: %w", err)
		}
		if err := decodeTarget(&t.Target, roots, doc, authorized, created); err != nil {
			return nil, err
		}
		if lastScan.Valid {
			if t.LastScanAt, err = parseTime(lastScan.String); err != nil {
				return nil, err
			}
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}
	return out, nil
}

func decodeTarget(t *Target, roots, doc, authorized, created string) error {
	if err := json.Unmarshal([]byte(roots), &t.Rules.Roots); err != nil {
		return fmt.Errorf("storage: target %q: malformed roots: %w", t.Name, err)
	}
	var sd scopeDoc
	if err := json.Unmarshal([]byte(doc), &sd); err != nil {
		return fmt.Errorf("storage: target %q: malformed scope: %w", t.Name, err)
	}
	t.Rules.Include, t.Rules.Exclude = sd.Include, sd.Exclude

	var err error
	if t.AuthorizedAt, err = parseTime(authorized); err != nil {
		return err
	}
	if t.CreatedAt, err = parseTime(created); err != nil {
		return err
	}
	return nil
}
