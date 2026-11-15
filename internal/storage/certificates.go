package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Dani4x2y/driftrecon/internal/model"
)

func saveCertificates(ctx context.Context, tx *sql.Tx, certs []model.Certificate) error {
	for _, c := range certs {
		sans, err := json.Marshal(c.SANs)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `
			INSERT OR IGNORE INTO certificates (sha256, subject_cn, issuer_cn, issuer_org, serial, sans, spki_sha256,
			                                    not_before, not_after, key_alg, is_ca, self_signed)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			c.SHA256, c.SubjectCN, c.IssuerCN, c.IssuerOrg, c.Serial, string(sans), c.SPKISHA256,
			formatTime(c.NotBefore), formatTime(c.NotAfter), c.KeyAlg, c.IsCA, c.SelfSigned)
		if err != nil {
			return fmt.Errorf("certificate %s: %w", c.SHA256, err)
		}
	}
	return nil
}

// Certificates returns the stored certificates with the given SHA-256
// digests, keyed by digest. Digests that are not on record are left out.
func (s *Store) Certificates(ctx context.Context, digests ...string) (map[string]model.Certificate, error) {
	out := make(map[string]model.Certificate, len(digests))
	if len(digests) == 0 {
		return out, nil
	}

	args := make([]any, len(digests))
	for i, d := range digests {
		args[i] = d
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT sha256, subject_cn, issuer_cn, issuer_org, serial, sans, spki_sha256,
		       not_before, not_after, key_alg, is_ca, self_signed
		FROM certificates
		WHERE sha256 IN (?`+strings.Repeat(", ?", len(digests)-1)+`)`, args...)
	if err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			c                         model.Certificate
			sans, notBefore, notAfter string
		)
		err := rows.Scan(&c.SHA256, &c.SubjectCN, &c.IssuerCN, &c.IssuerOrg, &c.Serial, &sans, &c.SPKISHA256,
			&notBefore, &notAfter, &c.KeyAlg, &c.IsCA, &c.SelfSigned)
		if err != nil {
			return nil, fmt.Errorf("storage: %w", err)
		}
		if err := json.Unmarshal([]byte(sans), &c.SANs); err != nil {
			return nil, fmt.Errorf("storage: certificate %s: malformed names: %w", c.SHA256, err)
		}
		if c.NotBefore, err = parseTime(notBefore); err != nil {
			return nil, err
		}
		if c.NotAfter, err = parseTime(notAfter); err != nil {
			return nil, err
		}
		out[c.SHA256] = c
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}
	return out, nil
}
