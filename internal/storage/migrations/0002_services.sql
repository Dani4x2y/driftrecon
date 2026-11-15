-- Certificates are stored once and shared by every snapshot that saw them.
CREATE TABLE certificates (
  sha256      TEXT PRIMARY KEY,
  subject_cn  TEXT NOT NULL,
  issuer_cn   TEXT NOT NULL,
  issuer_org  TEXT NOT NULL,
  serial      TEXT NOT NULL,
  sans        TEXT NOT NULL,
  spki_sha256 TEXT NOT NULL,
  not_before  TEXT NOT NULL,
  not_after   TEXT NOT NULL,
  key_alg     TEXT NOT NULL,
  is_ca       INTEGER NOT NULL,
  self_signed INTEGER NOT NULL
);

ALTER TABLE snapshots ADD COLUMN fp_tls TEXT NOT NULL DEFAULT '';
ALTER TABLE snapshots ADD COLUMN fp_headers TEXT NOT NULL DEFAULT '';
ALTER TABLE snapshots ADD COLUMN fp_redirect TEXT NOT NULL DEFAULT '';
ALTER TABLE snapshots ADD COLUMN fp_dom TEXT NOT NULL DEFAULT '';

-- Copies of values from the observation, kept as columns so that services
-- can be compared with each other without decoding every document.
ALTER TABLE snapshots ADD COLUMN dom_simhash INTEGER;
ALTER TABLE snapshots ADD COLUMN favicon_mmh3 INTEGER;

-- The certificate of the service itself, the first of the presented chain.
ALTER TABLE snapshots ADD COLUMN cert_sha256 TEXT REFERENCES certificates(sha256);

CREATE INDEX idx_snapshots_cert ON snapshots(cert_sha256) WHERE cert_sha256 IS NOT NULL;
