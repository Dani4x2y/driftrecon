CREATE TABLE targets (
  id            INTEGER PRIMARY KEY,
  name          TEXT NOT NULL UNIQUE,
  roots         TEXT NOT NULL,
  scope         TEXT NOT NULL,
  authorized_at TEXT NOT NULL,
  created_at    TEXT NOT NULL
);

CREATE TABLE scans (
  id          INTEGER PRIMARY KEY,
  target_id   INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  profile     TEXT NOT NULL,
  status      TEXT NOT NULL,
  config_hash TEXT NOT NULL,
  fp_version  INTEGER NOT NULL,
  started_at  TEXT NOT NULL,
  finished_at TEXT,
  stats       TEXT
);

CREATE INDEX idx_scans_target ON scans(target_id, id);

CREATE TABLE assets (
  id            INTEGER PRIMARY KEY,
  target_id     INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  kind          TEXT NOT NULL,
  key           TEXT NOT NULL,
  host          TEXT NOT NULL,
  first_seen_at TEXT NOT NULL,
  last_seen_at  TEXT NOT NULL,
  UNIQUE (target_id, kind, key)
);

CREATE TABLE asset_sources (
  asset_id      INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  source        TEXT NOT NULL,
  first_seen_at TEXT NOT NULL,
  PRIMARY KEY (asset_id, source)
) WITHOUT ROWID;

-- Observations are stored once per distinct content. An asset that does not
-- change between scans keeps pointing at the same row.
CREATE TABLE blobs (
  hash TEXT PRIMARY KEY,
  data BLOB NOT NULL
);

CREATE TABLE snapshots (
  scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  asset_id    INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  state       TEXT NOT NULL,
  fp          TEXT NOT NULL,
  fp_dns      TEXT NOT NULL DEFAULT '',
  blob_hash   TEXT NOT NULL REFERENCES blobs(hash),
  observed_at TEXT NOT NULL,
  PRIMARY KEY (scan_id, asset_id)
);

CREATE INDEX idx_snapshots_asset ON snapshots(asset_id, scan_id);
