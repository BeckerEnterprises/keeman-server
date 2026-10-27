-- Freshness attestations and device pairing. An attestation is the
-- canonical statement bytes in plain text with the Ed25519 signature of the
-- account that made it; each account keeps its latest one per vault and one
-- for its user data. A pairing is an envelope the server can neither read
-- nor forge, one per account, valid for a few minutes.

CREATE TABLE vault_freshness (
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  vault_id    TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  statement   BLOB NOT NULL,
  signature   BLOB NOT NULL,
  updated_at  TEXT NOT NULL,
  PRIMARY KEY (user_id, vault_id)
) STRICT;

CREATE TABLE user_freshness (
  user_id     TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  statement   BLOB NOT NULL,
  signature   BLOB NOT NULL,
  updated_at  TEXT NOT NULL
) STRICT;

CREATE TABLE pairings (
  user_id     TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  payload     BLOB NOT NULL,
  created_at  TEXT NOT NULL,
  expires_at  TEXT NOT NULL
) STRICT;
CREATE INDEX pairings_by_expiry ON pairings(expires_at);
