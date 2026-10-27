-- Signed roles: the public signing key of each account (NULL until an
-- older account adds it) and the owner-signed roles chain of each vault.
-- Statements are the canonical bytes in plain text; the hash is kept to
-- compare it with the `previous` field of the next statement.

ALTER TABLE users ADD COLUMN signing_public_key BLOB;

CREATE TABLE vault_roles (
  vault_id    TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  version     INTEGER NOT NULL,
  statement   BLOB NOT NULL,
  signature   BLOB NOT NULL,
  hash        BLOB NOT NULL,
  created_at  TEXT NOT NULL,
  PRIMARY KEY (vault_id, version)
) STRICT;
