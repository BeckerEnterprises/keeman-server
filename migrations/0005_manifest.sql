-- Object type `manifest`. SQLite cannot change a CHECK constraint, so the
-- table is rebuilt with the same columns in the same order (`data` last on
-- purpose, see 0001) and its indexes are created again. No table refers to
-- `objects` by foreign key, and there are no triggers or views.

CREATE TABLE objects_new (
  vault_id     TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  id           TEXT NOT NULL,
  type         TEXT NOT NULL CHECK (type IN ('vault_meta', 'group', 'entry', 'icon', 'manifest')),
  revision     INTEGER NOT NULL,
  key_version  INTEGER NOT NULL,
  deleted      INTEGER NOT NULL DEFAULT 0,
  size         INTEGER NOT NULL DEFAULT 0,
  updated_at   TEXT NOT NULL,
  updated_by   TEXT NOT NULL,
  data         BLOB,
  PRIMARY KEY (vault_id, id)
) STRICT;

INSERT INTO objects_new (vault_id, id, type, revision, key_version, deleted, size, updated_at, updated_by, data)
  SELECT vault_id, id, type, revision, key_version, deleted, size, updated_at, updated_by, data FROM objects;

DROP TABLE objects;
ALTER TABLE objects_new RENAME TO objects;

CREATE INDEX objects_by_revision ON objects (vault_id, revision, id);
CREATE INDEX objects_tombstones ON objects (vault_id, updated_at) WHERE deleted = 1;
CREATE INDEX objects_quota ON objects (vault_id, size);
