-- The storage quota also counts objects (with tombstones) and the excess
-- of staged rotation objects over the objects they replace.
ALTER TABLE rotations ADD COLUMN staged_excess INTEGER NOT NULL DEFAULT 0;
CREATE INDEX objects_quota ON objects (vault_id, size);
