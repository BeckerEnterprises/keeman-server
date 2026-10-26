-- A random generation per attachment row: a part checks it is still the
-- attachment it saw before its body, also if one with the same ID was
-- deleted and created again within the same millisecond.
ALTER TABLE attachments ADD COLUMN generation TEXT NOT NULL DEFAULT '';
