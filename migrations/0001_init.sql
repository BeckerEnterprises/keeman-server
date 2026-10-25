-- KeeMan schema. Released migrations are never edited; schema changes come
-- as new migrations.

CREATE TABLE users (
  id                        TEXT PRIMARY KEY,
  email                     TEXT NOT NULL UNIQUE,             -- normalised: trimmed, NFC, lower case
  kdf_params                TEXT NOT NULL,                    -- JSON
  kdf_salt                  BLOB NOT NULL,
  auth_hash                 TEXT NOT NULL,                    -- Argon2id PHC string
  user_key_wrapped          BLOB NOT NULL,
  public_key                BLOB NOT NULL,
  private_key_wrapped       BLOB NOT NULL,
  user_data                 BLOB NOT NULL,
  user_data_revision        INTEGER NOT NULL DEFAULT 1,
  recovery_auth_hash        TEXT NOT NULL,
  user_key_recovery_wrapped BLOB NOT NULL,
  totp_secret_enc           BLOB,                             -- NULL = not set up
  totp_enabled              INTEGER NOT NULL DEFAULT 0,
  totp_last_step            INTEGER,
  disabled                  INTEGER NOT NULL DEFAULT 0,
  last_login_at             TEXT,
  created_at                TEXT NOT NULL,
  updated_at                TEXT NOT NULL
) STRICT;

CREATE TABLE webauthn_credentials (
  id                    TEXT PRIMARY KEY,
  user_id               TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id         BLOB NOT NULL UNIQUE,
  passkey               TEXT NOT NULL,
  name                  TEXT NOT NULL,
  prf_wrapped_user_key  BLOB,
  created_at            TEXT NOT NULL,
  last_used_at          TEXT
) STRICT;
CREATE INDEX webauthn_credentials_by_user ON webauthn_credentials (user_id);

CREATE TABLE backup_codes (
  id        INTEGER PRIMARY KEY,
  user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  used_at   TEXT
) STRICT;
CREATE INDEX backup_codes_by_user ON backup_codes (user_id);

CREATE TABLE sessions (
  id                  TEXT PRIMARY KEY,
  user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_name         TEXT NOT NULL,
  client_type         TEXT NOT NULL CHECK (client_type IN ('web', 'desktop', 'mobile', 'cli')),
  refresh_expires_at  TEXT NOT NULL,                          -- sliding
  ip_hint             TEXT,
  created_at          TEXT NOT NULL,
  last_seen_at        TEXT NOT NULL,
  revoked_at          TEXT
) STRICT;
CREATE INDEX sessions_by_user ON sessions (user_id);

-- Current and all superseded refresh tokens of a session; reusing a
-- superseded one revokes the session.
CREATE TABLE refresh_tokens (
  token_hash     BLOB PRIMARY KEY,
  session_id     TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  created_at     TEXT NOT NULL,
  superseded_at  TEXT                                         -- NULL = current token
) STRICT;
CREATE INDEX refresh_tokens_by_session ON refresh_tokens (session_id);

CREATE TABLE access_tokens (
  token_hash  BLOB PRIMARY KEY,
  session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  expires_at  TEXT NOT NULL
) STRICT;
CREATE INDEX access_tokens_by_session ON access_tokens (session_id);
CREATE INDEX access_tokens_by_expiry ON access_tokens (expires_at);

-- Failed attempts per e-mail HMAC, also for unknown addresses, so a lockout
-- does not reveal whether an account exists.
CREATE TABLE login_throttle (
  email_hmac    BLOB PRIMARY KEY,
  failures      INTEGER NOT NULL DEFAULT 0,
  locked_until  TEXT,
  updated_at    TEXT NOT NULL
) STRICT;

CREATE TABLE challenges (
  token_hash  BLOB PRIMARY KEY,
  purpose     TEXT NOT NULL CHECK (purpose IN ('login', 'recovery', 'recovery_finish', 'reauth', 'webauthn_register', 'totp_setup')),
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_id  TEXT REFERENCES sessions(id) ON DELETE CASCADE,
  state       TEXT,
  attempts    INTEGER NOT NULL DEFAULT 0,
  expires_at  TEXT NOT NULL
) STRICT;
CREATE INDEX challenges_by_user ON challenges (user_id, purpose);
CREATE INDEX challenges_by_expiry ON challenges (expires_at);

CREATE TABLE invites (
  id          TEXT PRIMARY KEY,
  code_hash   BLOB NOT NULL UNIQUE,
  note        TEXT,
  created_at  TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  used_by     TEXT REFERENCES users(id) ON DELETE SET NULL,
  used_at     TEXT
) STRICT;

CREATE TABLE security_log (
  id        INTEGER PRIMARY KEY,
  ts        TEXT NOT NULL,
  user_id   TEXT,
  vault_id  TEXT,
  event     TEXT NOT NULL,
  ip_hint   TEXT,
  detail    TEXT                                              -- JSON, never secrets
) STRICT;
CREATE INDEX security_log_by_ts ON security_log (ts);

CREATE TABLE vaults (
  id                 TEXT PRIMARY KEY,
  revision           INTEGER NOT NULL,
  key_version        INTEGER NOT NULL,
  rotation_required  INTEGER NOT NULL DEFAULT 0,
  tombstone_horizon  INTEGER NOT NULL DEFAULT 0,              -- highest revision of a purged tombstone
  created_by         TEXT NOT NULL,                           -- no foreign key: shared vaults outlive accounts
  created_at         TEXT NOT NULL
) STRICT;

CREATE TABLE memberships (
  vault_id               TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  user_id                TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role                   TEXT NOT NULL CHECK (role IN ('owner', 'member')),
  state                  TEXT NOT NULL CHECK (state IN ('pending', 'active')),
  key_version            INTEGER NOT NULL,
  key_wrapped            BLOB,                                -- active: AEAD(UK, VK)
  key_box                BLOB,                                -- pending: invitation
  sender_id              TEXT,                                -- inviter; NULL for the creator
  pending_key_box        BLOB,                                -- after a rotation
  pending_key_version    INTEGER,
  pending_key_sender_id  TEXT,
  created_at             TEXT NOT NULL,
  PRIMARY KEY (vault_id, user_id)
) STRICT;
CREATE INDEX memberships_by_user ON memberships (user_id);

-- `data` is the last column: reading the metadata of a row never touches the
-- overflow pages of a large object (page budget of `changes`).
CREATE TABLE objects (
  vault_id     TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  id           TEXT NOT NULL,
  type         TEXT NOT NULL CHECK (type IN ('vault_meta', 'group', 'entry', 'icon')),
  revision     INTEGER NOT NULL,
  key_version  INTEGER NOT NULL,
  deleted      INTEGER NOT NULL DEFAULT 0,
  size         INTEGER NOT NULL DEFAULT 0,                    -- decoded bytes of `data`
  updated_at   TEXT NOT NULL,
  updated_by   TEXT NOT NULL,
  data         BLOB,                                          -- encrypted object or tombstone; NULL only when dropped by a rotation
  PRIMARY KEY (vault_id, id)
) STRICT;
CREATE INDEX objects_by_revision ON objects (vault_id, revision, id);
CREATE INDEX objects_tombstones ON objects (vault_id, updated_at) WHERE deleted = 1;

CREATE TABLE rotations (
  id               TEXT PRIMARY KEY,
  vault_id         TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  base_revision    INTEGER NOT NULL,
  new_key_version  INTEGER NOT NULL,
  created_by       TEXT NOT NULL,
  expires_at       TEXT NOT NULL
) STRICT;
CREATE INDEX rotations_by_vault ON rotations (vault_id);
CREATE INDEX rotations_by_expiry ON rotations (expires_at);

CREATE TABLE rotation_objects (
  rotation_id  TEXT NOT NULL REFERENCES rotations(id) ON DELETE CASCADE,
  id           TEXT NOT NULL,
  type         TEXT NOT NULL,
  data         BLOB NOT NULL,
  PRIMARY KEY (rotation_id, id)
) STRICT;

-- Never stores answers that contain tokens.
CREATE TABLE idempotency (
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key           TEXT NOT NULL,
  endpoint      TEXT NOT NULL,                                -- method and concrete path
  request_hash  BLOB NOT NULL,                                -- SHA-256 of the raw body
  status        INTEGER NOT NULL,
  response      BLOB NOT NULL,                                -- success JSON or problem without `instance`
  created_at    TEXT NOT NULL,
  PRIMARY KEY (user_id, key)
) STRICT;
CREATE INDEX idempotency_by_created ON idempotency (created_at);

-- `size` is the size of the encrypted blob; the file key never reaches the
-- server. The blob lives in data_dir/attachments/ once complete.
CREATE TABLE attachments (
  id            TEXT PRIMARY KEY,
  vault_id      TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  entry_id      TEXT NOT NULL,                                -- only checked for format
  size          INTEGER NOT NULL,
  parts         INTEGER NOT NULL,
  state         TEXT NOT NULL CHECK (state IN ('uploading', 'complete')),
  created_by    TEXT NOT NULL,                                -- no foreign key: attachments outlive accounts
  created_at    TEXT NOT NULL,
  completed_at  TEXT
) STRICT;
CREATE INDEX attachments_by_entry ON attachments (vault_id, entry_id);
CREATE INDEX attachments_by_state ON attachments (state, created_at);
