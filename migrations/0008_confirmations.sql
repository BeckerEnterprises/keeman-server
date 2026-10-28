-- Confirmation by another device replaces the pairing by code. A device
-- asks the other sessions of its account with a nonce; one of them answers
-- with a signed statement. One request per session, valid for a few
-- minutes; the answer is the canonical statement bytes in plain text with
-- the Ed25519 signature of the account.

DROP TABLE pairings;

CREATE TABLE confirmations (
  id                TEXT PRIMARY KEY,
  user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_id        TEXT NOT NULL UNIQUE REFERENCES sessions(id) ON DELETE CASCADE,
  nonce             BLOB NOT NULL,
  created_at        TEXT NOT NULL,
  expires_at        TEXT NOT NULL,
  answer_statement  BLOB,
  answer_signature  BLOB
) STRICT;
CREATE INDEX confirmations_by_user ON confirmations(user_id);
CREATE INDEX confirmations_by_expiry ON confirmations(expires_at);
