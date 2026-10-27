# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

Upgrading: the migration `0005_manifest.sql` runs on start and rebuilds the `objects` table, which briefly needs about twice its size on disk; back up first. An older binary does not start with the migrated database. Web clients opened before the update stop syncing a vault once it has a manifest and their saves are refused with `422`; reloading the page fixes this.

The migration `0006_roles.sql` adds the column `users.signing_public_key` and the table `vault_roles`; existing accounts keep working without a signing key until their client adds it. Web clients opened before the update cannot register (the signing key is required) or create vaults (the first roles statement is required), and once a vault has a roles chain their role changes and key rotations are refused with `422 roles_required`; reloading the page fixes this.

### Added

- Signed roles: every account has a public Ed25519 signing key (`signing_public_key`, required at registration, reported by `GET /v1/me`, user lookup, `public-key` and the member list). Accounts from before add it once with `PUT /v1/me/signing-key` (needs reauth; the same key again is `204`, another one `409 conflict`; security log `signing_key_set`).
- Each vault keeps an owner-signed roles chain in `vault_roles`: statements naming the owners with their keys and committing to the vault key of their key version. `POST /v1/vaults` requires the first statement; role changes (`PATCH …/members/{user_id}`) and rotation commits carry the next one once a chain exists, otherwise `422 roles_required`; `POST /v1/vaults/{id}/roles` adds the first statement of an older vault or one that only drops owners who are gone. `GET /v1/vaults/{id}/roles?since=` serves the chain to members and invitees, and the vault list reports `roles_version`.
- Every new statement is checked in the writing transaction: canonical bytes, following the stored head (`409 roles_conflict` with `current_roles_version`), signed by the caller as an owner of the head (Ed25519 through `ring`, already in the tree through `rustls`), naming exactly the active owners afterwards with their registered keys, and the vault's key version. Promoting an account without a signing key gives `409 signing_key_missing`. Answers of the check are stored for the idempotency key. Security log `roles_changed`.
- An owner of a vault with a roles chain demotes itself before leaving it or deleting the account, otherwise `409 owner_must_demote`.
- `check` reports roles chains with gaps in their versions or statements that do not link to their predecessor.
- `GET /v1/config` reports `features.roles`.
- Object type `manifest` for the authenticated vault manifest that clients keep in every vault: an encrypted list of all live objects, so a server can no longer withhold or replay objects unnoticed. The server stores it like any other object and never reads it.
- Manifest objects are allowed only under 65 IDs derived from the vault ID (BLAKE2b, crate `blake2`), and no other type may use these IDs; they can be neither deleted nor dropped in a key rotation (`400`).
- Once a vault has a manifest root, every batch must write it, otherwise `422 manifest_required` (stored for the idempotency key). An outdated client can then no longer change objects behind the manifest.
- `GET /v1/config` reports `features.manifest`.

## [0.1.1] - 2026-10-26

Security release after a code review and a whitebox security audit of 0.1.0. KeeMan is still in early development: do not use it with real passwords yet.

Upgrading: the migrations `0002_quota.sql`, `0003_limits.sql` and `0004_attachment_generation.sql` run on start; back up first. The new limits have defaults and need no configuration. `backup` now ends with exit code 3 when attachment files are missing, which monitoring may report as a failure.

### Security

- A login lockout that begins while a credential check is still running now applies to that check: a failure or success during a lock changes nothing, so parallel guesses can no longer lift a fresh lock.
- Changing the password ends open sign-in and recovery steps begun with the old one; a new recovery key ends open recoveries.
- Vault membership and role are checked before large request bodies are read (batch, key rotation, attachment parts). A response already stored for the same idempotency key and endpoint is still replayed.
- New rate limit per account across all sessions (`rate_limits.account_per_min`, default 1200 per minute).
- Large request bodies share a memory budget (`limits.large_body_budget_bytes`, default 128 MiB, requests wait in arrival order), and one account runs at most `limits.large_requests_per_account` (default 4) of them at once; one more gets `429` with `Retry-After: 1`.
- Inviting is limited to 30 invitations per hour per inviting account and 30 per hour per invited account (`rate_limits.invites_per_account_per_hour`, `rate_limits.invites_per_invitee_per_hour`), on top of the general limits. Pending invitations expire after `limits.invitation_ttl_days` (default 30); the cleanup job deletes them, logs `invitation_expired` and tells the affected accounts.
- Attachment parts are stored only after a write transaction has checked the membership again, and completing an upload checks it in its transaction: a member removed while a part was still arriving can no longer store it.
- Every WebSocket send has a time limit of 10 seconds, so a client that stops reading no longer keeps its connection and slot forever.
- Favicon pages and images are parsed, decoded and scaled on the blocking thread pool instead of the async workers.
- The compose example trusts only the proxy's fixed address to set the client IP; before, any container in a private network could fake it for the rate limits.
- Login, recovery start and reauth check the credential again in their write transaction: a password change or new recovery key committed while the key was being verified makes the attempt a failure, and disabled state and second factor come from that transaction. Endpoints that need reauth check the token, the session and the account again first thing in their transaction, and the session endpoints check the calling session, so a revocation or password change can no longer be overtaken by a request already running.
- A passkey login rereads the passkey and its signature counter in the transaction that completes it and stores the counter only over the state it read; concurrent logins keep the counter monotonic, and a passkey removed meanwhile fails. Registering a passkey uses its token up in the transaction that stores it.
- Answers stored for idempotency keys have a budget per account (`limits.idempotency_entries_per_account`, `limits.idempotency_bytes_per_account`); the oldest give way.
- At most `limits.sessions_per_account` (default 100) active sessions per account; a new session revokes the least recently used.
- The security log keeps at most `logging.security_log_per_account_per_day` entries per account, event and day (`logging.security_log_anonymous_per_day` without an account) and counts the rest in one `log_capped` entry. The migration `0003_limits.sql` runs on start.
- Completions of the same attachment run one after another and take a slot for large requests; temporary files are deleted also when a request is cut off; creating an attachment whose ID still has files answers `409`.
- Everything that creates or deletes the files of one attachment (create, part, complete, delete and the file cleanup after batches, vault and account deletion, rotations and the jobs) runs one at a time per attachment ID, so a deletion still running never meets a new attachment with the same ID; the cleanup job checks for an open upload again under that lock. A part for an attachment that was deleted and created again with the same ID while the part arrived answers `404`; attachments carry a random generation for this check (migration `0004_attachment_generation.sql`), since a millisecond timestamp can repeat. A file cleanup that runs after its deletion committed reads the row again under the lock and leaves the files of a new attachment with the same ID alone.

### Changed

- `backup` ends with exit code 3 and keeps all older backups when attachment files are missing; the archive is still written.
- The storage quota (`limits.user_quota_bytes`) now counts objects including deletion markers and what open key rotations add, not only attachments. Vault creation, batches and key rotations that would exceed it get `507 quota_exceeded`, which is never stored for an idempotency key; deleting and shrinking always work. The migration `0002_quota.sql` runs on start.

## [0.1.0] - 2026-10-25

First public release. KeeMan is in early development: do not use it with real passwords yet, and note that the code has not been reviewed externally.

### Added

- REST API and WebSocket events for zero-knowledge clients: the server stores only ciphertext, hashes and metadata.
- Accounts with invite-only, open or closed registration; login with a key derived in the client (hashed again with Argon2id on the server), rotating refresh tokens with reuse detection, re-authentication for sensitive actions, recovery with a recovery key and account deletion.
- Two-factor login with TOTP, passkeys (WebAuthn) and one-time backup codes; rate limits and a login lockout that behave the same for unknown e-mail addresses.
- Vaults with members and roles, invitations, and a staged key rotation that also removes members.
- Revision-based sync with cursor paging, all-or-nothing batches with conflict lists, and idempotency keys.
- Attachments uploaded in parts, downloads with ranges, and a storage quota per vault owner.
- Favicon proxy with protection against server-side request forgery (blocked address ranges, DNS rebinding, redirect, size and time limits); icons come back as 64 × 64 PNG.
- CLI: `init`, `serve`, `migrate`, `invite`, `user` (list, disable, enable, reset-2fa), `backup`, `restore` and `check`.
- `backup`: a consistent snapshot of the database and every complete attachment file in one `.tar.zst` archive with a manifest of sizes and SHA-256 hashes, also while the server runs. `--dir` writes timestamped backups into a folder and keeps the newest of the most recent 14 days and 8 weeks (`--keep-daily`, `--keep-weekly`).
- `restore`: fills an empty data directory from a backup after checking every file against the manifest; refuses archives with other entries, links or paths outside the data directory. Needs no configuration.
- `check`: reports every problem of configuration, permissions, migrations, database integrity, foreign keys and attachment files without changing anything; exit code 1 on problems.
- systemd units for the service and for daily backups (`deploy/`), a deploy script, a container image (`Dockerfile`, non-root) and a compose example with the web client and Caddy (`deploy/compose/`).
- README: building, setup, backup and restore, copies elsewhere, containers, and the duties of the AGPL for modified versions.

[0.1.1]: https://github.com/BeckerEnterprises/keeman-server/releases/tag/v0.1.1
[0.1.0]: https://github.com/BeckerEnterprises/keeman-server/releases/tag/v0.1.0
