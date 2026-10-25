# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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

### Changed

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

[0.1.0]: https://github.com/BeckerEnterprises/keeman-server/releases/tag/v0.1.0
