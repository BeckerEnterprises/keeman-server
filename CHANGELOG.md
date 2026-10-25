# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
