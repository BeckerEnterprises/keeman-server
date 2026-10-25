# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `backup`: a consistent snapshot of the database and every complete attachment file in one `.tar.zst` archive with a manifest of sizes and SHA-256 hashes, also while the server runs. `--dir` writes timestamped backups into a folder and keeps the newest of the most recent 14 days and 8 weeks (`--keep-daily`, `--keep-weekly`).
- `restore`: fills an empty data directory from a backup after checking every file against the manifest; refuses archives with other entries, links or paths outside the data directory. Needs no configuration.
- `check`: reports every problem of configuration, permissions, migrations, database integrity, foreign keys and attachment files without changing anything; exit code 1 on problems.
- systemd service and timer for daily backups (`deploy/keeman-backup.service`, `deploy/keeman-backup.timer`).
- Container image (`Dockerfile`, non-root) and a compose example with the web client and Caddy (`deploy/compose/`).
- README: backup and restore, copies elsewhere, containers, and the duties of the AGPL for modified versions.
