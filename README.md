# KeeMan Server

API server for [KeeMan](https://www.keeman.org), a self-hosted zero-knowledge password manager with a KeePassXC-like user experience. The server stores only ciphertext, hashes and metadata; all encryption and decryption happens in the clients.

First things first: Keeman is vibe-coded!

Stack: Rust, Axum, SQLite.

> **Status:** early development. Do not use with real passwords yet.

## Building

Building needs Rust (stable), a C compiler, `pkg-config` and the OpenSSL development files (`libssl-dev` on Debian/Ubuntu): the WebAuthn library links the system OpenSSL, and the favicon proxy's TLS provider `ring` compiles C code. The binary needs `libssl3` at runtime, the system CA certificates (`ca-certificates`) and outgoing HTTP/HTTPS for the favicon proxy (`features.favicon`).

```bash
cargo build --release --locked   # target/release/keeman-server
make check                       # sqlx data, rustfmt, clippy, tests, cargo audit, cargo deny
make sqlx-prepare                # after changing a query or migration: refresh .sqlx/
```

`make check` needs `sqlx-cli`, `cargo-audit` and `cargo-deny`. Queries are checked at compile time against the prepared data in `.sqlx/`, so a build needs no database. All SQL lives in `src/db/`. The tests need no network and no other repository; shared test vectors are in `tests/vectors/`.

## Local development

Configuration, secret and data in the git-ignored `dev/`:

```bash
cargo run -- init --dev --config dev/config.toml
cargo run -- invite create --config dev/config.toml
cargo run -- serve --config dev/config.toml        # http://127.0.0.1:8787
```

The development configuration allows the web client on `http://localhost:5173`.

## Configuration

`keeman-server init` writes a complete, commented `config.toml` (mode 0600), the server secret and the data directory. Unknown keys are an error, and every value can be overridden with an environment variable `KEEMAN__<SECTION>__<KEY>`, for example `KEEMAN__SERVER__LISTEN`.

Four keys depend on the installation and have no default; `init` writes example values that you must replace:

```toml
[server]
public_api_url = "https://api.example.org"     # where clients reach the API
allowed_origins = ["https://app.example.org"]  # origin of the web client (CORS, refresh cookie)

[webauthn]
rp_id = "app.example.org"                      # passkeys are bound to this domain; changing it later invalidates them
rp_origins = ["https://app.example.org"]
```

The web client and the API must be on the same site (for example `app.example.org` and `api.example.org`) because the refresh cookie is `SameSite=Strict`.

Limits worth knowing:

- `limits.user_quota_bytes` (default 2 GiB) is the storage of each vault owner: objects including deletion markers, attachments and what an open key rotation adds. A request that would grow beyond it gets `507 quota_exceeded`; deleting and shrinking always work. Members of a shared vault write into its owner's quota.
- `limits.large_body_budget_bytes` (default 128 MiB) caps the request bodies of large requests (batches, key rotation, attachment parts) held in memory at once; further requests wait. `limits.large_requests_per_account` (default 4) is how many of them one account may run at the same time.
- `rate_limits.session_per_min` (600) and `rate_limits.account_per_min` (1200) limit authenticated requests per session and for all sessions of an account together.
- `rate_limits.invites_per_account_per_hour` and `rate_limits.invites_per_invitee_per_hour` (30 each) limit invitations sent by one account and received by one account; pending invitations expire after `limits.invitation_ttl_days` (30).
- `rate_limits.roles_per_account_per_hour` (60) limits the new statements of a vault's signed owner list that one account signs (role changes, key rotations, dropping owners who left); stepping down oneself before leaving is not counted. A statement must change something, and `GET /v1/vaults/{id}/roles` is paged.
- `rate_limits.confirmations_per_account_per_hour` (20) limits how often the devices of one account ask the others for a confirmation; a request is valid for 5 minutes. The older key `rate_limits.pairings_per_account_per_hour` is still accepted, ignored with a warning at start, and can be removed.
- `limits.idempotency_entries_per_account` (1000) and `limits.idempotency_bytes_per_account` (8 MiB) bound the answers stored for idempotency keys per account; beyond that the oldest give way, and a repeated request with such a key acts again like one older than a day.
- `limits.sessions_per_account` (100) is the number of active sessions per account; a new one revokes the least recently used.
- `logging.security_log_per_account_per_day` (1000) and `logging.security_log_anonymous_per_day` (10000) cap the security log per account (or without one), event and day; further events of that kind are only counted in one `log_capped` entry.
- The quota follows the owner: when the account a vault counts against leaves it (demoted, left, removed by a key rotation or deleted), the vault counts against the owner with the oldest membership, who may then be over the quota until something is deleted.

## Commands

All commands take `--config <path>` (default `./config.toml`) and refuse to run if the configuration, the file permissions or the server secret are not safe; `restore` needs no configuration, and `check` reports every problem instead of stopping at the first.

| Command | Purpose |
|---|---|
| `init [--dev] [--data-dir <path>] [--secret-file <path>]` | Create configuration, server secret (0600) and data directory (0700); never overwrites |
| `serve` | Run the API (applies pending migrations) |
| `migrate` | Apply pending migrations only |
| `invite create [--expires 7d] [--note …]` | Print a new invite code (stdout contains only the code) |
| `invite list` / `invite revoke <id>` | List invites (never the codes) / delete an unused one |
| `user list` / `user disable <email>` / `user enable <email>` | List accounts / disable an account and revoke its sessions / enable it again |
| `user reset-2fa <email>` | Emergency: remove TOTP, passkeys and backup codes of an account; its sessions stay |
| `backup --out <file.tar.zst>` | Write a backup of the database and the attachment files, also while the server runs |
| `backup --dir <folder> [--keep-daily 14] [--keep-weekly 8]` | The same as `keeman-<YYYYMMDD-HHMMSS>.tar.zst` in a folder, then delete older backups there; exit code 3 if attachment files were missing (then nothing is deleted) |
| `restore --from <file.tar.zst> --data-dir <folder>` | Restore a backup into an empty data directory (server stopped) |
| `check` | Check configuration, permissions, database integrity and attachment files; changes nothing, exit code 1 on problems |

## Installation

Every [release](https://github.com/BeckerEnterprises/keeman-server/releases) has the binary for Linux x86_64 (glibc 2.34 or newer, OpenSSL 3) together with the systemd units, a container image and the compose example; or build it yourself (see Building). Check downloads with the release's `SHA256SUMS`.

A layout that keeps the service away from everything it does not need:

| Path | Content | Owner | Mode |
|---|---|---|---|
| `/opt/keeman/keeman-server` | binary | your deploy account | 0755 |
| `/etc/keeman/config.toml` | configuration | `keeman-api` | 0600 |
| `/etc/keeman/server_secret` | 32-byte secret | `keeman-api` | 0600 |
| `/var/lib/keeman/` | `keeman.sqlite`, `attachments/`, `uploads/` | `keeman-api` | 0700 |

The service runs as the system user `keeman-api`, which can write only its data directory. It must not be able to change the binary or the files of the web client: whoever can replace the web client's JavaScript can capture master passwords. Serve the web client from files owned by another account, ideally from another host.

One-time setup (`deploy` stands for your deploy account). First, as `deploy`, in the checkout: `cargo build --release --locked`. Then as root:

```bash
useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin keeman-api
install -d -o deploy -g deploy -m 0755 /opt/keeman
install -d -m 0755 /etc/keeman
install -o deploy -g deploy -m 0755 target/release/keeman-server /opt/keeman/keeman-server
/opt/keeman/keeman-server init --config /etc/keeman/config.toml --data-dir /var/lib/keeman
chown keeman-api:keeman-api /etc/keeman/config.toml /etc/keeman/server_secret
chown -R keeman-api:keeman-api /var/lib/keeman
editor /etc/keeman/config.toml                 # replace the example hosts
install -m 0644 deploy/keeman-api.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now keeman-api
```

Put a reverse proxy with TLS in front of `127.0.0.1:8787`; the server itself speaks only HTTP on loopback. Never serve `/etc/keeman` or the data directory as a document root. With Caddy:

```caddyfile
api.example.org {
	request_body {
		max_size 20MiB
	}
	header Strict-Transport-Security "max-age=63072000"
	reverse_proxy 127.0.0.1:8787
}
```

If the proxy is not on the same host or adds its own client IP header, set `server.trusted_proxies` and `server.client_ip_header`; otherwise rate limits count the proxy's address.

CLI commands run as the service user:

```bash
sudo -u keeman-api /opt/keeman/keeman-server invite create --config /etc/keeman/config.toml
```

## Backup and restore

A backup is one `.tar.zst` archive (mode 0600) with a consistent snapshot of the database, every complete attachment file and a `manifest.json` with the size and SHA-256 of each file. It never contains `server_secret` or `config.toml`: back those up separately, encrypted, for example with `age -p`, and keep them away from the server. Without the secret, the TOTP second factor of every account stops working. Backups hold no plaintext, but they do hold the hashes and wrapped keys an attacker would need for guessing master passwords offline, so treat them as confidential.

Daily backups with systemd, keeping the newest of 14 days and 8 weeks:

```bash
install -d -o keeman-api -g keeman-api -m 0700 /var/backups/keeman
install -m 0644 deploy/keeman-backup.service deploy/keeman-backup.timer /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now keeman-backup.timer
systemctl start keeman-backup.service          # a first backup right away
```

Copy the backups to another place as well. Do this from an account other than `keeman-api`, with its own key, and do not mirror deletions blindly (no `rsync --delete`): otherwise whoever compromises the API could wipe the copies by deleting the local files. For example, as root from a timer of its own:

```bash
rsync -a /var/backups/keeman/ backup@backup.example.org:keeman/
```

Restore, for example after moving to a new server:

```bash
systemctl stop keeman-api
sudo -u keeman-api /opt/keeman/keeman-server restore --from keeman-20261025-030000.tar.zst --data-dir /var/lib/keeman
# restore server_secret and config.toml from their own backup, then:
sudo -u keeman-api /opt/keeman/keeman-server check --config /etc/keeman/config.toml
systemctl start keeman-api
```

If an attachment file is missing, the backup is still written with the file listed under `missing` in the manifest, but the command ends with exit code 3 and keeps all older backups, so an incomplete run never pushes out a complete one. A file deleted while the backup ran can cause this; the next run is then complete. If it stays, `check` names the missing files.

`restore` only fills an empty data directory (or one with the empty `attachments/` and `uploads/` that `init` leaves). It checks every file against the manifest before anything is put in place, and refuses archives with other entries. Try a restore now and then in a fresh environment, for example in a container, and run `check` afterwards.

## Containers

`Dockerfile` builds an image of the server (non-root user `keeman`, volumes `/etc/keeman`, `/var/lib/keeman` and `/var/backups/keeman`); the web client repository has one for the web client. `deploy/compose/` combines both with Caddy, which gets TLS certificates for the two hosts:

```bash
podman build -t keeman-server .                # here; the web client image in its repository
cd deploy/compose                              # replace the example hosts in compose.yaml and Caddyfile
podman compose run --rm api init --config /etc/keeman/config.toml --data-dir /var/lib/keeman
podman compose up -d
podman compose exec api keeman-server invite create --config /etc/keeman/config.toml
```

Instead of building, load the image of a release: `docker load -i keeman-server-<version>-image-linux-amd64.tar.gz` (or `podman load -i …`) names it `keeman-server:<version>` and `keeman-server:latest`, as the compose file expects; the web client release has its image as well. The same works with Docker (`docker build`, `docker compose`). In the compose file, environment variables set the installation-specific keys (`KEEMAN__SERVER__PUBLIC_API_URL` and so on) over the placeholders `init` writes. The containers share a network with a fixed subnet, and `trusted_proxies` names only the proxy's fixed address in it: any other container could otherwise set `X-Forwarded-For` and fake client IPs for the rate limits. If you change the subnet, change both. Backups: `podman compose exec api keeman-server backup --config /etc/keeman/config.toml --dir /var/backups/keeman`, for example from a timer on the host, then copy the `backups` volume elsewhere.

## Deployment

`scripts/deploy.sh` builds the release binary from a clean working tree, installs it, restarts the service and waits for `/v1/health`:

```bash
KEEMAN_BIN=/opt/keeman/keeman-server KEEMAN_SERVICE=keeman-api \
KEEMAN_HEALTH_URL=http://127.0.0.1:8787/v1/health scripts/deploy.sh
```

The deploy account needs the right to restart the unit, for example in `/etc/sudoers.d/keeman-api`:

```
deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart keeman-api, /usr/bin/systemctl status keeman-api
deploy ALL=(keeman-api) NOPASSWD: /opt/keeman/keeman-server
```

## License

[GNU Affero General Public License v3.0 or later](LICENSE) (`AGPL-3.0-or-later`).

If you run a modified version of the server or the web client for others, the AGPL requires you to offer them the source code of exactly that version. The web client links to the source code (`apps/web/src/build-info.ts` in its repository); point those links to your own repositories.

The KeeMan name and logo are not licensed under the AGPL: as permitted by section 7(e) of the license, no rights to use them are granted. If you distribute or run a modified version for others, give it your own name and logo.
