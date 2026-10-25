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

## Commands

All commands take `--config <path>` (default `./config.toml`) and refuse to run if the configuration, the file permissions or the server secret are not safe.

| Command | Purpose |
|---|---|
| `init [--dev] [--data-dir <path>] [--secret-file <path>]` | Create configuration, server secret (0600) and data directory (0700); never overwrites |
| `serve` | Run the API (applies pending migrations) |
| `migrate` | Apply pending migrations only |
| `invite create [--expires 7d] [--note …]` | Print a new invite code (stdout contains only the code) |
| `invite list` / `invite revoke <id>` | List invites (never the codes) / delete an unused one |
| `user list` / `user disable <email>` / `user enable <email>` | List accounts / disable an account and revoke its sessions / enable it again |
| `user reset-2fa <email>` | Emergency: remove TOTP, passkeys and backup codes of an account; its sessions stay |

## Installation

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

Back up `server_secret` and `config.toml` separately from the data. Without the secret, the TOTP second factor of every account stops working.

CLI commands run as the service user:

```bash
sudo -u keeman-api /opt/keeman/keeman-server invite create --config /etc/keeman/config.toml
```

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

The KeeMan name and logo are not licensed under the AGPL: as permitted by section 7(e) of the license, no rights to use them are granted. If you distribute or run a modified version for others, give it your own name and logo.
