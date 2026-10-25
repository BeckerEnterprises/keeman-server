//! `keeman-server init`: configuration, server secret and data
//! directory. Never overwrites, never prints the secret, creates no database.

use std::fs::{DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

use super::CliResult;
use crate::crypto::random_bytes;

fn quoted(path: &Path) -> String {
    toml::Value::String(path.display().to_string()).to_string()
}

pub fn template(dev: bool, data_dir: &Path, secret_file: &Path) -> String {
    let (api, origin, rp_id, format) = if dev {
        (
            "http://127.0.0.1:8787",
            "http://localhost:5173",
            "localhost",
            "text",
        )
    } else {
        (
            "https://api.example.org",
            "https://app.example.org",
            "app.example.org",
            "json",
        )
    };
    let data_dir = quoted(data_dir);
    let secret_file = quoted(secret_file);
    format!(
        r#"# KeeMan server configuration. Unknown keys are an error.
# Every value can be overridden with KEEMAN__<SECTION>__<KEY>.
# Replace the example hosts with the addresses of this installation: the API
# (public_api_url) and the web client (allowed_origins, webauthn).

[server]
listen = "127.0.0.1:8787"
public_api_url = "{api}"
allowed_origins = ["{origin}"]
# Only these peers may set the client IP via client_ip_header.
trusted_proxies = ["127.0.0.1/32", "::1/128"]
client_ip_header = "X-Forwarded-For"

[storage]
data_dir = {data_dir}

[security]
server_secret_file = {secret_file}
registration = "invite"                   # closed | invite | open
access_token_ttl_minutes = 15
refresh_token_ttl_days = 30
# Local development only: refresh cookie "keeman_rt" instead of "__Host-keeman_rt";
# allowed only with localhost origins.
dev_mode = false

[webauthn]
rp_id = "{rp_id}"
rp_name = "KeeMan"
rp_origins = ["{origin}"]

[limits]
attachment_max_bytes = 52428800
user_quota_bytes = 2147483648
tombstone_retention_days = 180

[features]
favicon = true

[rate_limits]
prelogin_per_ip_per_min = 20
credential_per_ip_per_min = 10
credential_per_email_per_min = 5
lockout_failures = 10
lockout_minutes = 15
register_per_ip_per_hour = 5
refresh_per_ip_per_min = 60
events_per_ip_per_min = 60
session_per_min = 600
lookup_per_account_per_hour = 30       # users/lookup, not counted against session_per_min
favicon_per_account_per_min = 30       # favicon, not counted against session_per_min

[logging]
level = "info"
format = "{format}"
security_log_retention_days = 90
"#
    )
}

fn create_private_file(path: &Path, content: &[u8]) -> CliResult<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    file.write_all(content)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

pub fn init(
    config: &Path,
    dev: bool,
    data_dir: Option<&Path>,
    secret_file: Option<&Path>,
) -> CliResult<()> {
    let base = config
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let data_dir = data_dir.unwrap_or(Path::new("data"));
    let secret_file = secret_file.unwrap_or(Path::new("server_secret"));
    let secret_path = base.join(secret_file);
    for existing in [config, secret_path.as_path()] {
        if existing.exists() {
            return Err(format!(
                "{} already exists; init never overwrites",
                existing.display()
            ));
        }
    }
    // The data directory and its attachment directories.
    for dir in [
        base.join(data_dir),
        base.join(data_dir).join("attachments"),
        base.join(data_dir).join("uploads"),
    ] {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| format!("cannot create data directory: {e}"))?;
    }
    let secret = random_bytes::<32>().map_err(|e| e.to_string())?;
    create_private_file(&secret_path, &secret)?;
    create_private_file(config, template(dev, data_dir, secret_file).as_bytes())?;
    println!(
        "created {}, {} and {}",
        config.display(),
        secret_path.display(),
        base.join(data_dir).display()
    );
    Ok(())
}
