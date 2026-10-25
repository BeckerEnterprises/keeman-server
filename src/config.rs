//! Configuration: TOML file, `KEEMAN__<SECTION>__<KEY>` overrides,
//! strict parsing and the startup refusals.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ipnet::IpNet;
use serde::Deserialize;

use crate::crypto::ServerSecret;
use crate::storage::attachments::Storage;

#[derive(Debug)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

fn err<T>(message: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError(message.into()))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerSection,
    pub storage: StorageSection,
    #[serde(default)]
    pub security: SecuritySection,
    pub webauthn: WebauthnSection,
    #[serde(default)]
    pub limits: LimitsSection,
    #[serde(default)]
    pub features: FeaturesSection,
    #[serde(default)]
    pub rate_limits: RateLimitsSection,
    #[serde(default)]
    pub logging: LoggingSection,
}

/// `public_api_url` and `allowed_origins` depend on the installation and have
/// no default.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    #[serde(default = "default_listen")]
    pub listen: String,
    pub public_api_url: String,
    pub allowed_origins: Vec<String>,
    #[serde(default = "default_trusted_proxies")]
    pub trusted_proxies: Vec<String>,
    #[serde(default = "default_client_ip_header")]
    pub client_ip_header: String,
}

fn default_listen() -> String {
    "127.0.0.1:8787".into()
}

fn default_trusted_proxies() -> Vec<String> {
    vec!["127.0.0.1/32".into(), "::1/128".into()]
}

fn default_client_ip_header() -> String {
    "X-Forwarded-For".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageSection {
    pub data_dir: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Registration {
    Closed,
    Invite,
    Open,
}

impl Registration {
    pub fn as_str(self) -> &'static str {
        match self {
            Registration::Closed => "closed",
            Registration::Invite => "invite",
            Registration::Open => "open",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SecuritySection {
    pub server_secret_file: Option<PathBuf>,
    pub registration: Registration,
    pub access_token_ttl_minutes: u32,
    pub refresh_token_ttl_days: u32,
    pub dev_mode: bool,
}

impl Default for SecuritySection {
    fn default() -> Self {
        Self {
            server_secret_file: None,
            registration: Registration::Invite,
            access_token_ttl_minutes: 15,
            refresh_token_ttl_days: 30,
            dev_mode: false,
        }
    }
}

/// `rp_id` and `rp_origins` depend on the installation and have no default.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebauthnSection {
    pub rp_id: String,
    #[serde(default = "default_rp_name")]
    pub rp_name: String,
    pub rp_origins: Vec<String>,
}

fn default_rp_name() -> String {
    "KeeMan".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LimitsSection {
    pub attachment_max_bytes: u64,
    pub user_quota_bytes: u64,
    pub tombstone_retention_days: u32,
    /// Bodies of large requests in memory at once (`batch`, rotation
    /// uploads and commit, attachment parts).
    pub large_body_budget_bytes: u64,
    /// Large requests of one account at once.
    pub large_requests_per_account: u32,
    /// Pending invitations are deleted after this many days.
    pub invitation_ttl_days: u32,
    /// Stored idempotency answers per account; the oldest give way.
    pub idempotency_entries_per_account: u32,
    pub idempotency_bytes_per_account: u64,
    /// Active sessions per account; a new one revokes the least recently used.
    pub sessions_per_account: u32,
}

impl Default for LimitsSection {
    fn default() -> Self {
        Self {
            attachment_max_bytes: 52_428_800,
            user_quota_bytes: 2_147_483_648,
            tombstone_retention_days: 180,
            large_body_budget_bytes: 134_217_728,
            large_requests_per_account: 4,
            invitation_ttl_days: 30,
            idempotency_entries_per_account: 1000,
            idempotency_bytes_per_account: 8_388_608,
            sessions_per_account: 100,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FeaturesSection {
    pub favicon: bool,
}

impl Default for FeaturesSection {
    fn default() -> Self {
        Self { favicon: true }
    }
}

/// Rate limits: per IP, per e-mail address, per account or per session, as
/// each key's name says.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RateLimitsSection {
    pub prelogin_per_ip_per_min: u32,
    pub credential_per_ip_per_min: u32,
    pub credential_per_email_per_min: u32,
    pub lockout_failures: u32,
    pub lockout_minutes: u32,
    pub register_per_ip_per_hour: u32,
    pub refresh_per_ip_per_min: u32,
    pub events_per_ip_per_min: u32,
    pub session_per_min: u32,
    /// All sessions of an account together; the same exceptions as
    /// `session_per_min`.
    pub account_per_min: u32,
    pub lookup_per_account_per_hour: u32,
    pub favicon_per_account_per_min: u32,
    /// Invitations, on top of the session and account limits.
    pub invites_per_account_per_hour: u32,
    pub invites_per_invitee_per_hour: u32,
}

impl Default for RateLimitsSection {
    fn default() -> Self {
        Self {
            prelogin_per_ip_per_min: 20,
            credential_per_ip_per_min: 10,
            credential_per_email_per_min: 5,
            lockout_failures: 10,
            lockout_minutes: 15,
            register_per_ip_per_hour: 5,
            refresh_per_ip_per_min: 60,
            events_per_ip_per_min: 60,
            session_per_min: 600,
            account_per_min: 1200,
            lookup_per_account_per_hour: 30,
            favicon_per_account_per_min: 30,
            invites_per_account_per_hour: 30,
            invites_per_invitee_per_hour: 30,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Text,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LoggingSection {
    pub level: LogLevel,
    pub format: LogFormat,
    pub security_log_retention_days: u32,
    /// Entries per account, event and day; more are only counted.
    pub security_log_per_account_per_day: u32,
    /// The same for events without an account.
    pub security_log_anonymous_per_day: u32,
}

impl Default for LoggingSection {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Json,
            security_log_retention_days: 90,
            security_log_per_account_per_day: 1000,
            security_log_anonymous_per_day: 10_000,
        }
    }
}

const ENV_PREFIX: &str = "KEEMAN__";
pub const SECRET_ENV: &str = "KEEMAN_SERVER_SECRET";

impl Config {
    /// Reads, overlays the environment, parses strictly and validates.
    pub fn load(path: &Path, env: &[(String, String)]) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(path)
            .or_else(|e| err(format!("cannot read config {}: {e}", path.display())))?;
        let mut table: toml::Table = toml::from_str(&text)
            .or_else(|e| err(format!("invalid TOML in {}: {e}", path.display())))?;
        overlay_env(&mut table, env)?;
        let mut config = Config::deserialize(toml::Value::Table(table))
            .or_else(|e| err(format!("invalid configuration: {e}")))?;
        let base = path.parent().unwrap_or(Path::new("."));
        config.storage.data_dir = absolute(base, &config.storage.data_dir);
        if let Some(file) = &config.security.server_secret_file {
            config.security.server_secret_file = Some(absolute(base, file));
        }
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        self.server
            .listen
            .parse::<SocketAddr>()
            .or_else(|_| err("server.listen is not an address"))?;
        self.trusted_proxies()?;
        axum::http::HeaderName::from_bytes(self.server.client_ip_header.as_bytes())
            .or_else(|_| err("server.client_ip_header is not a header name"))?;
        let dev = self.security.dev_mode;
        for (name, origins) in [
            ("server.allowed_origins", &self.server.allowed_origins),
            ("webauthn.rp_origins", &self.webauthn.rp_origins),
        ] {
            for origin in origins {
                let parsed = parse_origin(origin)
                    .ok_or_else(|| ConfigError(format!("{name}: {origin} is not an origin")))?;
                if dev && !parsed.is_loopback() {
                    return err(format!(
                        "{name}: dev_mode allows only localhost origins, not {origin}"
                    ));
                }
                if !dev && parsed.scheme != "https" && !parsed.is_loopback() {
                    return err(format!("{name}: {origin} must use https"));
                }
            }
        }
        let rp_id = self.webauthn.rp_id.as_str();
        if !is_domain_name(rp_id) {
            return err(format!(
                "webauthn.rp_id {rp_id} must be a lower-case domain name, not an IP address"
            ));
        }
        if self.webauthn.rp_origins.is_empty() {
            return err("webauthn.rp_origins must not be empty");
        }
        for origin in &self.webauthn.rp_origins {
            let host = parse_origin(origin).map(|o| o.host).unwrap_or_default();
            if host != rp_id && !host.ends_with(&format!(".{rp_id}")) {
                return err(format!("webauthn.rp_id {rp_id} does not match {origin}"));
            }
        }
        if !(1..=60).contains(&self.security.access_token_ttl_minutes) {
            return err("security.access_token_ttl_minutes must be 1-60");
        }
        if !(1..=365).contains(&self.security.refresh_token_ttl_days) {
            return err("security.refresh_token_ttl_days must be 1-365");
        }
        let r = &self.rate_limits;
        if [
            r.prelogin_per_ip_per_min,
            r.credential_per_ip_per_min,
            r.credential_per_email_per_min,
            r.lockout_failures,
            r.lockout_minutes,
            r.register_per_ip_per_hour,
            r.refresh_per_ip_per_min,
            r.events_per_ip_per_min,
            r.session_per_min,
            r.account_per_min,
            r.lookup_per_account_per_hour,
            r.favicon_per_account_per_min,
            r.invites_per_account_per_hour,
            r.invites_per_invitee_per_hour,
        ]
        .contains(&0)
        {
            return err("rate_limits must all be positive");
        }
        if self.limits.large_body_budget_bytes < crate::extract::LARGE_BODY_LIMIT as u64 {
            return err("limits.large_body_budget_bytes must be at least 16 MiB");
        }
        if self.limits.large_requests_per_account == 0 {
            return err("limits.large_requests_per_account must be positive");
        }
        if self.limits.invitation_ttl_days == 0 {
            return err("limits.invitation_ttl_days must be positive");
        }
        if self.limits.idempotency_entries_per_account < 10 {
            return err("limits.idempotency_entries_per_account must be at least 10");
        }
        // Larger than any single stored answer, so the newest always fits.
        if self.limits.idempotency_bytes_per_account < 1_048_576 {
            return err("limits.idempotency_bytes_per_account must be at least 1 MiB");
        }
        if self.limits.sessions_per_account == 0 {
            return err("limits.sessions_per_account must be positive");
        }
        if self.logging.security_log_per_account_per_day == 0
            || self.logging.security_log_anonymous_per_day == 0
        {
            return err("logging.security_log_*_per_day must be positive");
        }
        Ok(())
    }

    pub fn trusted_proxies(&self) -> Result<Vec<IpNet>, ConfigError> {
        self.server
            .trusted_proxies
            .iter()
            .map(|entry| {
                entry
                    .parse::<IpNet>()
                    .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
                    .or_else(|_| err(format!("server.trusted_proxies: {entry} is not a network")))
            })
            .collect()
    }

    pub fn database_path(&self) -> PathBuf {
        self.storage.data_dir.join("keeman.sqlite")
    }

    /// File permissions must not grant anything to group or others.
    pub fn check_permissions(&self, config_path: &Path) -> Result<(), ConfigError> {
        private(config_path, "config file")?;
        let data = &self.storage.data_dir;
        if !data.is_dir() {
            return err(format!("data_dir {} does not exist", data.display()));
        }
        private(data, "data_dir")?;
        if let Some(file) = &self.security.server_secret_file {
            private(file, "server_secret_file")?;
        }
        let db = self.database_path();
        if db.exists() {
            private(&db, "database")?;
        }
        for dir in Storage::dirs(data) {
            if dir.exists() {
                private(&dir, "attachment directory")?;
            }
        }
        Ok(())
    }

    /// Like `check_permissions`, but collects every problem of the config
    /// file, `data_dir` and the secret file instead of stopping at the first.
    /// The paths below `data_dir` are checked by `check` itself.
    pub fn permission_problems(&self, config_path: &Path) -> Vec<String> {
        let mut problems = Vec::new();
        let mut collect = |result: Result<(), ConfigError>| {
            if let Err(error) = result {
                problems.push(error.0);
            }
        };
        collect(private(config_path, "config file"));
        let data = &self.storage.data_dir;
        if data.is_dir() {
            collect(private(data, "data_dir"));
        } else {
            collect(err(format!("data_dir {} does not exist", data.display())));
        }
        if let Some(file) = &self.security.server_secret_file {
            collect(private(file, "server_secret_file"));
        }
        problems
    }

    /// The server secret from file or environment, never both.
    pub fn load_secret(&self, env: &[(String, String)]) -> Result<ServerSecret, ConfigError> {
        let from_env = env
            .iter()
            .find(|(k, _)| k == SECRET_ENV)
            .map(|(_, v)| v.as_str());
        match (&self.security.server_secret_file, from_env) {
            (Some(_), Some(_)) => err(format!(
                "server secret is set both as file and as {SECRET_ENV}"
            )),
            (None, None) => {
                err("no server secret: set security.server_secret_file or KEEMAN_SERVER_SECRET")
            }
            (Some(file), None) => {
                let bytes = std::fs::read(file)
                    .or_else(|e| err(format!("cannot read server secret: {e}")))?;
                let array: [u8; 32] = bytes
                    .try_into()
                    .or_else(|_| err("server secret file must contain exactly 32 bytes"))?;
                Ok(ServerSecret::from_bytes(array))
            }
            (None, Some(text)) => {
                let bytes = URL_SAFE_NO_PAD
                    .decode(text)
                    .or_else(|_| err(format!("{SECRET_ENV} is not Base64url")))?;
                let array: [u8; 32] = bytes
                    .try_into()
                    .or_else(|_| err(format!("{SECRET_ENV} must decode to 32 bytes")))?;
                Ok(ServerSecret::from_bytes(array))
            }
        }
    }
}

fn private(path: &Path, what: &str) -> Result<(), ConfigError> {
    let metadata = std::fs::metadata(path)
        .or_else(|e| err(format!("cannot read {what} {}: {e}", path.display())))?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return err(format!(
            "{what} {} must not be accessible by group or others (chmod go-rwx)",
            path.display()
        ));
    }
    Ok(())
}

fn absolute(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

/// `KEEMAN__SECTION__KEY=value`; values are TOML literals, otherwise text.
fn overlay_env(table: &mut toml::Table, env: &[(String, String)]) -> Result<(), ConfigError> {
    for (name, value) in env {
        let Some(rest) = name.strip_prefix(ENV_PREFIX) else {
            continue;
        };
        let parts: Vec<&str> = rest.split("__").collect();
        let [section, key] = parts.as_slice() else {
            return err(format!("{name}: expected KEEMAN__<SECTION>__<KEY>"));
        };
        let parsed = toml::from_str::<toml::Table>(&format!("v = {value}"))
            .ok()
            .and_then(|mut t| t.remove("v"))
            .unwrap_or_else(|| toml::Value::String(value.clone()));
        let section = table
            .entry(section.to_ascii_lowercase())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        let Some(section) = section.as_table_mut() else {
            return err(format!("{name}: section is not a table"));
        };
        section.insert(key.to_ascii_lowercase(), parsed);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
}

impl Origin {
    fn is_loopback(&self) -> bool {
        matches!(self.host.as_str(), "localhost" | "127.0.0.1" | "[::1]")
    }
}

/// A serialised origin: `scheme://host[:port]`, nothing else.
pub fn parse_origin(text: &str) -> Option<Origin> {
    let (scheme, rest) = text.split_once("://")?;
    if scheme != "https" && scheme != "http" {
        return None;
    }
    if rest.is_empty() || rest.contains(['/', '?', '#', '@', '*']) {
        return None;
    }
    let (host, port) = if let Some(end) = rest.strip_prefix('[').and_then(|r| r.find(']')) {
        let host = &rest[..end + 2];
        let after = &rest[end + 2..];
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p.parse::<u16>().ok()?),
            None if after.is_empty() => None,
            None => return None,
        };
        (host.to_string(), port)
    } else {
        match rest.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), Some(p.parse::<u16>().ok()?)),
            None => (rest.to_string(), None),
        }
    };
    let valid_host = !host.is_empty()
        && host.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | '[' | ']' | ':')
        });
    (valid_host && port != Some(0)).then(|| Origin {
        scheme: scheme.to_string(),
        host,
        port,
    })
}

/// A lower-case DNS name, as WebAuthn needs for the RP ID: labels of
/// `a–z`, `0–9` and inner hyphens, and a last label that is not numeric, so
/// IP addresses never pass.
fn is_domain_name(name: &str) -> bool {
    let labels: Vec<&str> = name.split('.').collect();
    let label_ok = |l: &&str| {
        (1..=63).contains(&l.len())
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    name.len() <= 253
        && labels.iter().all(label_ok)
        && labels
            .last()
            .is_some_and(|l| !l.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rp_ids_are_domain_names() {
        for good in ["localhost", "app.example.org", "a-b.example", "x1.example"] {
            assert!(is_domain_name(good), "{good}");
        }
        for bad in [
            "",
            "127.0.0.1",
            "::1",
            "[::1]",
            "App.Example.org",
            "app.example.org.",
            "-a.example",
            "a_b.example",
            "example.123",
        ] {
            assert!(!is_domain_name(bad), "{bad}");
        }
    }

    #[test]
    fn parses_origins_strictly() {
        assert_eq!(
            parse_origin("https://app.example.org").map(|o| o.host),
            Some("app.example.org".into())
        );
        assert_eq!(
            parse_origin("http://localhost:5173").and_then(|o| o.port),
            Some(5173)
        );
        assert!(parse_origin("http://[::1]:8080").is_some());
        for bad in [
            "https://app.example.org/",
            "https://*.example.org",
            "null",
            "ftp://x",
            "https://",
            "https://a:0",
            "https://A.org",
            "https://a.org?x",
        ] {
            assert!(parse_origin(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn env_values_are_toml_literals_or_text() {
        let mut table = toml::Table::new();
        let env = vec![
            (
                "KEEMAN__SERVER__LISTEN".to_string(),
                "127.0.0.1:9000".to_string(),
            ),
            (
                "KEEMAN__LIMITS__ATTACHMENT_MAX_BYTES".to_string(),
                "1024".to_string(),
            ),
            (
                "KEEMAN__SERVER__ALLOWED_ORIGINS".to_string(),
                "[\"https://a.example\"]".to_string(),
            ),
            ("OTHER".to_string(), "x".to_string()),
        ];
        overlay_env(&mut table, &env).unwrap();
        assert_eq!(table["server"]["listen"].as_str(), Some("127.0.0.1:9000"));
        assert_eq!(
            table["limits"]["attachment_max_bytes"].as_integer(),
            Some(1024)
        );
        assert_eq!(
            table["server"]["allowed_origins"][0].as_str(),
            Some("https://a.example")
        );
        assert!(overlay_env(&mut table, &[("KEEMAN__X".into(), "1".into())]).is_err());
    }
}
