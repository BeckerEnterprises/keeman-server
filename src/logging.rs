//! Process logging: only request metadata, never bodies, tokens,
//! cookies, e-mails, IPs or device names.

use tracing::level_filters::LevelFilter;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::{LogFormat, LogLevel, LoggingSection};

fn level(level: LogLevel) -> LevelFilter {
    match level {
        LogLevel::Error => LevelFilter::ERROR,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Trace => LevelFilter::TRACE,
    }
}

/// DNS crates of the favicon proxy: they name queried hosts even on `warn`
/// and `error`, so they are silenced.
const SILENCED: [&str; 3] = ["hickory_resolver", "hickory_net", "hickory_proto"];

/// The server logs at the configured level, dependencies at most at `info`:
/// webauthn-rs prints credential IDs and ceremony details on `debug` and
/// `trace`.
pub fn targets(configured: LogLevel) -> Targets {
    let level = level(configured);
    SILENCED.iter().fold(
        Targets::new()
            .with_target("keeman_server", level)
            .with_default(level.min(LevelFilter::INFO)),
        |targets, target| targets.with_target(*target, LevelFilter::OFF),
    )
}

/// Installs the global subscriber; output goes to stdout (systemd journal).
pub fn init(config: &LoggingSection) {
    let builder = tracing_subscriber::fmt()
        .with_max_level(level(config.level))
        .with_target(false);
    let targets = targets(config.level);
    let result = match config.format {
        LogFormat::Json => builder.json().finish().with(targets).try_init(),
        LogFormat::Text => builder.finish().with(targets).try_init(),
    };
    // A second init (e.g. in tests) keeps the first subscriber.
    let _ = result;
}
