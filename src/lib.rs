//! KeeMan API server. The binary in `main.rs` is a thin wrapper, so integration
//! tests can use everything here directly.

pub mod api;
pub mod app;
pub mod audit;
pub mod auth;
pub mod backup;
pub mod cli;
pub mod client_ip;
pub mod clock;
pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod events;
pub mod extract;
pub mod favicon;
pub mod idempotency;
pub mod inflight;
pub mod jobs;
pub mod logging;
pub mod quota;
pub mod ratelimit;
pub mod storage;
pub mod types;
