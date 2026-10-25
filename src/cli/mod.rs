//! Command-line interface. Every command except `init` and `restore`
//! refuses to run with an invalid configuration; `check` reports every
//! problem instead of stopping at the first.

pub mod backup;
pub mod check;
pub mod init;
pub mod invite;
pub mod restore;
pub mod serve;
pub mod user;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::audit::Audit;
use crate::config::Config;
use crate::crypto::ServerSecret;
use crate::db::Db;

/// API server for KeeMan, a self-hosted zero-knowledge password manager.
#[derive(Debug, Parser)]
#[command(version, about, arg_required_else_help = true)]
pub struct Cli {
    /// Configuration file
    #[arg(long, global = true, default_value = "config.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create the configuration, server secret and data directory (never overwrites)
    Init {
        /// Local development values (localhost origins, rp_id localhost)
        #[arg(long)]
        dev: bool,
        /// Data directory, relative to the configuration file
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Server secret file, relative to the configuration file
        #[arg(long)]
        secret_file: Option<PathBuf>,
    },
    /// Run the API server (applies pending migrations)
    Serve,
    /// Apply pending database migrations only
    Migrate,
    /// Manage invite codes
    #[command(subcommand)]
    Invite(InviteCommand),
    /// Manage accounts
    #[command(subcommand)]
    User(UserCommand),
    /// Write a backup of the database and the attachment files
    Backup {
        /// Archive to write (.tar.zst); must not exist
        #[arg(long, conflicts_with = "dir", required_unless_present = "dir")]
        out: Option<PathBuf>,
        /// Folder for timestamped backups, pruned afterwards
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Keep the newest backup of this many recent days (with --dir)
        #[arg(long, default_value_t = 14, requires = "dir")]
        keep_daily: usize,
        /// Keep the newest backup of this many recent weeks (with --dir)
        #[arg(long, default_value_t = 8, requires = "dir")]
        keep_weekly: usize,
    },
    /// Restore a backup into an empty data directory (stop the server first;
    /// needs no configuration)
    Restore {
        /// Archive written by `backup`
        #[arg(long)]
        from: PathBuf,
        /// Data directory to fill; must be empty or missing
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Check configuration, permissions, database and attachment files;
    /// changes nothing
    Check,
}

#[derive(Debug, Subcommand)]
enum InviteCommand {
    /// Create an invite code and print it once (stdout contains only the code)
    Create {
        /// Validity as <n>m, <n>h or <n>d, at most 365d
        #[arg(long, default_value = "7d")]
        expires: String,
        /// Note for the invite list, at most 200 characters
        #[arg(long)]
        note: Option<String>,
    },
    /// List invites (never the codes)
    List,
    /// Delete an unused invite
    Revoke { id: String },
}

#[derive(Debug, Subcommand)]
enum UserCommand {
    /// List accounts
    List,
    /// Disable an account and revoke all its sessions
    Disable { email: String },
    /// Enable a disabled account
    Enable { email: String },
    /// Emergency: remove TOTP, passkeys and backup codes; sessions stay
    #[command(name = "reset-2fa")]
    ResetTwoFactor { email: String },
}

pub type CliResult<T> = Result<T, String>;

/// Parses the command line and runs the requested command.
pub fn run() -> ExitCode {
    match execute(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn execute(cli: Cli) -> CliResult<()> {
    if let Command::Init {
        dev,
        data_dir,
        secret_file,
    } = &cli.command
    {
        return init::init(
            &cli.config,
            *dev,
            data_dir.as_deref(),
            secret_file.as_deref(),
        );
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async move {
        let now = time::OffsetDateTime::now_utc();
        match &cli.command {
            Command::Restore { from, data_dir } => return restore::restore(from, data_dir).await,
            Command::Check => return check::check(&cli.config, now).await,
            _ => {}
        }
        let loaded = load(&cli.config)?;
        match cli.command {
            Command::Init { .. } | Command::Restore { .. } | Command::Check => Ok(()),
            Command::Backup {
                out,
                dir,
                keep_daily,
                keep_weekly,
            } => {
                let target = backup::Target {
                    out,
                    dir,
                    keep_daily,
                    keep_weekly,
                };
                backup::backup(&loaded.config, target, now).await
            }
            Command::Serve => serve::serve(loaded).await,
            Command::Migrate => {
                open_db(&loaded.config).await?.close().await;
                Ok(())
            }
            Command::Invite(command) => {
                let db = open_db(&loaded.config).await?;
                let audit = Audit::new(&loaded.config.logging);
                let now = time::OffsetDateTime::now_utc();
                let result = match command {
                    InviteCommand::Create { expires, note } => {
                        invite::create_command(&db, &audit, now, &expires, note.as_deref()).await
                    }
                    InviteCommand::List => invite::list_command(&db, now).await,
                    InviteCommand::Revoke { id } => invite::revoke(&db, &audit, now, &id).await,
                };
                db.close().await;
                result
            }
            Command::User(command) => {
                let db = open_db(&loaded.config).await?;
                let audit = Audit::new(&loaded.config.logging);
                let now = time::OffsetDateTime::now_utc();
                let result = match command {
                    UserCommand::List => user::list_command(&db).await,
                    UserCommand::Disable { email } => {
                        user::set_disabled(&db, &audit, now, &email, true).await
                    }
                    UserCommand::Enable { email } => {
                        user::set_disabled(&db, &audit, now, &email, false).await
                    }
                    UserCommand::ResetTwoFactor { email } => {
                        user::reset_two_factor(&db, &audit, now, &email).await
                    }
                };
                db.close().await;
                result
            }
        }
    })
}

pub struct Loaded {
    pub config: Config,
    pub secret: ServerSecret,
}

/// The process environment as UTF-8 pairs (non-UTF-8 entries are skipped).
pub fn environment() -> Vec<(String, String)> {
    std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
        .collect()
}

/// Loads and checks configuration, permissions and secret.
pub fn load(path: &Path) -> CliResult<Loaded> {
    let env = environment();
    let config = Config::load(path, &env).map_err(|e| e.to_string())?;
    config.check_permissions(path).map_err(|e| e.to_string())?;
    let secret = config.load_secret(&env).map_err(|e| e.to_string())?;
    Ok(Loaded { config, secret })
}

/// Opens the database and applies pending migrations.
pub async fn open_db(config: &Config) -> CliResult<Db> {
    let db = Db::open(&config.database_path())
        .await
        .map_err(|e| format!("cannot open database: {e}"))?;
    db.migrate()
        .await
        .map_err(|e| format!("migration failed: {e}"))?;
    Ok(db)
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
