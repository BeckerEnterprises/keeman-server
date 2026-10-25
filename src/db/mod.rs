//! Repository layer: the only place with SQL. Reads use a pool of
//! connections; writes use one connection and `BEGIN IMMEDIATE`.

use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous,
};
use sqlx::{Acquire, Sqlite, SqliteConnection, Transaction};

pub mod attachments;
pub mod backup_codes;
pub mod challenges;
pub mod cleanup;
pub mod idempotency;
pub mod invites;
pub mod maintenance;
pub mod objects;
pub mod passkeys;
pub mod rotations;
pub mod security_log;
pub mod sessions;
pub mod throttle;
pub mod users;
pub mod vaults;

pub type Conn = SqliteConnection;

#[derive(Clone)]
pub struct Db {
    pub read: SqlitePool,
    write: SqlitePool,
}

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

fn options(path: &Path) -> Result<SqliteConnectOptions, sqlx::Error> {
    Ok(
        SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))?
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5))
            .pragma("secure_delete", "ON")
            .pragma("trusted_schema", "OFF"),
    )
}

impl Db {
    /// Opens the database, creating the file with mode 0600 if needed.
    pub async fn open(path: &Path) -> Result<Db, sqlx::Error> {
        if !path.exists() {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(sqlx::Error::Io)?;
        }
        let read = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(options(path)?)
            .await?;
        let write = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options(path)?)
            .await?;
        Ok(Db { read, write })
    }

    /// Opens an existing database without creating or migrating it, for
    /// the maintenance commands next to a running server.
    pub async fn open_existing(path: &Path) -> Result<Db, sqlx::Error> {
        if !path.is_file() {
            return Err(sqlx::Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no database at {}", path.display()),
            )));
        }
        let read = SqlitePoolOptions::new()
            .max_connections(2)
            .connect_with(options(path)?.create_if_missing(false))
            .await?;
        let write = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options(path)?.create_if_missing(false))
            .await?;
        Ok(Db { read, write })
    }

    /// Applies pending migrations; refuses a database from a newer binary.
    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        MIGRATOR.run(&self.write).await
    }

    /// A write transaction with `BEGIN IMMEDIATE`; rolls back on drop.
    pub async fn begin(&self) -> Result<Tx, sqlx::Error> {
        self.write.begin_with("BEGIN IMMEDIATE").await
    }

    pub async fn ping(&self) -> bool {
        sqlx::query_scalar!("SELECT 1 AS \"one!: i64\"")
            .fetch_one(&self.read)
            .await
            .is_ok()
    }

    pub async fn close(&self) {
        self.read.close().await;
        self.write.close().await;
    }
}

pub type Tx = Transaction<'static, Sqlite>;

/// A savepoint inside a write transaction; rolls back to it on drop.
pub async fn savepoint(tx: &mut Tx) -> Result<Transaction<'_, Sqlite>, sqlx::Error> {
    Acquire::begin(&mut *tx).await
}
