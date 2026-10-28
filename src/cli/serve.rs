//! `keeman-server serve`: runs the API until SIGTERM or Ctrl-C.

use std::net::SocketAddr;
use std::sync::Arc;

use super::{CliResult, Loaded, open_db};
use crate::app::{App, router};
use crate::clock::SystemClock;
use crate::events::socket;
use crate::{jobs, logging};

pub async fn serve(loaded: Loaded) -> CliResult<()> {
    let Loaded { config, secret } = loaded;
    logging::init(&config.logging);
    if config.rate_limits.pairings_per_account_per_hour.is_some() {
        tracing::warn!(
            "rate_limits.pairings_per_account_per_hour is no longer used and can be removed"
        );
    }
    let listen: SocketAddr = config
        .server
        .listen
        .parse()
        .map_err(|_| "server.listen is not an address".to_string())?;
    let db = open_db(&config).await?;
    let app = App::new(config, &secret, db.clone(), Arc::new(SystemClock))?;
    let cleanup = jobs::spawn(app.clone());
    let revalidation = socket::spawn_revalidation(app.clone());
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|e| format!("cannot listen on {listen}: {e}"))?;
    tracing::info!(listen = %listen, version = env!("CARGO_PKG_VERSION"), "keeman-server started");
    let hub_app = app.clone();
    let result = axum::serve(
        listener,
        router(app).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown().await;
        // Open WebSockets end with 1001.
        hub_app.hub.shutdown();
    })
    .await
    .map_err(|e| e.to_string());
    cleanup.abort();
    revalidation.abort();
    db.close().await;
    tracing::info!("keeman-server stopped");
    result
}

async fn shutdown() {
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        () = terminate => {}
    }
}
