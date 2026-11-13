//! Doors for `tests/background_embedding_line.rs` (census L1-27, ARCH-0053
//! `#embedding-admission-built`): a server holding the embedder a serve
//! config names, built as plain and managed serve build it, and its
//! embedding worker.

use std::sync::Arc;

use crate::config::ServeConfig;
use crate::server::SyncServer;

/// `server`, holding the embedder `config` names, built as serve builds it
/// for the server's vault ([`crate::commands::build_embedder`]).
///
/// # Errors
///
/// The build's: a section that does not resolve, or an endpoint that fails
/// its startup probe.
pub async fn with_served_embedder(
    server: SyncServer,
    config: &ServeConfig,
) -> anyhow::Result<SyncServer> {
    let built = crate::commands::build_embedder(server.vault(), config, None).await?;
    Ok(server.with_embedder(built.slot))
}

/// Spawns `server`'s embedding worker, as serve does: `None` with no
/// embedder.
#[must_use]
pub fn spawn_embedding_worker(server: &Arc<SyncServer>) -> Option<tokio::task::JoinHandle<()>> {
    server.spawn_embedding_worker()
}
