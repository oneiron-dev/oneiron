//! Doors for `tests/embedder_host_line_notice.rs` (0053-EMB, on census
//! L1-27): a server holding an endpoint embedder slot bound to its vault's
//! background line, as serve binds it, and the paid door of a remote rung on
//! that slot's line.

use std::sync::Arc;

use oneiron::llm::run_admission::RunReceiptSink;

use crate::config::{EmbedderConfig, EmbedderProvider, EndpointEmbedderConfig};
use crate::embedder::EmbedderSlot;
use crate::server::SyncServer;

/// `server`, holding an endpoint embedder slot bound to the server vault's
/// background line, as serve binds the slot it builds
/// (`commands::build_embedder`). The slot's endpoint is never probed or
/// called here. Call it off the runtime's async threads, as serve builds its
/// slot: the slot's blocking HTTP client panics when built in async code.
///
/// # Errors
///
/// The slot's build, or the resolution of the vault's system principal.
pub fn with_bound_endpoint_slot(server: SyncServer) -> anyhow::Result<SyncServer> {
    let config = EmbedderConfig {
        provider: EmbedderProvider::Endpoint,
        endpoint: EndpointEmbedderConfig {
            endpoint: Some("http://127.0.0.1:9/v1".to_owned()),
            model_key: Some("embedding-model".to_owned()),
            ..EndpointEmbedderConfig::default()
        },
        ..EmbedderConfig::default()
    };
    let slot = EmbedderSlot::with_broker(&config, None)?
        .ok_or_else(|| anyhow::anyhow!("an endpoint section builds a slot"))?;
    slot.bind_background_line(server.vault())?;
    Ok(server.with_embedder(Some(slot)))
}

/// Sends `texts` through the paid door of a third-party remote rung on the
/// line of `server`'s embedder slot (the host's pushed line, else the vault's
/// background line), as the embedding worker's rung sends a batch, its run
/// rows written to `receipts`. `post` stands in for the request, and the door
/// calls it only once it admits the request. What the door answers: the
/// vectors `post` returned, or why it refused.
///
/// # Errors
///
/// The server holds no embedder slot, or the door refused the request.
pub fn send_as_remote_rung(
    server: &SyncServer,
    receipts: Arc<dyn RunReceiptSink>,
    texts: &[&str],
    post: &mut dyn FnMut() -> oneiron::Result<Vec<Vec<f32>>>,
) -> oneiron::Result<Vec<Vec<f32>>> {
    server
        .embedder_slot()
        .ok_or(oneiron::Error::InvariantViolation(
            "the server holds no embedder slot",
        ))?
        .send_as_remote_rung(receipts, texts, post)
}
