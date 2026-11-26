//! Doors for `tests/endpoint_model_floors.rs` (EMBEDDER-ENDPOINT-VECTOR-FLOORS): a served
//! embedder made ready and admitted by the server's vault, as the server's embedding worker and
//! query path make it.

use crate::server::SyncServer;

/// Makes `server`'s embedder ready for its vault and admits it there, as the server's own
/// callers do (`EmbedderSlot::ensure_ready_for`): the vault is then judged by the floors the
/// admitted provider serves. Call it off the runtime's async threads (`spawn_blocking`), as the
/// server does: the slot's HTTP client blocks.
///
/// # Errors
///
/// The server holds no embedder, or the provider is not admitted.
pub fn admit_served_embedder(server: &SyncServer) -> anyhow::Result<()> {
    let slot = server
        .embedder_slot()
        .ok_or_else(|| anyhow::anyhow!("the server holds no embedder"))?;
    slot.ensure_ready_for(server.vault())?;
    Ok(())
}
