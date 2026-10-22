//! `vault.packs.preview` (FIX 5493): the owner's look at a pack folder
//! before he puts it, under the proof `/v1/owner` takes from the request.
//! The generated HTTP and MCP dispatchers both enter here.

use std::sync::Arc;

use oneiron::memory::MemoryResult;
use oneiron::skill_hub::pack_catalog::PackImportPreview;
use oneiron::task_verb::sdk::PackPreviewRequest;

use super::host_doors::support::{internal, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.packs.preview`: the world a travelling agent would land in when
/// its current setting does not cover this machine; stages and writes
/// nothing.
pub(crate) async fn vault_packs_preview(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PackPreviewRequest,
) -> MemoryResult<PackImportPreview> {
    let owner = owner_proof(auth, server, "vault.packs.preview")?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        oneiron::task_verb::sdk::pack_preview_as_owner(server.vault(), &owner, input)
    })
    .await
    .map_err(|_| internal("vault.packs.preview"))?
}
