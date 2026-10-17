//! The weave lens's human doors (OF-499): the one-tap wrong control a person
//! uses on a link in their own report. The generated HTTP facade handler and
//! the MCP dispatcher both call these through `host_doors`.
use std::sync::Arc;

use oneiron::claim::{WeaveLinkCorrectionView, WeaveWrongLinkRequest};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};

use super::host_doors::internal;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.weave.link.wrong`: a live person labels a link in their own
/// person lens as wrong, under their own proof. The label is not a
/// retraction; the loops learn from it. An agent's credential carries no
/// person proof, so it is refused here, as the engine refuses an agent
/// reader.
pub(crate) async fn vault_weave_link_wrong(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WeaveWrongLinkRequest,
) -> MemoryResult<WeaveLinkCorrectionView> {
    const VERB: &str = "vault.weave.link.wrong";
    let proof = super::shared_act_doors::person(server, auth, VERB)?;
    let (actor, class) = super::facade_actor(auth).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{VERB} labels a link in the credential's own lens"),
            &["Present your own verified human credential."],
        )
    })?;
    let server = Arc::clone(server);
    let auth = auth.clone();
    tokio::task::spawn_blocking(move || {
        crate::api::credential_memory(&server.vault, Some(&auth), actor, class)
            .at(auth.locality())
            .weave_wrong_link(None, &proof, &input)
    })
    .await
    .map_err(|_| internal(VERB))?
}
