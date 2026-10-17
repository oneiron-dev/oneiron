//! The weave lens's host doors (OF-499): the one-tap wrong control a person
//! uses on a link in their own report, and the live report rendered into its
//! lens on this server's model. The generated HTTP facade handler and the
//! MCP dispatcher both call these through `host_doors`.
use std::sync::Arc;

use oneiron::claim::{WeaveLinkCorrectionView, WeaveReportRequest, WeaveWrongLinkRequest};
use oneiron::lens::LensFrameCard;
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

/// `vault.weave.lens`: the credential's own live weave report, rendered
/// through the weave-report skill into its lens on this server's Dreamer
/// narrative route, as a card whose frame this server holds for the
/// credential's events on it. A person reads the person lens, an agent its
/// own; the owner lens is `POST /v1/owner/weave/lens`. The step spends on
/// the caller's own line.
pub(crate) async fn vault_weave_lens(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WeaveReportRequest,
) -> MemoryResult<LensFrameCard> {
    const VERB: &str = "vault.weave.lens";
    let (actor, class) = super::facade_actor(auth).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{VERB} renders the credential's own lens"),
            &["Present a person's or an agent's own credential."],
        )
    })?;
    crate::ai_host::render_live_weave_lens(
        server,
        crate::ai_host::WeaveLensCaller::Credential {
            auth: auth.clone(),
            actor,
            class,
        },
        input,
    )
    .await
}
