//! FIX 987: the owner's slate re-draft and a key holder's own narrow, shared
//! by HTTP, SDK and MCP.
use std::sync::Arc;

use oneiron::memory::MemoryError;
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::{
    ConnectorSlateNarrowRequest, ConnectorSlateNarrowView, ConnectorSlateRedraftReply,
    ConnectorSlateRedraftRequest, narrow_connector_slate_as,
};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::{Listed, internal};
use super::legal_hold_doors::as_owner_naming;
use crate::api::owner_routes::connector_slate_routes::redraft_slate;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.connectors.slates.redraft`: the owner's re-draft, through the
/// host's configured drafter. It reads the slate and the past rulings, side
/// tables that hold no row, so it lists none.
pub(crate) async fn vault_connectors_slates_redraft(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ConnectorSlateRedraftRequest,
) -> Listed<ConnectorSlateRedraftReply> {
    as_owner_naming(
        server,
        auth,
        "vault.connectors.slates.redraft",
        move |server, owner| redraft_slate(server, owner, input).map_err(MemoryError::from),
        |_| Vec::new(),
    )
    .await
}

/// `vault.connectors.slates.narrow`: the authenticated caller, as the key's
/// holder, tightens what its own key's calls meet. It lists the key and, for
/// a per-grant key, the grant it read.
pub(crate) async fn vault_connectors_slates_narrow(
    server: &Arc<SyncServer>,
    _auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: ConnectorSlateNarrowRequest,
) -> Listed<ConnectorSlateNarrowView> {
    const VERB: &str = "vault.connectors.slates.narrow";
    let server = Arc::clone(server);
    let (holder, _) = caller;
    let ran = tokio::task::spawn_blocking(move || {
        narrow_connector_slate_as(server.vault(), holder, input)
    })
    .await;
    match ran {
        Ok(Ok((view, rows))) => (Ok(view), rows),
        Ok(Err(error)) => (Err(error), Vec::new()),
        Err(_) => (Err(internal(VERB)), Vec::new()),
    }
}
