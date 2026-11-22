//! The host door of the owner's erase of one subject's authority attribution
//! (census L5-22 1b): `vault.authority.attribution.erase`. `host_doors`
//! re-exports it, so the generated HTTP facade handler and the MCP
//! dispatcher call it by the name every host door has. The vault owner's
//! proof, as `/v1/owner` takes it, is bound before the engine writer runs;
//! the engine door rechecks that proof in its own writer before erasing.
use std::sync::Arc;

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;
use oneiron::task_verb::sdk;

pub(crate) async fn vault_authority_attribution_erase(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: sdk::AuthorityAttributionEraseRequest,
) -> Listed<sdk::AuthorityAttributionErased> {
    as_owner_naming(
        server,
        auth,
        "vault.authority.attribution.erase",
        move |server, owner| {
            sdk::erase_authority_attribution_as_owner(server.vault(), owner, input)
        },
        |_| Vec::new(),
    )
    .await
}
