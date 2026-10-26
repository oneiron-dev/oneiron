//! The host door of an agent's witness-read grant over a connector
//! conversation (FIX 10895): `vault.connectors.read_grants.revoke`.
//! `host_doors` re-exports it, so the generated HTTP facade handler and the
//! MCP dispatcher call it by the name every host door has, and a tool call,
//! a code-mode call and an SDK call meet one admission: the vault owner's
//! proof (`facade_owner`), never a person's or an agent's. The engine door
//! rechecks that proof before it revokes. It lists the grant row it names.
use std::sync::Arc;

use oneiron::task_verb::sdk::{
    self, ConnectorWitnessReadGrantRevokeRequest, ConnectorWitnessReadGrantRevoked,
};

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.connectors.read_grants.revoke`: the owner revokes one agent's
/// witness-read grant, listing the grant row it names.
pub(crate) async fn vault_connectors_read_grants_revoke(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ConnectorWitnessReadGrantRevokeRequest,
) -> Listed<ConnectorWitnessReadGrantRevoked> {
    as_owner_naming(
        server,
        auth,
        "vault.connectors.read_grants.revoke",
        move |server, owner| {
            sdk::revoke_connector_witness_read_grant_as(server.vault(), owner, input)
        },
        |revoked| vec![revoked.grant_ref],
    )
    .await
}
