//! The host doors of an agent's witness-read grant over a connector
//! conversation: `vault.connectors.read_grants.revoke` (FIX 10895) and
//! `vault.connectors.read_grants.grant` (FIX 10962). `host_doors`
//! re-exports them, so the generated HTTP facade handler and the MCP
//! dispatcher call each by the name every host door has, and a tool call, a
//! code-mode call and an SDK call meet one admission: the vault owner's
//! proof (`facade_owner`), never a person's or an agent's. The engine door
//! rechecks that proof in its own write. Each lists the grant row it names.
use std::sync::Arc;

use oneiron::task_verb::sdk::{
    self, ConnectorWitnessReadGrantRequest, ConnectorWitnessReadGrantRevokeRequest,
    ConnectorWitnessReadGrantRevoked, ConnectorWitnessReadGranted,
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

/// `vault.connectors.read_grants.grant`: the owner grants one agent its
/// witness-read grant once more, listing the grant row it names.
pub(crate) async fn vault_connectors_read_grants_grant(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ConnectorWitnessReadGrantRequest,
) -> Listed<ConnectorWitnessReadGranted> {
    as_owner_naming(
        server,
        auth,
        "vault.connectors.read_grants.grant",
        move |server, owner| {
            sdk::grant_connector_witness_read_grant_as(server.vault(), owner, input)
        },
        |granted| vec![granted.grant_ref],
    )
    .await
}
