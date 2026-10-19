//! The host door of the owner's historical secret lift sweep,
//! `vault.secrets.lift_history` (OF-067). `host_doors` re-exports it, so the
//! generated HTTP facade handler and the MCP dispatcher call it by the name
//! every host door has. It takes the vault owner's proof as `/v1/owner` takes
//! it (`owner_routes::owner`); the engine checks the owner again in its own
//! transaction.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::memory::MemoryError;
use oneiron::policy_model::{SecretLiftRequest, SecretLiftStatus, secret_lift_as_owner};

use super::host_doors::{Listed, internal, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

const VERB: &str = "vault.secrets.lift_history";

/// `vault.secrets.lift_history`: the sweep's run in progress, its last
/// receipt and the lift proposals still open, after queueing a run when the
/// input's `start` asks for one. It lists each record a proposal it shows
/// was filed from (`record:<id>`): the proposal's reason and suggested name
/// come from that record. The run, its receipt, its counts and the proposals
/// live in the sweep's side tables, which hold no row.
pub(crate) async fn vault_secrets_lift_history(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SecretLiftRequest,
) -> Listed<SecretLiftStatus> {
    let owner = match super::owner_binding::facade_owner(server, auth, VERB) {
        Ok(owner) => owner,
        Err(refusal) => return refused(refusal),
    };
    let server = Arc::clone(server);
    let answer = tokio::task::spawn_blocking(move || {
        secret_lift_as_owner(server.vault(), &owner, &input).map_err(MemoryError::from)
    })
    .await
    .unwrap_or_else(|_| Err(internal(VERB)));
    let rows = answer
        .as_ref()
        .map_or_else(|_| Vec::new(), proposal_records);
    (answer, rows)
}

/// The record each proposal `status` shows was filed from; a side-table or
/// carrier proposal names none.
fn proposal_records(status: &SecretLiftStatus) -> Vec<EntityId> {
    status
        .proposals
        .iter()
        .filter_map(|shown| shown.proposal.path.strip_prefix("record:"))
        .filter_map(|hex| EntityId::from_hex(hex).ok())
        .collect()
}
