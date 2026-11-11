//! The host door of the owner's answer to a send that may have gone out (FIX
//! 4747): `vault.outbound.uncertain_send.answer`, the one-tap actions of the
//! inbox ask a connector-send TASK raised when no provider lookup could tell
//! whether its send went. `host_doors` re-exports it, so the generated HTTP
//! facade handler and the MCP dispatcher call it by the name every host door
//! has, and a tool call, a code-mode call and an SDK call meet one admission:
//! the vault owner's proof, as `/v1/owner` takes it, never a person's or an
//! agent's. The engine door rechecks that proof in its writer. It lists the
//! TASK it answered (`host_door_lists`).
use std::sync::Arc;

use oneiron::task_verb::sdk::{self, UncertainSendAnswer, UncertainSendAnswered};

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.outbound.uncertain_send.answer`: the owner sends an uncertain send
/// once more or leaves it, listing its TASK.
pub(crate) async fn vault_outbound_uncertain_send_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: UncertainSendAnswer,
) -> Listed<UncertainSendAnswered> {
    as_owner_naming(
        server,
        auth,
        "vault.outbound.uncertain_send.answer",
        move |server, owner| sdk::answer_uncertain_send_as(server.vault(), owner, input),
        |answered| vec![answered.task_ref],
    )
    .await
}
