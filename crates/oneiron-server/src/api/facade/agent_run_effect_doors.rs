//! The host door of the owner's answer to a call a moved agent run replays
//! (FIX 4747 slice 7): `vault.agent.run_effect.answer`, the one-tap actions
//! of the inbox ask a run's replayed step raised when the machine that ran
//! it before may already have made the call. `host_doors` re-exports it, so
//! the generated HTTP facade handler and the MCP dispatcher call it by the
//! name every host door has, and a tool call, a code-mode call and an SDK
//! call meet one admission: the vault owner's proof, as `/v1/owner` takes
//! it, never a person's or an agent's. The engine door rechecks that proof
//! in its writer. It lists the run TASK it answered (`host_door_lists`).
use std::sync::Arc;

use oneiron::task_verb::sdk::{self, AgentRunEffectAnswer, AgentRunEffectAnswered};

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.agent.run_effect.answer`: the owner makes a replayed call once
/// more or leaves it, listing its run TASK.
pub(crate) async fn vault_agent_run_effect_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AgentRunEffectAnswer,
) -> Listed<AgentRunEffectAnswered> {
    as_owner_naming(
        server,
        auth,
        "vault.agent.run_effect.answer",
        move |server, owner| sdk::answer_agent_run_effect_as(server.vault(), owner, input),
        |answered| vec![answered.task_ref],
    )
    .await
}
