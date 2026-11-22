//! The host door of the owner's answer to a resumed pending step whose re-entered program changed
//! an effect step (L8-23): `vault.code_run.resume_divergence.answer`, the one-tap actions of the
//! inbox ask the hold raised. `host_doors` re-exports it, so the generated HTTP facade handler and
//! the MCP dispatcher call it by the name every host door has, and a tool call, a code-mode call
//! and an SDK call meet one admission: the vault owner's proof, as `/v1/owner` takes it, never a
//! person's or an agent's. The engine door rechecks that proof in its writer. It lists the run it
//! answered (`host_door_lists`).
use std::sync::Arc;

use oneiron::task_verb::sdk::{self, ResumeDivergenceAnswer, ResumeDivergenceAnswered};

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.code_run.resume_divergence.answer`: the owner re-fires a held resume's changed effect
/// steps once or leaves them, listing its run.
pub(crate) async fn vault_code_run_resume_divergence_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ResumeDivergenceAnswer,
) -> Listed<ResumeDivergenceAnswered> {
    as_owner_naming(
        server,
        auth,
        "vault.code_run.resume_divergence.answer",
        move |server, owner| {
            sdk::answer_code_run_resume_divergence_as(server.vault(), owner, input)
        },
        |answered| vec![answered.run_ref],
    )
    .await
}
