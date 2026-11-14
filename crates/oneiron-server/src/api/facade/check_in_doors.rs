//! The host door of `vault.check_in.answer` (ROLES-CHECKIN P2.3c, piece 2l;
//! Engine ruling P23-SHAPE Q9 = A): a person pinned on a pending check-in's
//! current rung answers it on their own proof. `host_doors` re-exports it,
//! so the generated HTTP facade handler and the MCP dispatcher call it by
//! the name every host door has.
//!
//! The proof is a member's own, as `vault.workflows.dispatch_bound` takes it
//! (`agent_definition_doors::member_proof`): the vault owner as the owner
//! door admits them, or any other live person on their own verified human
//! slip, bound to it so the engine rechecks that slip in the answering
//! writer. The engine then judges the answer: the exact effect, the person
//! pinned on the current rung, and their live grant and own check-in.

use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::MemoryResult;
use oneiron::task_verb::sdk::{self, CheckInAnswerRequest, CheckInSettlement};

use super::host_doors::support::internal;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

const ANSWER_VERB: &str = "vault.check_in.answer";

/// The proof a check-in holder answers on: a live person's own, bound to
/// their slip ([`super::agent_definition_doors::member_proof`]).
pub(super) fn holder_proof(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<AuthenticatedOwner> {
    super::agent_definition_doors::member_proof(server, auth, verb)
}

/// `vault.check_in.answer`: the person approves or denies the exact effect
/// one pending check-in waits on; the engine settles it in one writer, or
/// echoes their same answer.
pub(crate) async fn vault_check_in_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CheckInAnswerRequest,
) -> MemoryResult<CheckInSettlement> {
    let person = holder_proof(server, auth, ANSWER_VERB)?;
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || -> MemoryResult<CheckInSettlement> {
        sdk::check_in_answer_as_person(server.vault(), &person, input)
    })
    .await
    .map_err(|_| internal(ANSWER_VERB))?
}
