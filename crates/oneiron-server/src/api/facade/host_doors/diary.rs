//! The caller's own diary query door (`self.memory.diary.query`).
//! `self_memory_diary_query` is its call surface.
//! The engine's diary read (`oneiron::memory`) defines the records forwarded here.

use std::sync::Arc;

use super::support::{Listed, credential_listing, diary_reader, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `self.memory.diary.query`: the caller reads an agent's diary, stating a
/// reason the agent sees in its read log (`Memory::read_agent_diary`). The
/// caller's `diary.read` Grants decide what it gets. A person reads with
/// their authentication: the vault owner's own credential carries the proof
/// `/v1/owner` takes from the request, and any other verified human carries
/// their own person proof ([`crate::api::facade::shared_act_doors::person`], OF-490), so
/// their own Grant decides. Any other caller passes none and the engine door
/// decides: an agent or system reads as itself, and a person without a proof
/// is refused. Beside it, the rows its reads listed.
pub(crate) async fn self_memory_diary_query(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::task_verb::sdk::DiaryQueryRequest,
) -> Listed<oneiron::task_verb::sdk::DiaryQueryOutcome> {
    const VERB: &str = "self.memory.diary.query";
    let caller = match diary_reader(server, auth) {
        Ok(caller) => caller,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(server, auth, caller, VERB, move |server, auth, memory| {
        let proof = crate::api::facade::shared_act_doors::person(server, auth, VERB).ok();
        oneiron::task_verb::sdk::diary_query_as(&memory, proof.as_ref(), input)
    })
    .await
}
