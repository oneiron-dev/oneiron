//! The caller's own diary query door (`self.memory.diary.query`), and the
//! sealed-pad doors on a person's own proof (`self.memory.pads.read`,
//! `self.memory.pads.admin_reads`, FIX 12143).
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

/// `self.memory.pads.read`: the caller reads an agent's sealed scratchpads
/// as a ruled reader, stating a reason the agent sees in its read log
/// (`Memory::read_agent_sealed_pads`, FIX 12143). A person reads on their
/// own person proof ([`crate::api::facade::shared_act_doors::person`]): the
/// vault owner's, or a work vault Admin's, whom the engine admits through
/// the same logged step. An agent or system passes none and reads as itself.
/// `/v1/owner/pads/read` stays the owner's own route. Beside it, the rows its
/// reads listed.
pub(crate) async fn self_memory_pads_read(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::task_verb::sdk::DiaryQueryRequest,
) -> Listed<oneiron::task_verb::sdk::DiaryQueryOutcome> {
    const VERB: &str = "self.memory.pads.read";
    let caller = match diary_reader(server, auth) {
        Ok(caller) => caller,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(server, auth, caller, VERB, move |server, auth, memory| {
        let proof = crate::api::facade::shared_act_doors::person(server, auth, VERB).ok();
        oneiron::task_verb::sdk::pads_read_as(&memory, proof.as_ref(), input)
    })
    .await
}

/// `self.memory.pads.admin_reads`: the companion's owner reads the reads a
/// work vault's Admin made of an agent's sealed pads (`Memory::admin_pad_reads`,
/// FIX 12143), on their own person proof
/// ([`crate::api::facade::shared_act_doors::person`]); the engine admits the
/// companion's owner alone. Beside it, the rows its reads listed.
pub(crate) async fn self_memory_pads_admin_reads(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::task_verb::sdk::AdminPadReadsRequest,
) -> Listed<oneiron::task_verb::sdk::AdminPadReadsView> {
    const VERB: &str = "self.memory.pads.admin_reads";
    let caller = match diary_reader(server, auth) {
        Ok(caller) => caller,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(server, auth, caller, VERB, move |server, auth, memory| {
        let proof = crate::api::facade::shared_act_doors::person(server, auth, VERB)?;
        oneiron::task_verb::sdk::admin_pad_reads_as(&memory, &proof, input)
    })
    .await
}
