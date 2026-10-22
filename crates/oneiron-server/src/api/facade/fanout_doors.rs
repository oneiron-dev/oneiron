//! The host doors of the owner's fan-out rulings (OF-393): `vault.fanout.resume`
//! on a held launch and `vault.fanout.ack` on the width check of one that went
//! out. `host_doors` re-exports them, so the generated HTTP facade handler and
//! the MCP dispatcher call them by the name every host door has, and a paired
//! owner meets the admission `/v1/owner` has: the vault owner's proof
//! (`owner_routes::owner`). The engine door revalidates that proof inside its
//! own transaction. An embedded handle keeps its embedded-owner call.
//!
//! `vault.fanout.resume_as` is the same ruling by a live lead or board holder
//! of the launch's bound project, acting as the slip's principal with its
//! declared class (`decision_ask_doors::holder`); the engine verifies the
//! writer and reads the role again in its transaction.
//!
//! Each keeps its proof's own handle, and answers beside the rows that
//! handle's reads listed (`host_door_lists`). The ruling runs as on any
//! surface the proof came from; a caller off this device whose answer would
//! carry a row that stays here hears only that it ran (FIX 3414,
//! [`crate::device_local::act_answer`]).
use std::sync::Arc;

use oneiron::EdgeActorClass;
use oneiron::task_verb::sdk::{
    self, ActAnswer, FanoutAckRequest, FanoutLaunchView, FanoutResumeRequest,
};

use super::host_doors::support::{Listed, off_runtime_listing, refused};
use super::legal_hold_doors::as_owner_listing;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.fanout.resume`: the owner approves a held launch once, approves
/// and remembers it under a cap, or denies it, by the digest they saw.
pub(crate) async fn vault_fanout_resume(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FanoutResumeRequest,
) -> Listed<ActAnswer<FanoutLaunchView>> {
    let answer = as_owner_listing(
        server,
        auth,
        "vault.fanout.resume",
        move |server, owner, producers| {
            let memory = server
                .vault()
                .memory(owner.revalidate(server.vault())?, EdgeActorClass::Human)
                .listing_producers(producers);
            sdk::resume_fanout_launch_as(&memory, owner, input)
        },
    )
    .await;
    crate::device_local::act_answer(server.vault(), &auth.destination(), answer)
}

/// `vault.fanout.resume_as`: a live holder of a held launch's bound lead or
/// board role approves it once or denies it, by the digest it saw. Only the
/// owner remembers.
pub(crate) async fn vault_fanout_resume_as(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FanoutResumeRequest,
) -> Listed<ActAnswer<FanoutLaunchView>> {
    const VERB: &str = "vault.fanout.resume_as";
    let holder = match super::decision_ask_doors::holder(auth, VERB) {
        Ok(holder) => holder,
        Err(refusal) => return refused(refusal),
    };
    let held = Arc::clone(server);
    let answer = off_runtime_listing(VERB, move |producers| {
        let memory = held
            .vault()
            .memory(holder.entity_ref(), holder.actor_class())
            .listing_producers(producers);
        sdk::resume_fanout_launch_as_holder(&memory, &holder, input)
    })
    .await;
    crate::device_local::act_answer(server.vault(), &auth.destination(), answer)
}

/// `vault.fanout.ack`: the owner acknowledges a launched fan-out's width
/// check, once or remembered under a cap.
pub(crate) async fn vault_fanout_ack(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FanoutAckRequest,
) -> Listed<ActAnswer<FanoutLaunchView>> {
    let answer = as_owner_listing(
        server,
        auth,
        "vault.fanout.ack",
        move |server, owner, producers| {
            let memory = server
                .vault()
                .memory(owner.revalidate(server.vault())?, EdgeActorClass::Human)
                .listing_producers(producers);
            sdk::ack_fanout_check_as(&memory, owner, input)
        },
    )
    .await;
    crate::device_local::act_answer(server.vault(), &auth.destination(), answer)
}
