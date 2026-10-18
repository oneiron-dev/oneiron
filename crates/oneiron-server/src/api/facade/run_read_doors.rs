//! Owner-only reads of committed run state (DOOR-141 A/B): a settled model
//! step and a code run's checkpoints, over the caller's own credential read
//! lane. Neither executes, admits, resumes or leases anything.
use std::sync::Arc;

use oneiron::engine_executor::checkpoint_read::{
    CheckpointReadRequest, CheckpointView, checkpoint_as_owner,
};
use oneiron::llm::model_step::{SettledStepRequest, SettledStepView, settled_step_as_owner};
use oneiron::runtime_hooks::InvocationId;
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::{Listed, credential_listing, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_runs_step(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: SettledStepRequest,
) -> Listed<Option<SettledStepView>> {
    const VERB: &str = "vault.runs.step";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        settled_step_as_owner(&memory, &owner, &input)
    })
    .await
}

pub(crate) async fn vault_runs_checkpoint(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: CheckpointReadRequest,
) -> Listed<Option<CheckpointView>> {
    const VERB: &str = "vault.runs.checkpoint";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        checkpoint_as_owner(&memory, &owner, &input)
    })
    .await
}
