//! Reads of committed run state (DOOR-141 A/B): a settled model step, a code
//! run's checkpoints and a code run step's kept model reply, over the
//! caller's own credential read lane. The
//! owner reads any run on its proof; another person or agent reads a run it is
//! the actor of (primitive A, slice 6.4c). Neither executes, admits, resumes
//! or leases anything.
use std::sync::Arc;

use oneiron::engine_executor::checkpoint_read::{
    CheckpointReadRequest, CheckpointView, checkpoint_as_owner,
};
use oneiron::engine_executor::reply_evidence::{
    ReplyEvidenceRequest, ReplyEvidenceView, reply_evidence_as_owner,
};
use oneiron::llm::model_step::{SettledStepRequest, SettledStepView, settled_step_as_owner};
use oneiron::runtime_hooks::InvocationId;
use oneiron::snapshot_read::{
    checkpoint_as_reader, reply_evidence_as_reader, settled_step_as_reader,
};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::{Listed, credential_listing, owner_proof, refused};
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
    let owner = match run_reader(server, auth, VERB) {
        Ok(owner) => owner,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(
        server,
        auth,
        caller,
        VERB,
        move |_, _, memory| match &owner {
            Some(owner) => settled_step_as_owner(&memory, owner, &input),
            None => settled_step_as_reader(&memory, &input),
        },
    )
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
    let owner = match run_reader(server, auth, VERB) {
        Ok(owner) => owner,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(
        server,
        auth,
        caller,
        VERB,
        move |_, _, memory| match &owner {
            Some(owner) => checkpoint_as_owner(&memory, owner, &input),
            None => checkpoint_as_reader(&memory, &input),
        },
    )
    .await
}

pub(crate) async fn vault_code_reply_evidence(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: ReplyEvidenceRequest,
) -> Listed<Option<ReplyEvidenceView>> {
    const VERB: &str = "vault.code.reply_evidence";
    let owner = match run_reader(server, auth, VERB) {
        Ok(owner) => owner,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(
        server,
        auth,
        caller,
        VERB,
        move |_, _, memory| match &owner {
            Some(owner) => reply_evidence_as_owner(&memory, owner, &input),
            None => reply_evidence_as_reader(&memory, &input),
        },
    )
    .await
}

/// Who reads a committed run: the owner under its proof (`Some`), or a person
/// or agent on a verified slip of its own (`None`), whose run the engine
/// reader checks. Anyone else keeps the owner refusal it had.
pub(super) fn run_reader(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> oneiron::memory::MemoryResult<Option<oneiron::consent::AuthenticatedOwner>> {
    use oneiron::EdgeActorClass::{Agent, Human};
    match owner_proof(auth, server, verb) {
        Ok(owner) => Ok(Some(owner)),
        Err(refusal) => match (auth.verified_slip(), super::facade_actor(server, auth)) {
            (Some(_), Ok((_, Human | Agent))) => Ok(None),
            _ => Err(refusal),
        },
    }
}
