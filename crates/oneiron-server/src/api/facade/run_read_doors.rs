//! Reads of committed run state (DOOR-141 A/B): a settled model step, a code
//! run's checkpoints and a code run step's kept model reply, over the
//! caller's own credential read lane, and one job (L10-05), also at canon's
//! `GET /v1/core/jobs/{job_id}` (0002c §6.1.13). The
//! owner reads any run on its proof; another person or agent reads a run it is
//! the actor of (primitive A, slice 6.4c). Neither executes, admits, resumes
//! or leases anything.
use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{Extensions, HeaderMap};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
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
use oneiron::task_verb::run_doors::{
    RunBranchView, RunJobRequest, RunJobView, read_job_as, read_job_as_reader,
};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::{Listed, MaybeListed, credential_listing, owner_proof, refused};
use super::shared_act_doors::as_person_naming;
use super::{FacadeCall, call_verb};
use crate::auth::CoreAuth;
use crate::error::ApiErrorEnvelope;
use crate::server::SyncServer;

/// The verb the job route serves.
const JOB_VERB: &str = "vault.runs.job";

/// The job route: canon's core job read over the `vault.runs.job` verb.
pub(crate) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/v1/core/jobs/{job_id}", get(get_core_job))
}

/// Read one job: one attempt row, its state, kind, parent, TASK, times,
/// result reference and error. It is `vault.runs.job` on its path's id,
/// run through the facade's own dispatch, so its scope, record scope, run
/// reader proof, hooks and reply release are the verb's.
#[utoipa::path(
    get,
    path = "/v1/core/jobs/{job_id}",
    params(
        (
            "job_id" = String,
            Path,
            description = "The job's attempt id as 32 hex, as the run tree names it.",
            example = "0123456789abcdef0123456789abcdef"
        )
    ),
    responses(
        (status = 200, description = "`{\"job\": ...}`: the attempt row as `vault.runs.job` answers it. The result is `job.result_ref`, the reference the producer wrote, or null.", body = Object, content_type = "application/json"),
        (status = 400, description = "The job id is not 32 hex.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "The credential lacks core:read or is narrowed to facets or records, or the job is not the caller's.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "No job has this id (the owner's read).", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn get_core_job(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
    extensions: Extensions,
    Path(job_id): Path<String>,
) -> Response {
    let call = FacadeCall::http(&server, &auth, &headers, &extensions);
    let input = serde_json::json!({ "job": job_id });
    match call_verb(&server, &call, JOB_VERB, Ok(input)).await {
        Ok(output) => super::release::released_reply(&server, &auth, JOB_VERB, output),
        Err(refusal) => refusal.into_response(),
    }
}

/// `vault.runs.job`: one job, as the run reads admit it (ENGINE CALL S64-3 =
/// A). The owner's read lists the job's TASK, as the branch read lists its
/// TASK; a slip's read lists what its own lane read.
pub(crate) async fn vault_runs_job(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: RunJobRequest,
) -> MaybeListed<RunJobView> {
    match run_reader(server, auth, JOB_VERB) {
        Ok(Some(owner)) => {
            as_person_naming(
                server,
                JOB_VERB,
                Ok(owner),
                move |server, owner| read_job_as(server.vault(), &owner, input),
                |read| job_rows(&read.job),
            )
            .await
        }
        Ok(None) => {
            let (answer, rows) =
                credential_listing(server, auth, caller, JOB_VERB, move |_, _, memory| {
                    read_job_as_reader(&memory, input)
                })
                .await;
            (answer, Some(rows))
        }
        Err(refusal) => (Err(refusal), Some(Vec::new())),
    }
}

/// The TASK a job realizes, when it realizes one; unknown when its stored
/// TASK ref does not parse.
fn job_rows(job: &RunBranchView) -> Option<Vec<EntityId>> {
    match &job.task_ref {
        None => Some(Vec::new()),
        Some(task) => EntityId::from_hex(task).ok().map(|task| vec![task]),
    }
}

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
