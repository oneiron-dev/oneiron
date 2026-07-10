use super::core_engine_error;
use super::hex_bytes;
use super::json_payload;
use super::query_params;
use super::unix_seconds_now;
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiError;
use crate::error::ApiErrorEnvelope;
use crate::error::EnvelopedApiError;
use crate::server::SyncServer;
use axum::extract::Query;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::extract::rejection::QueryRejection;
use axum::response::Json;
use serde::Deserialize;
use serde::Serialize;
use std::sync::Arc;
use utoipa::IntoParams;
use utoipa::ToSchema;

pub(crate) const CORE_RUN_TREE_RUN_ID_MAX_BYTES: usize = 128;

/// Query parameters for the runtime run-tree projection.
#[derive(Debug, Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct CoreRunTreeQuery {
    /// Runtime run id to filter the tree. Unfiltered HTTP reads are rejected to
    /// avoid unbounded queue scans.
    #[serde(default, rename = "run_id", alias = "runId")]
    #[schema(example = "run-2026-07-03T12:00:00Z")]
    #[param(required = true, example = "run-2026-07-03T12:00:00Z")]
    run_id: Option<String>,
}

/// Request body for run-tree intervention.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "job_id": "0123456789abcdef0123456789abcdef",
    "kind": "pause",
    "note": "operator requested a checkpoint"
}))]
pub(crate) struct CoreRunTreeInterventionRequest {
    /// Hex-encoded job id to intervene on.
    #[serde(rename = "job_id", alias = "jobId")]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    job_id: String,
    /// Intervention primitive to apply.
    kind: CoreRunTreeInterventionKind,
    /// Optional operator note recorded on the event.
    #[serde(default)]
    #[schema(example = "operator requested a checkpoint")]
    note: Option<String>,
}

/// Intervention primitive for a runtime job.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoreRunTreeInterventionKind {
    Interrupt,
    Pause,
    Resume,
    Cancel,
}

/// Response from a run-tree intervention.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreRunTreeInterventionResponse {
    /// Hex-encoded job id that was targeted.
    #[serde(rename = "job_id")]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    job_id: String,
    /// Run id carried by the affected row, when present.
    #[serde(rename = "run_id")]
    #[schema(example = "run-2026-07-03T12:00:00Z")]
    run_id: Option<String>,
    /// Requested intervention primitive.
    kind: CoreRunTreeInterventionKind,
    /// Durable effect of the request.
    effect: CoreRunTreeInterventionEffect,
    /// Fresh snapshot for the affected run, when the job row has a run id.
    tree: Option<CoreRunTreeResponse>,
}

/// Observable intervention effect.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoreRunTreeInterventionEffect {
    Interrupted,
    Paused,
    AlreadyPaused,
    Resumed,
    AlreadyResumed,
    Cancelled,
    AlreadyCancelled,
}

/// Runtime job tree response.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreRunTreeResponse {
    /// Root jobs after non-mutating repair of missing parents or cycles.
    roots: Vec<CoreRunTreeNode>,
    /// Repairs applied while rendering the tree from queue rows.
    repairs: Vec<CoreRunTreeRepair>,
}

/// One runtime job in the rendered tree.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreRunTreeNode {
    /// Hex-encoded job id.
    #[serde(rename = "job_id")]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    job_id: String,
    /// Runtime run id carried by the backing job row.
    #[serde(rename = "run_id")]
    #[schema(example = "run-2026-07-03T12:00:00Z")]
    run_id: Option<String>,
    /// Hex-encoded parent job id when the runner recorded one.
    #[serde(rename = "parent_id")]
    #[schema(example = "11111111111111111111111111111111")]
    parent_id: Option<String>,
    /// Worker kind exposed by the row or runner payload.
    #[serde(rename = "worker_kind")]
    #[schema(example = "orchestrator")]
    worker_kind: String,
    /// The dispatched agent's label for `agent.dispatch` jobs, when the
    /// payload snapshot decodes. Elided when absent.
    #[serde(rename = "agent_id", skip_serializing_if = "Option::is_none")]
    #[schema(example = "eiri.agent.summarizer")]
    agent_id: Option<String>,
    /// Surface lifecycle state.
    status: CoreRunTreeStatus,
    /// Queue row timestamps.
    timestamps: CoreRunTreeTimestamps,
    /// Terminal failure summary, when present.
    failure: Option<CoreRunTreeFailure>,
    /// Lifecycle/operator events projected from the backing queue row.
    events: Vec<CoreRunTreeEvent>,
    /// Child jobs ordered deterministically by creation time and job id.
    #[schema(no_recursion)]
    children: Vec<CoreRunTreeNode>,
}

/// Surface lifecycle state for a runtime job.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoreRunTreeStatus {
    Queued,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

/// Queue row timestamps for a runtime job.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreRunTreeTimestamps {
    /// Creation timestamp from the backing queue row.
    #[serde(rename = "created_at")]
    #[schema(example = 1782357600_u64)]
    created_at: u64,
    /// Last update timestamp from the backing queue row.
    #[serde(rename = "updated_at")]
    #[schema(example = 1782357635_u64)]
    updated_at: u64,
}

/// Summarized terminal failure state.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreRunTreeFailure {
    /// Last failure reason recorded on the backing queue row.
    #[schema(example = "worker failed")]
    reason: String,
}

/// Lifecycle/operator event projected for a runtime job.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreRunTreeEvent {
    /// Monotonic event sequence in the projected run-tree event stream.
    #[schema(example = 1_u64)]
    sequence: u64,
    /// Event timestamp in Unix seconds.
    #[schema(example = 1782357635_u64)]
    at: u64,
    /// Authenticated principal for operator events, otherwise the runtime actor.
    #[schema(example = "dreamer-dashboard")]
    actor: String,
    /// Lifecycle or operator event kind.
    kind: CoreRunTreeEventKind,
    /// Optional operator note.
    #[schema(example = "operator requested a checkpoint")]
    note: Option<String>,
}

/// Lifecycle/operator event kind.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoreRunTreeEventKind {
    Created,
    Claimed,
    Paused,
    Resumed,
    Completed,
    Failed,
    Cancelled,
    Interrupted,
}

/// Non-mutating repair applied while rendering a run tree.
#[derive(Debug, Serialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum CoreRunTreeRepair {
    MissingParent {
        /// Job promoted to a root because its recorded parent row was absent.
        #[serde(rename = "job_id")]
        #[schema(example = "22222222222222222222222222222222")]
        job_id: String,
        /// Recorded parent id that was absent from the filtered row set.
        #[serde(rename = "missing_parent_id")]
        #[schema(example = "11111111111111111111111111111111")]
        missing_parent_id: String,
    },
    ParentCycle {
        /// Job promoted or skipped because following parents would cycle.
        #[serde(rename = "job_id")]
        #[schema(example = "22222222222222222222222222222222")]
        job_id: String,
        /// Parent edge involved in the cycle.
        #[serde(rename = "parent_id")]
        #[schema(example = "11111111111111111111111111111111")]
        parent_id: String,
    },
}

/// Read the runtime job queue as a deterministic run tree.
#[utoipa::path(
    get,
    path = "/v1/core/run-tree",
    params(CoreRunTreeQuery),
    responses(
        (status = 200, description = "Runtime job queue rendered as a deterministic run tree.", body = CoreRunTreeResponse, content_type = "application/json"),
        (status = 400, description = "Invalid run-tree query.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Run-tree read failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn core_run_tree(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<CoreRunTreeQuery>, QueryRejection>,
) -> Result<Json<CoreRunTreeResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let params = query_params(query)?;
    validate_core_run_tree_query(&params)?;

    let adapter = oneiron::RunTreeAdapter::new(&server.vault);
    let run_id = params.run_id.as_deref().expect("run_id validated");
    let tree = adapter.read_run(run_id).map_err(|error| {
        tracing::error!(error = %error, "core run tree read failed");
        core_engine_error("core run tree read failed", error)
    })?;

    Ok(Json(core_run_tree_response(tree)))
}

/// Observe the runtime job queue as a deterministic run tree.
#[utoipa::path(
    get,
    path = "/v1/core/run-tree/observe",
    params(CoreRunTreeQuery),
    responses(
        (status = 200, description = "Runtime job queue rendered as a deterministic run tree.", body = CoreRunTreeResponse, content_type = "application/json"),
        (status = 400, description = "Invalid run-tree query.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Run-tree read failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn core_run_tree_observe(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<CoreRunTreeQuery>, QueryRejection>,
) -> Result<Json<CoreRunTreeResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let params = query_params(query)?;
    validate_core_run_tree_query(&params)?;

    let adapter = oneiron::RunTreeAdapter::new(&server.vault);
    let run_id = params.run_id.as_deref().expect("run_id validated");
    let tree = adapter.read_run(run_id).map_err(|error| {
        tracing::error!(error = %error, "core run tree observe failed");
        core_engine_error("core run tree observe failed", error)
    })?;

    Ok(Json(core_run_tree_response(tree)))
}

/// Intervene on a runtime job and return a fresh run-tree snapshot.
#[utoipa::path(
    post,
    path = "/v1/core/run-tree/intervene",
    request_body(content = CoreRunTreeInterventionRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Intervention applied idempotently and recorded on the backing job row.", body = CoreRunTreeInterventionResponse, content_type = "application/json"),
        (status = 400, description = "Malformed intervention or invalid lifecycle transition.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:write.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Run-tree intervention failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn core_run_tree_intervene(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<CoreRunTreeInterventionRequest>, JsonRejection>,
) -> Result<Json<CoreRunTreeInterventionResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    let req = json_payload(payload)?;
    let job_id = parse_job_id_param(&req.job_id, "job_id")?;
    let kind = job_intervention_kind(req.kind);
    let outcome = oneiron::JobQueue::new(&server.vault)
        .intervene(oneiron::InterveneJob {
            id: job_id,
            kind,
            actor: auth.principal().to_owned(),
            note: req.note,
            now: unix_seconds_now(),
        })
        .map_err(|error| {
            tracing::error!(error = %error, job_id = %req.job_id, "core run tree intervene failed");
            core_engine_error("core run tree intervene failed", error)
        })?;

    let response_job_id = hex_bytes(outcome.record.id.as_bytes());
    let run_id = outcome.record.run_id.clone();
    let tree = if let Some(run_id) = run_id.as_deref() {
        let adapter = oneiron::RunTreeAdapter::new(&server.vault);
        Some(core_run_tree_response(
            adapter.read_run(run_id).map_err(|error| {
                tracing::error!(error = %error, run_id, "core run tree intervention snapshot failed");
                core_engine_error("core run tree intervention snapshot failed", error)
            })?,
        ))
    } else {
        None
    };

    Ok(Json(CoreRunTreeInterventionResponse {
        job_id: response_job_id,
        run_id,
        kind: req.kind,
        effect: core_run_tree_intervention_effect(outcome.effect),
        tree,
    }))
}

pub(crate) fn validate_core_run_tree_query(params: &CoreRunTreeQuery) -> Result<(), ApiError> {
    let Some(run_id) = params.run_id.as_deref() else {
        return Err(ApiError::bad_request(
            "run_id is required; unfiltered run-tree reads are not supported",
            Some("run_id"),
        ));
    };
    if run_id.is_empty() {
        return Err(ApiError::bad_request(
            "run_id must not be empty",
            Some("run_id"),
        ));
    }
    if run_id.len() > CORE_RUN_TREE_RUN_ID_MAX_BYTES {
        return Err(ApiError::bad_request(
            "run_id exceeds 128 bytes",
            Some("run_id"),
        ));
    }
    Ok(())
}

pub(crate) fn core_run_tree_response(tree: oneiron::RunTree) -> CoreRunTreeResponse {
    CoreRunTreeResponse {
        roots: tree.roots.into_iter().map(core_run_tree_node).collect(),
        repairs: tree.repairs.into_iter().map(core_run_tree_repair).collect(),
    }
}

pub(crate) fn core_run_tree_node(node: oneiron::RunTreeNode) -> CoreRunTreeNode {
    CoreRunTreeNode {
        job_id: node.job_id,
        run_id: node.run_id,
        parent_id: node.parent_id,
        worker_kind: node.worker_kind,
        agent_id: node.agent_id,
        status: core_run_tree_status(node.status),
        timestamps: CoreRunTreeTimestamps {
            created_at: node.timestamps.created_at,
            updated_at: node.timestamps.updated_at,
        },
        failure: node.failure.map(|failure| CoreRunTreeFailure {
            reason: failure.reason,
        }),
        events: node.events.into_iter().map(core_run_tree_event).collect(),
        children: node.children.into_iter().map(core_run_tree_node).collect(),
    }
}

pub(crate) fn core_run_tree_status(status: oneiron::RunTreeStatus) -> CoreRunTreeStatus {
    match status {
        oneiron::RunTreeStatus::Queued => CoreRunTreeStatus::Queued,
        oneiron::RunTreeStatus::Running => CoreRunTreeStatus::Running,
        oneiron::RunTreeStatus::Paused => CoreRunTreeStatus::Paused,
        oneiron::RunTreeStatus::Completed => CoreRunTreeStatus::Completed,
        oneiron::RunTreeStatus::Failed => CoreRunTreeStatus::Failed,
        oneiron::RunTreeStatus::Cancelled => CoreRunTreeStatus::Cancelled,
    }
}

pub(crate) fn core_run_tree_event(event: oneiron::RunTreeEvent) -> CoreRunTreeEvent {
    CoreRunTreeEvent {
        sequence: event.sequence,
        at: event.at,
        actor: event.actor,
        kind: core_run_tree_event_kind(event.kind),
        note: event.note,
    }
}

pub(crate) fn core_run_tree_event_kind(kind: oneiron::RunTreeEventKind) -> CoreRunTreeEventKind {
    match kind {
        oneiron::RunTreeEventKind::Created => CoreRunTreeEventKind::Created,
        oneiron::RunTreeEventKind::Claimed => CoreRunTreeEventKind::Claimed,
        oneiron::RunTreeEventKind::Paused => CoreRunTreeEventKind::Paused,
        oneiron::RunTreeEventKind::Resumed => CoreRunTreeEventKind::Resumed,
        oneiron::RunTreeEventKind::Completed => CoreRunTreeEventKind::Completed,
        oneiron::RunTreeEventKind::Failed => CoreRunTreeEventKind::Failed,
        oneiron::RunTreeEventKind::Cancelled => CoreRunTreeEventKind::Cancelled,
        oneiron::RunTreeEventKind::Interrupted => CoreRunTreeEventKind::Interrupted,
    }
}

pub(crate) fn job_intervention_kind(
    kind: CoreRunTreeInterventionKind,
) -> oneiron::JobInterventionKind {
    match kind {
        CoreRunTreeInterventionKind::Interrupt => oneiron::JobInterventionKind::Interrupt,
        CoreRunTreeInterventionKind::Pause => oneiron::JobInterventionKind::Pause,
        CoreRunTreeInterventionKind::Resume => oneiron::JobInterventionKind::Resume,
        CoreRunTreeInterventionKind::Cancel => oneiron::JobInterventionKind::Cancel,
    }
}

pub(crate) fn core_run_tree_intervention_effect(
    effect: oneiron::JobInterventionEffect,
) -> CoreRunTreeInterventionEffect {
    match effect {
        oneiron::JobInterventionEffect::Interrupted => CoreRunTreeInterventionEffect::Interrupted,
        oneiron::JobInterventionEffect::Paused => CoreRunTreeInterventionEffect::Paused,
        oneiron::JobInterventionEffect::AlreadyPaused => {
            CoreRunTreeInterventionEffect::AlreadyPaused
        }
        oneiron::JobInterventionEffect::Resumed => CoreRunTreeInterventionEffect::Resumed,
        oneiron::JobInterventionEffect::AlreadyResumed => {
            CoreRunTreeInterventionEffect::AlreadyResumed
        }
        oneiron::JobInterventionEffect::Cancelled => CoreRunTreeInterventionEffect::Cancelled,
        oneiron::JobInterventionEffect::AlreadyCancelled => {
            CoreRunTreeInterventionEffect::AlreadyCancelled
        }
    }
}

pub(crate) fn core_run_tree_repair(repair: oneiron::RunTreeRepair) -> CoreRunTreeRepair {
    match repair {
        oneiron::RunTreeRepair::MissingParent {
            job_id,
            missing_parent_id,
        } => CoreRunTreeRepair::MissingParent {
            job_id,
            missing_parent_id,
        },
        oneiron::RunTreeRepair::ParentCycle { job_id, parent_id } => {
            CoreRunTreeRepair::ParentCycle { job_id, parent_id }
        }
    }
}

pub(crate) fn parse_job_id_param(
    value: &str,
    field: &'static str,
) -> Result<oneiron::JobId, ApiError> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError::bad_request(
            format!("{field} must be a 32-character hex job id"),
            Some(field),
        ));
    }
    let mut bytes = [0_u8; 16];
    for (index, slot) in bytes.iter_mut().enumerate() {
        let offset = index * 2;
        *slot = u8::from_str_radix(&value[offset..offset + 2], 16).map_err(|_| {
            ApiError::bad_request(
                format!("{field} must be a 32-character hex job id"),
                Some(field),
            )
        })?;
    }
    oneiron::JobId::from_bytes(&bytes).map_err(|_| {
        ApiError::bad_request(
            format!("{field} must be a 32-character hex job id"),
            Some(field),
        )
    })
}
