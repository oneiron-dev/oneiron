//! `/v1/owner/coach/training-offers/{prepare,authorize,training}` (OF-577):
//! the owner's setup of a Train offer's run. The owner prepares a run for
//! the offer's seat and base on a trainer connector this host names, then
//! authorizes that exact spec with the answer or after it; the host trains
//! it, and when it cannot, the run says why. Nothing here binds a model.
//!
//! `/v1/owner/coach/training-runs/{prepare,authorize}` (FIX 8237): the
//! owner's own doors with no offer. `prepare` takes a detector question's
//! plan and the owner's adjudicated rows in custody; `authorize` is the
//! owner's yes on any prepared run at the spec they saw.
//!
//! `PUT /v1/owner/coach/training-checkpoints` (FIX 12086, `checkpoints`):
//! the owner's starting checkpoint into custody, its files streamed.
use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::{post, put};
use oneiron::edit_distance::reservoir::ReservoirScope;
use oneiron::skill_optimize::{OfferTrainingHandoff, TrainingChoice};
use oneiron::training_pack::{
    DetectorCorpusRef, TrainingAuthorization, TrainingDeclarationPin, TrainingHold,
    TrainingPackDraft, TrainingPlan, TrainingRun, TrainingState,
};
use serde::{Deserialize, Serialize};

use super::super::{OwnerReply, OwnerRoute, OwnerTable, blocking, owner};
use super::{hex_id, now_secs};
use crate::ai_host::training_pack::{trainer_binding, training_declaration};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

pub(super) mod checkpoints;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "post",
                path: "/coach/training-offers/prepare",
                summary: "The owner's run for a Train offer's seat and base on a trainer connector this host names; nothing runs.",
                row: None,
            },
            post(prepare),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/coach/training-offers/authorize",
                summary: "The owner's yes on a prepared run after their train approval, at the exact spec they saw.",
                row: None,
            },
            post(authorize),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/coach/training-offers/training",
                summary: "A Train offer's handed-off run: its state, why it waits, the owner's authorization, its held-out summary and the plan the recipe suggests.",
                row: None,
            },
            post(training),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/coach/training-runs/prepare",
                summary: "The owner's run for one detector question's head, on their adjudicated target rows in custody and a trainer connector this host names; nothing runs.",
                row: None,
            },
            post(prepare_question),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/coach/training-runs/authorize",
                summary: "The owner's own yes on a prepared run at the exact spec they saw; the host's Coach queues it.",
                row: None,
            },
            post(authorize_run),
        ),
        (
            OwnerRoute {
                method: "put",
                path: "/coach/training-checkpoints",
                summary: "The owner's starting checkpoint into custody: the body is its files' raw bytes back to back, in the order the x-oneiron-checkpoint header's JSON manifest names them, spooled to disk as it arrives; the answer is the pinned checkpoint a training draft names.",
                row: None,
            },
            put(checkpoints::keep_checkpoint),
        ),
    ]
}

/// A train approval's prepared run and the spec the owner saw.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TrainingChoiceRequest {
    /// A prepared run id, as 32 hex.
    pub(super) run: String,
    /// The run's `spec_blake3`, as 64 hex.
    pub(super) spec: String,
}

/// The owner's training choice: the prepared run (32 hex) and the spec they
/// saw (64 hex), with the declaration this host admits that run under,
/// pinned.
pub(super) fn training_choice(
    server: &SyncServer,
    run: &str,
    spec: &str,
) -> OwnerResult<TrainingChoice> {
    let id = entity_id("run", run)?;
    let spec = blake3::Hash::from_hex(spec)
        .map_err(|_| OwnerError::Invalid("spec must be a 64-hex training spec".into()))?;
    let prepared = server
        .vault()
        .training_run(&id)?
        .ok_or_else(|| OwnerError::NotFound("training run", run.to_owned()))?;
    Ok(TrainingChoice {
        run: id,
        spec_blake3: *spec.as_bytes(),
        declaration: TrainingDeclarationPin::of(&training_declaration(&prepared)?)?,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareTrainingRun {
    /// A Train offer id, as 32 hex.
    offer: String,
    /// The owner's recipe, sealed held-out cohort, compute choice and
    /// quantity for this run.
    draft: TrainingPackDraft,
    scope: TrainingScope,
    /// The trainer connector's name on this host; there is no default.
    connector: String,
}

/// The consented reservoir's filters the run's corpus is exported under.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrainingScope {
    task_classes: Option<Vec<String>>,
    since: Option<u64>,
}

/// A prepared run, and its spec as 64 hex: what the owner authorizes.
#[derive(Debug, Serialize)]
struct PreparedTrainingRun {
    run: TrainingRun,
    spec: String,
}

/// `POST /v1/owner/coach/training-offers/prepare`: the owner's run for a
/// Train offer's seat and base on a trainer connector this host names. It
/// exports the consented corpus and pins the spec; nothing runs.
async fn prepare(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<PrepareTrainingRun>,
) -> OwnerReply<PreparedTrainingRun> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let prepared = blocking(move || -> OwnerResult<PreparedTrainingRun> {
        let offer = entity_id("offer", &request.offer)?;
        let vault = server.vault();
        oneiron::skill_optimize::check_offer_training_plan(vault, &offer, &request.draft.plan)?;
        let binding = trainer_binding(&server, &request.connector)
            .ok_or_else(|| OwnerError::NotFound("trainer connector", request.connector.clone()))?;
        let scope = ReservoirScope {
            task_classes: request.scope.task_classes,
            since: request.scope.since,
        };
        let run = vault.prepare_training_pack(&owner, &request.draft, scope, &binding)?;
        Ok(PreparedTrainingRun {
            spec: hex_id(&run.spec_blake3),
            run,
        })
    })
    .await?;
    Ok(Json(prepared))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizeOfferTraining {
    /// A Train offer id, as 32 hex.
    offer: String,
    /// A prepared run id, as 32 hex.
    run: String,
    /// The run's `spec_blake3`, as 64 hex.
    spec: String,
}

/// `POST /v1/owner/coach/training-offers/authorize`: the owner's yes on a
/// prepared run after their train approval, at the exact spec they saw. The
/// host's Coach queues it at once.
async fn authorize(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<AuthorizeOfferTraining>,
) -> OwnerReply<OfferTrainingHandoff> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let handoff = blocking(move || -> OwnerResult<OfferTrainingHandoff> {
        let offer = entity_id("offer", &request.offer)?;
        let choice = training_choice(&server, &request.run, &request.spec)?;
        Ok(oneiron::skill_optimize::authorize_offer_training(
            server.vault(),
            &owner,
            &offer,
            &choice,
            now_secs(),
        )?)
    })
    .await?;
    Ok(Json(handoff))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OfferTrainingRequest {
    /// A Train offer id, as 32 hex.
    offer: String,
}

/// A Train offer's run: the handoff its yes made, where that run is and why
/// it waits, and the plan the offer's recipe suggests.
#[derive(Debug, Serialize)]
struct OfferTraining {
    handoff: Option<OfferTrainingHandoff>,
    run: Option<TrainingRunStatus>,
    suggested_plan: Option<TrainingPlan>,
}

/// A handed-off run: its state, why it waits on the host, the owner's
/// authorization and its held-out summary.
#[derive(Debug, Serialize)]
struct TrainingRunStatus {
    state: TrainingState,
    spec: String,
    hold: Option<TrainingHold>,
    authorization: Option<TrainingAuthorization>,
    evaluation: Option<EvaluationSummary>,
}

#[derive(Debug, Serialize)]
struct EvaluationSummary {
    cases: u64,
    metrics: BTreeMap<String, f64>,
    passed: bool,
}

/// A run's status. A hold reads only while the run waits on the host.
fn status(run: TrainingRun) -> TrainingRunStatus {
    let waits = run.awaits_host();
    TrainingRunStatus {
        state: run.state,
        spec: hex_id(&run.spec_blake3),
        hold: run.hold.filter(|_| waits),
        authorization: run.authorization,
        evaluation: run.evaluation.map(|evaluation| EvaluationSummary {
            cases: evaluation.cases,
            metrics: evaluation.metrics,
            passed: evaluation.passed,
        }),
    }
}

/// `POST /v1/owner/coach/training-offers/training`: a Train offer's run as
/// it stands, an unready one with the reason the host recorded.
async fn training(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<OfferTrainingRequest>,
) -> OwnerReply<OfferTraining> {
    owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let view = blocking(move || -> OwnerResult<OfferTraining> {
        let offer = entity_id("offer", &request.offer)?;
        let vault = server.vault();
        let handoff = oneiron::skill_optimize::offer_training_handoff(vault, &offer)?;
        let run = match &handoff {
            Some(handoff) => vault.training_run(&handoff.run)?.map(status),
            None => None,
        };
        Ok(OfferTraining {
            handoff,
            run,
            suggested_plan: oneiron::skill_optimize::suggested_training_plan(vault, &offer)?,
        })
    })
    .await?;
    Ok(Json(view))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareQuestionRun {
    /// The owner's question plan, sealed held-out cohort, compute choice
    /// and quantity for this run.
    draft: TrainingPackDraft,
    /// The owner's adjudicated per-target rows, one pinned version in
    /// custody.
    corpus: DetectorCorpusRef,
    /// The trainer connector's name on this host; there is no default.
    connector: String,
}

/// `POST /v1/owner/coach/training-runs/prepare`: the owner's run for one
/// detector question's head. The ingress splits the owner's rows by source
/// family and pins the spec with its split and consent receipts; nothing
/// runs.
async fn prepare_question(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<PrepareQuestionRun>,
) -> OwnerReply<PreparedTrainingRun> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let prepared = blocking(move || -> OwnerResult<PreparedTrainingRun> {
        let binding = trainer_binding(&server, &request.connector)
            .ok_or_else(|| OwnerError::NotFound("trainer connector", request.connector.clone()))?;
        let run = server.vault().prepare_question_training_pack(
            &owner,
            &request.draft,
            &request.corpus,
            &binding,
        )?;
        Ok(PreparedTrainingRun {
            spec: hex_id(&run.spec_blake3),
            run,
        })
    })
    .await?;
    Ok(Json(prepared))
}

/// `POST /v1/owner/coach/training-runs/authorize`: the owner's own yes on a
/// prepared run at the exact spec they saw, under the declaration this host
/// admits it with. The host's Coach queues it at once; the same yes again
/// returns the run as it stands.
async fn authorize_run(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<TrainingChoiceRequest>,
) -> OwnerReply<TrainingRunStatus> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let run = blocking(move || -> OwnerResult<TrainingRunStatus> {
        let choice = training_choice(&server, &request.run, &request.spec)?;
        let run = server.vault().authorize_training_pack(
            &owner,
            &choice.run,
            &choice.spec_blake3,
            choice.declaration,
            now_secs(),
        )?;
        Ok(status(run))
    })
    .await?;
    Ok(Json(run))
}
