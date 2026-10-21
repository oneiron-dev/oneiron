//! `/v1/owner/coach/training-runs` (OF-577, FIX 857): the owner's view of a
//! training run's result and their own swap choice. A train yes runs the
//! pack, then shows its result for a separate swap choice; a trained model
//! never deploys by itself. The Coach also asks each owner in their
//! conversation with it, and either door settles the same run.
//!
//! `view` shows the run's state, held-out evaluation, export checks and
//! overlaps, every swap receipt, every swap question and how the returned
//! checkpoint serves here. `swap` binds the checkpoint the owner viewed,
//! named by its spec and load-set hashes, in one writer; a result that moved
//! since is refused as changed. An explicit override over failed checks is
//! chosen only here, with its reason. An embedder run is refused: its swap
//! stages a re-embed through a space move. Nothing loads trained weights on
//! this host yet, so a bound checkpoint's `serving` reads unavailable.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use axum::routing::post;
use oneiron::llm::manifest::ModelRole;
use oneiron::task_verb::TrainingSwapAskView;
use oneiron::training_pack::{
    ExportCheck, HeldOutResult, QuestionTarget, RoleSwapReceipt, SwapChoice, TrainingAuthorization,
    TrainingHold, TrainingState, ViewedSwap,
};
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::ai_host::trained_serving::{TrainedServing, trained_serving};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

/// Why the direct door refuses an embedder run.
const EMBEDDER_REFUSED: &str = "embedder swaps stage through a space move";

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/coach/training-runs/view", post(view))
        .route("/coach/training-runs/swap", post(swap))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewTrainingRun {
    /// A training run id, as 32 hex.
    run: String,
}

/// One training run's result as the owner decides on it.
#[derive(Debug, Serialize)]
struct TrainingRunView {
    run: String,
    /// The role a role run trains for; absent on a question run.
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<ModelRole>,
    /// The question a question run's head answers (FIX 7263); absent on a
    /// role run. Its head binds no role, so it serves nothing here and
    /// offers no swap.
    #[serde(skip_serializing_if = "Option::is_none")]
    question: Option<QuestionTargetView>,
    state: TrainingState,
    /// The run's spec hash (64 hex), which `swap` names back.
    spec: String,
    /// The returned checkpoint's full load-set hash (64 hex), which `swap`
    /// names back; `None` until it returns.
    checkpoint: Option<String>,
    evaluation: Option<HeldOutResult>,
    checks: Option<ExportCheck>,
    exact_hash_overlaps: u64,
    /// Whether the checks allow an evaluated swap; otherwise only an explicit
    /// override binds it.
    can_propose_swap: bool,
    swaps: Vec<RoleSwapReceipt>,
    asks: Vec<TrainingSwapAskView>,
    /// How the returned checkpoint serves on this host, once it returned.
    serving: Option<TrainedServing>,
    /// The owner's authorization of the run, if they gave one.
    authorization: Option<TrainingAuthorization>,
    /// Why the host cannot advance the run, while it waits on the host.
    hold: Option<TrainingHold>,
}

/// A question run's question: its pins and the new model, with the
/// definition's digest (64 hex) in place of the definition.
#[derive(Debug, Serialize)]
struct QuestionTargetView {
    question_id: String,
    question_version: u32,
    definition_blake3: String,
    family: String,
    corpus_revision: String,
    feature_schema: String,
    label_schema: String,
    renderer: String,
    output_model: String,
}

impl QuestionTargetView {
    fn of(question: &QuestionTarget) -> Self {
        Self {
            question_id: question.question_id.clone(),
            question_version: question.question_version,
            definition_blake3: hex(question.definition_blake3),
            family: question.family.clone(),
            corpus_revision: question.corpus_revision.clone(),
            feature_schema: question.feature_schema.clone(),
            label_schema: question.label_schema.clone(),
            renderer: question.renderer.clone(),
            output_model: question.output_model.as_str().to_owned(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewedResult {
    /// The viewed run's `spec`, as 64 hex.
    spec: String,
    /// The viewed run's `checkpoint`, as 64 hex.
    checkpoint: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SwapTrainingRun {
    /// A training run id, as 32 hex.
    run: String,
    choice: SwapChoice,
    /// The result the owner viewed: the swap binds only that one.
    expected: ViewedResult,
}

fn hex(bytes: [u8; 32]) -> String {
    blake3::Hash::from(bytes).to_hex().to_string()
}

/// Parses a 64-hex hash field, in canonical lowercase form.
fn hash_field(field: &str, value: &str) -> OwnerResult<[u8; 32]> {
    blake3::Hash::from_hex(value)
        .ok()
        .filter(|hash| hash.to_hex().as_str() == value)
        .map(|hash| *hash.as_bytes())
        .ok_or_else(|| OwnerError::Invalid(format!("{field} must be a 64-hex hash")))
}

/// `POST /v1/owner/coach/training-runs/view`: one training run's result,
/// its swaps and swap questions, and how it serves here.
async fn view(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ViewTrainingRun>, JsonRejection>,
) -> OwnerReply<TrainingRunView> {
    owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let view = blocking(move || -> OwnerResult<TrainingRunView> {
        let id = entity_id("run", &request.run)?;
        let vault = server.vault();
        let run = vault
            .training_run(&id)?
            .ok_or_else(|| OwnerError::NotFound("training run", request.run.clone()))?;
        let returned = run
            .result
            .as_ref()
            .map(|result| &result.exported_checkpoint);
        let checkpoint = returned
            .map(|checkpoint| checkpoint.content_hash())
            .transpose()?
            .map(hex);
        // A question head has no role to serve or ask about.
        let role = run.plan.target.role_binding().map(|(role, _)| role);
        let serving = match role {
            Some(role) => returned
                .map(|checkpoint| trained_serving(&server, role, checkpoint))
                .transpose()?,
            None => None,
        };
        let asks = match role {
            Some(_) => oneiron::task_verb::training_swap_asks(vault, &id)?,
            None => Vec::new(),
        };
        let waits = run.awaits_host();
        Ok(TrainingRunView {
            run: id.to_hex(),
            role,
            question: run.plan.target.question().map(QuestionTargetView::of),
            state: run.state,
            spec: hex(run.spec_blake3),
            checkpoint,
            checks: run.result.as_ref().map(|result| result.checks.clone()),
            exact_hash_overlaps: run.corpus.exact_hash_overlaps,
            can_propose_swap: run.can_propose_swap(),
            swaps: vault.training_run_swap_receipts(&id)?,
            asks,
            serving,
            hold: run.hold.filter(|_| waits),
            evaluation: run.evaluation,
            authorization: run.authorization,
        })
    })
    .await?;
    Ok(Json(view))
}

/// `POST /v1/owner/coach/training-runs/swap`: binds the checkpoint the
/// owner viewed to its role, while the run and the role's model are as the
/// owner saw them.
async fn swap(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<SwapTrainingRun>, JsonRejection>,
) -> OwnerReply<RoleSwapReceipt> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let receipt = blocking(move || -> OwnerResult<RoleSwapReceipt> {
        let id = entity_id("run", &request.run)?;
        let spec = hash_field("expected.spec", &request.expected.spec)?;
        let checkpoint = hash_field("expected.checkpoint", &request.expected.checkpoint)?;
        match server.vault().approve_viewed_training_role_swap(
            &owner,
            &id,
            request.choice,
            &spec,
            &checkpoint,
        )? {
            ViewedSwap::Bound(receipt) => Ok(*receipt),
            ViewedSwap::Stale => Err(OwnerError::Changed(
                "the training result is not the one viewed; view it again".to_owned(),
            )),
            ViewedSwap::Embedder => Err(OwnerError::Refused(EMBEDDER_REFUSED.to_owned())),
        }
    })
    .await?;
    Ok(Json(receipt))
}
