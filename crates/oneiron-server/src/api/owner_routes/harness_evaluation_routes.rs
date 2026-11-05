//! Owner observations and explicitly selected native OF360 harness metrics.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::post;
use oneiron::dreamer_runner::maintenance::{HarnessEvaluation, HarnessOf360Evaluation};
use serde::{Deserialize, Serialize};

use super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::stamp::now_unix_ms;
use crate::owner::{OwnerResult, entity_id};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "post",
                path: "/dreamer/maintenance/harness-evaluation",
                summary: "Queue an owner-supplied score for an immutable tuning-config version, not independent evaluation proof.",
                row: None,
                shape: Some(RestShape::json(input_schema, scheduled_schema)),
            },
            post(schedule),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/dreamer/maintenance/harness-evaluation/of360",
                summary: "Compute an owner-selected native OF360 metric from supplied gold/run inputs and queue its tuning observation; not execution or independent PASS proof.",
                row: None,
                shape: Some(RestShape::json(of360_input_schema, of360_scheduled_schema)),
            },
            post(schedule_of360),
        ),
    ]
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct EvaluationInput {
    /// The tuning-config artifact, as 32 hex.
    artifact: String,
    /// The immutable version being evaluated.
    version: u64,
    /// Owner-supplied score, finite and between zero and one inclusive.
    score: f64,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct Scheduled {
    /// The actual new or existing maintenance attempt; not a completed evaluation.
    attempt: String,
}

fn input_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<EvaluationInput>()
}

fn scheduled_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<Scheduled>()
}

async fn schedule(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<EvaluationInput>,
) -> OwnerReply<Scheduled> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let scheduled = blocking(move || -> OwnerResult<Scheduled> {
        let evaluation = HarnessEvaluation {
            artifact: entity_id("artifact", &request.artifact)?,
            version: request.version,
            score: request.score,
        };
        let attempt = server.vault().schedule_harness_evaluation_as(
            &owner,
            &evaluation,
            now_unix_ms() / 1_000,
        )?;
        Ok(Scheduled {
            attempt: crate::owner::healer::attempt_hex(&attempt),
        })
    })
    .await?;
    Ok(Json(scheduled))
}

fn of360_input_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object", "additionalProperties": false,
        "required": ["artifact", "version", "metric", "dataset", "run"],
        "properties": {
            "artifact": {"type": "string", "description": "Tuning-config artifact, as 32 hex."},
            "version": {"type": "integer", "minimum": 0, "description": "Owner-attested immutable config version associated with this run, not execution proof."},
            "metric": {"type": "string", "enum": [
                "updating_accuracy", "qa_accuracy", "omission_rate", "halumem_recall",
                "halumem_weighted_recall", "target_precision", "halumem_f1", "faithfulness_rate",
                "hallucination_rate", "overreach_rate", "temporal_correctness", "redundancy_rate"
            ]},
            "dataset": {"type": "object", "description": "Complete native Of360GoldDataset input; no corpus is generated or silently selected."},
            "run": {"type": "object", "description": "Native Of360ExtractionRun, including supplied graded matches; dataset id/revision must match dataset."}
        }
    })
}

fn of360_scheduled_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object", "required": ["attempt", "observation"],
        "properties": {
            "attempt": {"type": ["string", "null"], "description": "Actual new/existing attempt; null when the selected metric is unobservable, not a passing evaluation."},
            "observation": {"type": "object", "description": "Native raw rate, definition direction, optional higher-is-better score, canonical typed-input BLAKE3 digests, run/dataset identity and evaluator warnings."}
        }
    })
}

async fn schedule_of360(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<HarnessOf360Evaluation>,
) -> OwnerReply<serde_json::Value> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let scheduled = blocking(move || -> OwnerResult<serde_json::Value> {
        let scheduled = server.vault().schedule_harness_of360_evaluation_as(
            &owner,
            &request,
            now_unix_ms() / 1_000,
        )?;
        Ok(serde_json::json!({
            "attempt": scheduled.attempt.as_ref().map(crate::owner::healer::attempt_hex),
            "observation": scheduled.observation,
        }))
    })
    .await?;
    Ok(Json(scheduled))
}
