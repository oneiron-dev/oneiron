//! Owner-supplied scores for the native Dreamer tuning harness.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::post;
use oneiron::dreamer_runner::maintenance::HarnessEvaluation;
use serde::{Deserialize, Serialize};

use super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::stamp::now_unix_ms;
use crate::owner::{OwnerResult, entity_id};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![(
        OwnerRoute {
            method: "post",
            path: "/dreamer/maintenance/harness-evaluation",
            summary: "Queue an owner-supplied score for an immutable tuning-config version, not independent evaluation proof.",
            row: None,
            shape: Some(RestShape::json(input_schema, scheduled_schema)),
        },
        post(schedule),
    )]
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
