//! `/v1/owner/wire-health`: the health check past a threshold (OF-520). The
//! owner reads each check and where it stands, and records what happened
//! next to a crossing, the label its decision learns from. A check the
//! ladder left in the band is answered at `/v1/owner/decisions` like every
//! other ask.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::owner::{OwnerResult, entity_id};
use crate::server::SyncServer;
use crate::wire_health::{self, HealthCheck};

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/wire-health", get(list))
        .route("/wire-health/outcome", post(outcome))
}

#[derive(Debug, Serialize)]
struct HealthChecks {
    checks: Vec<HealthCheck>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordOutcome {
    /// The crossing's unit, as 32 hex (a check's `state.unit`).
    unit: String,
    /// `bot` or `valid_burst`.
    outcome: String,
}

#[derive(Debug, Serialize)]
struct OutcomeRecorded {
    fact: String,
}

/// `GET /v1/owner/wire-health`: every check this server keeps.
async fn list(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<HealthChecks> {
    owner(&auth, &server)?;
    let checks = blocking(move || -> OwnerResult<HealthChecks> {
        Ok(HealthChecks {
            checks: wire_health::checks(server.vault())?,
        })
    })
    .await?;
    Ok(Json(checks))
}

/// `POST /v1/owner/wire-health/outcome`: what happened next to one crossing.
async fn outcome(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<RecordOutcome>, JsonRejection>,
) -> OwnerReply<OutcomeRecorded> {
    owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let recorded = blocking(move || -> OwnerResult<OutcomeRecorded> {
        let unit = entity_id("unit", &request.unit)?;
        let fact = wire_health::record_outcome(server.vault(), unit, &request.outcome)
            .map_err(|error| crate::owner::OwnerError::Invalid(error.to_string()))?;
        Ok(OutcomeRecorded {
            fact: fact.to_hex(),
        })
    })
    .await?;
    Ok(Json(recorded))
}
