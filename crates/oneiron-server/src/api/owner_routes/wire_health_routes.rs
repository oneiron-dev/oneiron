//! `/v1/owner/wire-health`: the health check past a threshold (OF-520). The
//! owner reads each check and where it stands, and records what happened
//! next to a crossing, the label its decision learns from. A check the
//! ladder left in the band is answered at `/v1/owner/decisions` like every
//! other ask.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::response::Json;
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::{OwnerResult, entity_id};
use crate::server::SyncServer;
use crate::wire_health::{self, HealthCheck};
use crate::wire_telemetry::ConnectionPoolPressure;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/wire-health", get(list))
        .route("/wire-health/outcome", post(outcome))
}

#[derive(Debug, Serialize)]
struct HealthChecks {
    checks: Vec<HealthCheck>,
    /// The shared connection pool's live pressure check (FIX 7656).
    connection_pool_pressure: ConnectionPoolPressure,
    /// The mesh listener's sync streams' own check (FIX 7737).
    mesh_pool: ConnectionPoolPressure,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct RecordOutcome {
    /// The crossing's unit, as 32 hex (a check's `state.unit`).
    unit: String,
    /// `bot` or `valid_burst`.
    outcome: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct OutcomeRecorded {
    fact: String,
}

/// The OpenAPI schema of `POST /v1/owner/wire-health/outcome`'s body (FIX 11103):
/// [`RecordOutcome`].
pub(crate) fn record_outcome_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<RecordOutcome>()
}

/// The OpenAPI schema of `POST /v1/owner/wire-health/outcome`'s answer (FIX 11103):
/// [`OutcomeRecorded`].
pub(crate) fn outcome_recorded_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<OutcomeRecorded>()
}

/// `GET /v1/owner/wire-health`: every check this server keeps.
async fn list(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<HealthChecks> {
    owner(&auth, &server)?;
    let checks = blocking(move || -> OwnerResult<HealthChecks> {
        Ok(HealthChecks {
            checks: wire_health::checks(server.vault())?,
            connection_pool_pressure: server
                .wire_telemetry
                .limit_questions()
                .connection_pool_pressure(),
            mesh_pool: server.mesh_pressure.snapshot(),
        })
    })
    .await?;
    Ok(Json(checks))
}

/// `POST /v1/owner/wire-health/outcome`: what happened next to one crossing.
async fn outcome(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<RecordOutcome>,
) -> OwnerReply<OutcomeRecorded> {
    owner(&auth, &server)?;
    let request = payload.read(&server).await?;
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
