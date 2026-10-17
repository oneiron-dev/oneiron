//! `/v1/owner/dreamer/maintenance` (OF-023, owner ruling 10-18: "autoapply +
//! revert rather than holdout"): the Dreamer's maintenance writes that
//! applied at once (a curator rung, a harness retune finding, an advisory
//! action mode, a Dreamer-born digest cadence and presentation), and the
//! owner's revert of one. The Coach's findings still wait in the run tray.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::dreamer_runner::maintenance::{AppliedMaintenance, MaintenanceRevert};
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::owner::stamp::now_unix_ms;
use crate::owner::{OwnerResult, entity_id};
use crate::server::SyncServer;

/// The most applied writes one list returns unless the caller asks for fewer.
const DEFAULT_LIMIT: usize = 100;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/dreamer/maintenance/applied", get(applied))
        .route("/dreamer/maintenance/revert", post(revert))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AppliedQuery {
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevertMaintenance {
    /// The applied write's finding, as 32 hex.
    finding: String,
}

#[derive(Debug, Serialize)]
struct AppliedView {
    finding: String,
    /// `finding`, `curator` or `proactivity_policy`.
    kind: &'static str,
    facet: String,
    attempt: String,
    applied_at: u64,
    receipt_ref: String,
    /// The owner's revert, once made.
    reverted: Option<RevertView>,
}

#[derive(Debug, Serialize)]
struct RevertView {
    finding: String,
    /// Records standing again in place.
    restored: Vec<String>,
    /// The Dreamer's fresh copies of its own records, as `[record, copy]`.
    copied: Vec<[String; 2]>,
    /// Outputs the applied write made, closed by the revert.
    closed: Vec<String>,
    /// Settings rows put back.
    settings: Vec<String>,
    /// What a later write changed, left as it is.
    left_alone: Vec<String>,
    receipt_ref: String,
}

fn revert_view(revert: MaintenanceRevert) -> RevertView {
    let hex =
        |ids: &[oneiron::EntityId]| -> Vec<String> { ids.iter().map(|id| id.to_hex()).collect() };
    RevertView {
        finding: revert.finding.to_hex(),
        restored: hex(&revert.restored),
        copied: revert
            .copied
            .iter()
            .map(|(record, copy)| [record.to_hex(), copy.to_hex()])
            .collect(),
        closed: hex(&revert.closed),
        settings: revert.settings,
        left_alone: revert.left_alone,
        receipt_ref: revert.receipt_ref,
    }
}

fn applied_view(applied: AppliedMaintenance) -> AppliedView {
    AppliedView {
        finding: applied.finding.to_hex(),
        kind: applied.kind,
        facet: applied.facet,
        attempt: applied.attempt,
        applied_at: applied.applied_at,
        receipt_ref: applied.receipt_ref,
        reverted: applied.reverted.map(revert_view),
    }
}

/// `GET /v1/owner/dreamer/maintenance/applied` (optionally `?limit=<n>`):
/// every applied write, reverted ones too, newest first.
async fn applied(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<AppliedQuery>, QueryRejection>,
) -> OwnerReply<Vec<AppliedView>> {
    let owner = owner(&auth, &server)?;
    let query = query_params(query)?;
    let applied = blocking(move || -> OwnerResult<Vec<AppliedView>> {
        let applied = server
            .vault()
            .applied_dreamer_maintenance(&owner, query.limit.unwrap_or(DEFAULT_LIMIT))?;
        Ok(applied.into_iter().map(applied_view).collect())
    })
    .await?;
    Ok(Json(applied))
}

/// `POST /v1/owner/dreamer/maintenance/revert`: the owner's revert of one
/// applied write. Its effect is undone where no later write changed it, its
/// finding is retracted, and one receipt records the revert; a second revert
/// returns the first one's result.
async fn revert(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<RevertMaintenance>, JsonRejection>,
) -> OwnerReply<RevertView> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let reverted = blocking(move || -> OwnerResult<RevertView> {
        let finding = entity_id("finding", &request.finding)?;
        let now = now_unix_ms() / 1_000;
        let reverted = server
            .vault()
            .revert_dreamer_maintenance(&owner, finding, now)?;
        Ok(revert_view(reverted))
    })
    .await?;
    Ok(Json(reverted))
}
