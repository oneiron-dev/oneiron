//! `/v1/owner/dreamer/maintenance` (OF-023, owner ruling 10-18: "autoapply +
//! revert rather than holdout"): the Dreamer's maintenance writes that
//! applied at once (a curator rung, a harness retune finding, an advisory
//! action mode, a Dreamer-born digest cadence and presentation, a
//! stewardship reach-out, a follow-up plan saved for send review, an
//! identity ask whose names were kept separate for now), and the owner's
//! revert of one. The Coach's findings still wait in the run tray.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::dreamer_runner::maintenance::{
    AppliedMaintenance, MaintenanceRevert, MaintenanceTarget,
};
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::owner::stamp::now_unix_ms;
use crate::owner::{OwnerError, OwnerResult, entity_id};
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

/// One applied write: its finding, or the identity ask it kept separate.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevertMaintenance {
    /// The applied write's finding, as 32 hex.
    #[serde(default)]
    finding: Option<String>,
    /// The identity ask a nightly abstention kept separate, as 64 hex.
    #[serde(default)]
    ask: Option<String>,
}

#[derive(Debug, Serialize)]
struct AppliedView {
    /// The finding, as 32 hex; none for an identity ask.
    finding: Option<String>,
    /// The identity ask kept separate, as 64 hex.
    ask: Option<String>,
    /// `finding`, `curator`, `proactivity_policy`, `reach_out`,
    /// `representation_plan` or `identity_provisional`.
    kind: &'static str,
    facet: String,
    /// The attempt that wrote it; none for an identity ask.
    attempt: Option<String>,
    applied_at: u64,
    receipt_ref: String,
    /// The owner's revert, once made.
    reverted: Option<RevertView>,
}

#[derive(Debug, Serialize)]
struct RevertView {
    finding: Option<String>,
    ask: Option<String>,
    /// Records standing again in place.
    restored: Vec<String>,
    /// The Dreamer's fresh copies of its own records, as `[record, copy]`.
    copied: Vec<[String; 2]>,
    /// Outputs the applied write made, closed by the revert.
    closed: Vec<String>,
    /// Settings rows put back.
    settings: Vec<String>,
    /// Identity asks put to the owner, as 64 hex.
    asked: Vec<String>,
    /// What a later write changed, left as it is.
    left_alone: Vec<String>,
    receipt_ref: String,
}

/// The target as the views spell it: `(finding, ask)`.
fn target_view(target: MaintenanceTarget) -> (Option<String>, Option<String>) {
    match target {
        MaintenanceTarget::Finding(id) => (Some(id.to_hex()), None),
        MaintenanceTarget::IdentityAsk(_) => (None, Some(target.to_hex())),
    }
}

fn revert_view(revert: MaintenanceRevert) -> RevertView {
    let hex =
        |ids: &[oneiron::EntityId]| -> Vec<String> { ids.iter().map(|id| id.to_hex()).collect() };
    let (finding, ask) = target_view(revert.target);
    RevertView {
        finding,
        ask,
        restored: hex(&revert.restored),
        copied: revert
            .copied
            .iter()
            .map(|(record, copy)| [record.to_hex(), copy.to_hex()])
            .collect(),
        closed: hex(&revert.closed),
        settings: revert.settings,
        asked: revert.asked,
        left_alone: revert.left_alone,
        receipt_ref: revert.receipt_ref,
    }
}

fn applied_view(applied: AppliedMaintenance) -> AppliedView {
    let (finding, ask) = target_view(applied.target);
    AppliedView {
        finding,
        ask,
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

/// `POST /v1/owner/dreamer/maintenance/revert` with `{"finding"}` or
/// `{"ask"}`: the owner's revert of one applied write. Its effect is undone
/// where no later write changed it, its finding is retracted (an ask kept
/// separate goes to the owner as their question), and one receipt records
/// the revert; a second revert returns the first one's result.
async fn revert(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<RevertMaintenance>, JsonRejection>,
) -> OwnerReply<RevertView> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let reverted = blocking(move || -> OwnerResult<RevertView> {
        let target = match (&request.finding, &request.ask) {
            (Some(finding), None) => MaintenanceTarget::Finding(entity_id("finding", finding)?),
            (None, Some(ask)) => MaintenanceTarget::identity_ask(ask)
                .ok_or_else(|| OwnerError::Invalid("ask must be 64 hex".into()))?,
            _ => {
                return Err(OwnerError::Invalid(
                    "name exactly one of finding or ask".into(),
                ));
            }
        };
        let now = now_unix_ms() / 1_000;
        let reverted = server
            .vault()
            .revert_dreamer_maintenance(&owner, target, now)?;
        Ok(revert_view(reverted))
    })
    .await?;
    Ok(Json(reverted))
}
