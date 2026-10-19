//! `/v1/owner/owner-work/{request}`: where one owner work request stands
//! (FIX 4632, 4682, 4736). An owner act an install carries but cannot do
//! (a world's key work, a root change for another install) records a request
//! naming the one install that is to do it; its receipt is derived from the
//! fold whenever it is read: "recorded, awaiting a holder" until that
//! install's result arrives, then enacted or refused. Never a synchronous
//! success: "enacted" says the executor did the work and committed it, not
//! that every replica holds it.
//!
//! Every route that records owner work answers with the same view
//! ([`OwnerWorkView`]), so a surface polls this one read for any of them.
//! A refusal with a next step carries the engine's advice (FIX 4738), and a
//! bundle publication whose home may keep no sealed copy says why (FIX 4786).
//!
//! `/v1/owner/owner-work/{request}/diagnostics` reads what blocks a pending
//! request as its executor observes it (FIX 4686, 4784, 4785, 4787): ids and
//! closed reasons only, and only on the executor; any other install answers
//! that the executor's observation is unavailable here. It decides nothing.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::response::Json;
use axum::routing::get;
use oneiron::world_keys::{
    BundleHomeWarning, OwnerWorkDiagnostics, OwnerWorkReceipt, OwnerWorkUnassigned,
};
use serde::{Deserialize, Serialize};

use super::machine_routes::parse_revision;
use super::{OwnerReply, blocking, owner};
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/owner-work/{request}", get(status))
        .route("/owner-work/{request}/diagnostics", get(diagnostics))
}

/// One owner work receipt as a surface shows it: the receipt (ids only),
/// the engine's words for where it stands, and, when no install could be
/// named, the engine's words for why.
#[derive(Debug, Serialize)]
pub(super) struct OwnerWorkView {
    #[serde(flatten)]
    receipt: OwnerWorkReceipt,
    /// `OwnerWorkStatus::text`: "recorded, awaiting a holder", "enacted by
    /// its holder" or "refused by its holder".
    status_text: &'static str,
    /// `OwnerWorkUnassigned::text`, when nothing was recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    unassigned_text: Option<&'static str>,
    /// `OwnerWorkStatus::advice`, when a refusal names what the owner may do
    /// next: a root request whose target may not have synced (FIX 4738).
    #[serde(skip_serializing_if = "Option::is_none")]
    advice_text: Option<&'static str>,
    /// `BundleHomeWarning::text`, when a publication's home may keep no
    /// sealed copy (FIX 4786).
    #[serde(skip_serializing_if = "Option::is_none")]
    home_warning_text: Option<&'static str>,
}

impl From<OwnerWorkReceipt> for OwnerWorkView {
    fn from(receipt: OwnerWorkReceipt) -> Self {
        Self {
            status_text: receipt.status.text(),
            unassigned_text: receipt.unassigned.map(OwnerWorkUnassigned::text),
            advice_text: receipt.status.advice(),
            home_warning_text: receipt.home_warning.map(BundleHomeWarning::text),
            receipt,
        }
    }
}

/// One request's executor diagnostics as a surface shows them: ids and
/// closed reasons, with the engine's words for what this install observes.
#[derive(Debug, Serialize)]
struct OwnerWorkDiagnosticsView {
    #[serde(flatten)]
    diagnostics: OwnerWorkDiagnostics,
    /// `ExecutorObservation::text`.
    observation_text: &'static str,
}

/// Where a re-assertion's key page starts; 0 by default.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiagnosticsQuery {
    #[serde(default)]
    offset: usize,
}

/// A request's signed authority-log entry, as a surface names it: 64
/// lower-case hex, the receipt's `request`.
pub(super) fn request_entry(field: &str, value: &str) -> OwnerResult<[u8; 32]> {
    parse_revision(field, value)
}

/// `GET /v1/owner/owner-work/{request}`: the receipt of the owner work
/// request signed as entry `request`, as this install's fold stands. Not
/// found when this install folds no such request.
async fn status(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(request): Path<String>,
) -> OwnerReply<OwnerWorkView> {
    let owner = owner(&auth, &server)?;
    let view = blocking(move || -> OwnerResult<OwnerWorkView> {
        let entry = request_entry("request", &request)?;
        server
            .vault()
            .owner_work_receipt(&owner, entry)?
            .map(OwnerWorkView::from)
            .ok_or(OwnerError::NotFound("owner_work", request))
    })
    .await?;
    Ok(Json(view))
}

/// `GET /v1/owner/owner-work/{request}/diagnostics[?offset=]`: what blocks
/// the owner work request signed as entry `request`, as this install
/// observes it: its executor's own observation here, else that it is
/// unavailable. A re-assertion's keys page from `offset`. Not found when
/// this install folds no such request.
async fn diagnostics(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(request): Path<String>,
    Query(query): Query<DiagnosticsQuery>,
) -> OwnerReply<OwnerWorkDiagnosticsView> {
    let owner = owner(&auth, &server)?;
    let view = blocking(move || -> OwnerResult<OwnerWorkDiagnosticsView> {
        let entry = request_entry("request", &request)?;
        server
            .vault()
            .owner_work_diagnostics(&owner, entry, query.offset)?
            .map(|diagnostics| OwnerWorkDiagnosticsView {
                observation_text: diagnostics.observation.text(),
                diagnostics,
            })
            .ok_or(OwnerError::NotFound("owner_work", request))
    })
    .await?;
    Ok(Json(view))
}
