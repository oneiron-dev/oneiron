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
//! A root request the owner cancelled, or a newer one superseded, reads as
//! such, and his cancel says whether it came too late (FIX 4739).
//!
//! `POST /v1/owner/bundles/publications` records the owner's ask that the
//! vault's sealed bundle be published to one home (FIX 4782,
//! `Vault::request_bundle_publication`). Its answer is that request's view,
//! polled here at `GET /v1/owner/owner-work/{request}` by its `request`:
//! "recorded, awaiting a holder" until the publishing install's result
//! arrives, or why nothing was recorded. Where he spoke from is the request's
//! own (`machine_routes::act_surface_admitted`): audit only.
//!
//! `/v1/owner/owner-work/{request}/diagnostics` reads what blocks a pending
//! request as its executor observes it (FIX 4686, 4784, 4785, 4787): ids and
//! closed reasons only, and only on the executor; any other install answers
//! that the executor's observation is unavailable here. It decides nothing.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::secret_custody::CustodyManifestCheck;
use oneiron::world_keys::{
    BundleHomeWarning, OwnerWorkDiagnostics, OwnerWorkReceipt, OwnerWorkUnassigned,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::machine_routes::{act_surface_admitted, parse_revision};
use super::{OwnerReply, OwnerRoute, OwnerTable, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/owner-work/{request}",
                summary: "Where one owner work request stands, from this install's fold: the receipt (ids only), recorded and awaiting a holder until its executor's result arrives, then enacted or refused, with the engine's words.",
                row: None,
            },
            get(status),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/owner-work/{request}/diagnostics",
                summary: "What blocks one pending owner work request, as its executor observes it: a re-assertion's keys and their blockers (paged by offset), or a bundle publication's home, relay reach, outer capsules and unresolved attempt. Ids and closed reasons only; any other install answers that the executor's observation is unavailable here.",
                row: None,
            },
            get(diagnostics),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/bundles/publications",
                summary: "Records the owner's ask that the vault's sealed bundle be published to one linked home, ids only; the receipt is recorded and awaiting a holder, polled at /v1/owner/owner-work/{request}, or says why nothing was recorded.",
                row: None,
            },
            post(publish_bundle),
        ),
    ]
}

/// One owner work receipt with the holder's manifest judgment as a surface
/// shows it (FIX 5446): the receipt (ids only) and, for a custody register
/// whose result carries one, the words for what its holder checked.
/// Reporting only: an unchecked registration stays accepted.
#[derive(Debug, Serialize)]
pub(super) struct OwnerWorkReceiptView {
    #[serde(flatten)]
    receipt: OwnerWorkReceipt,
    /// `CustodyManifestCheck::Judged(check).text()`, when the receipt's
    /// `manifest_check` names one; `None` before the result, and for any
    /// other work.
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_text: Option<String>,
}

impl From<OwnerWorkReceipt> for OwnerWorkReceiptView {
    fn from(receipt: OwnerWorkReceipt) -> Self {
        let manifest_text = receipt
            .manifest_check
            .clone()
            .map(|check| CustodyManifestCheck::Judged(check).text());
        Self {
            receipt,
            manifest_text,
        }
    }
}

/// One owner work receipt as a surface shows it: the receipt (ids only),
/// the engine's words for where it stands, and, when no install could be
/// named, the engine's words for why.
#[derive(Debug, Serialize)]
pub(super) struct OwnerWorkView {
    #[serde(flatten)]
    receipt: OwnerWorkReceiptView,
    /// `OwnerWorkStatus::text`: "recorded, awaiting a holder", "enacted by
    /// its holder", "refused by its holder", "cancelled by the owner" or
    /// "superseded by a newer request on its target".
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
    /// `OwnerWorkCancelState::text`, when the owner cancelled a root request:
    /// "cancelled", or that its target answered it first, "already enacted"
    /// (FIX 4739).
    #[serde(skip_serializing_if = "Option::is_none")]
    cancel_text: Option<&'static str>,
}

impl From<OwnerWorkReceipt> for OwnerWorkView {
    fn from(receipt: OwnerWorkReceipt) -> Self {
        let status_text = receipt.status.text();
        let unassigned_text = receipt.unassigned.map(OwnerWorkUnassigned::text);
        let advice_text = receipt.status.advice();
        let home_warning_text = receipt.home_warning.as_ref().map(BundleHomeWarning::text);
        let cancel_text = receipt.cancel.as_ref().map(|cancel| cancel.state.text());
        Self {
            status_text,
            unassigned_text,
            advice_text,
            home_warning_text,
            cancel_text,
            receipt: OwnerWorkReceiptView::from(receipt),
        }
    }
}

/// `POST /v1/owner/bundles/publications`'s body: the linked install that is
/// to keep the sealed bundle. Ids only.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct BundlePublicationRequest {
    /// The home install, 32 hex.
    home: String,
}

/// The OpenAPI schema of `POST /v1/owner/bundles/publications`'s body (FIX
/// 4782): [`BundlePublicationRequest`].
pub(crate) fn bundle_publication_body_schema() -> Value {
    oneiron_contracts::code_run::vault_read::request_schema::<BundlePublicationRequest>()
}

/// The OpenAPI schema of [`OwnerWorkView`], as every route that records
/// owner work answers it (FIX 4782). The receipt's engine types carry no
/// schema derive, so its fields are spelled here, beside the view; each
/// closed value names its current words without fixing the set.
pub(crate) fn owner_work_view_schema() -> Value {
    let text = |what: &str| json!({"type": "string", "description": what});
    json!({
        "type": "object",
        "description": "One owner work request's receipt as a surface shows it: ids only, with the engine's words for where it stands.",
        "required": ["kind", "target", "status", "status_text"],
        "properties": {
            "request": {
                "type": ["string", "null"],
                "description": "The request's signed authority-log entry, 64 hex: read it again at GET /v1/owner/owner-work/{request}. Null when no install could be named and nothing was recorded."
            },
            "kind": text("What the work is: world_key, root, publish_bundle or custody."),
            "target": text("What the work is for, 32 hex: the world, the install a root change is for, the home a bundle publication is for, or a secret's custody record."),
            "executor": {
                "type": ["string", "null"],
                "description": "The one install that is to do it, 32 hex; null with no request."
            },
            "status": {
                "type": "object",
                "description": "Where it stands.",
                "required": ["state"],
                "properties": {
                    "state": text("recorded_awaiting_holder, enacted, refused, cancelled or superseded."),
                    "reason": text("With refused: why its holder refused it, as owner_not_live or home_not_linked.")
                }
            },
            "unassigned": text("Why no install was named, when nothing was recorded: as no_bundle_holder or target_not_linked."),
            "manifest_check": {
                "type": "object",
                "description": "For a custody register, what its holder checked the record against, as its signed result says."
            },
            "home_warning": text("For a bundle publication, why its home may keep no sealed copy: home_does_not_keep_sealed_bundles or home_profile_unknown. It decides nothing."),
            "cancel": {
                "type": "object",
                "description": "For a root request the owner cancelled: each cancel's entry and where it stands.",
                "properties": {
                    "entries": {"type": "array", "items": {"type": "string"}},
                    "state": text("cancelled, already_enacted or already_refused.")
                }
            },
            "manifest_text": text("The words for manifest_check."),
            "status_text": text("The words for status: as \"recorded, awaiting a holder\"."),
            "unassigned_text": text("The words for unassigned."),
            "advice_text": text("What the owner may do next, when a refusal names it."),
            "home_warning_text": text("The words for home_warning."),
            "cancel_text": text("The words for cancel's state.")
        }
    })
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

/// `POST /v1/owner/bundles/publications`: records the owner's ask that the
/// vault's sealed bundle be published to `home`. Its answer is the request's
/// view: "recorded, awaiting a holder" until the publishing install's result
/// arrives, then enacted or refused, each read again at
/// `GET /v1/owner/owner-work/{request}`; with no install to name, nothing is
/// recorded and the view says why. A home that may keep no sealed copy says
/// so beside it, and decides nothing.
async fn publish_bundle(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<BundlePublicationRequest>,
) -> OwnerReply<OwnerWorkView> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let body = payload.read(&server).await?;
    let view = blocking(move || -> OwnerResult<OwnerWorkView> {
        let home = entity_id("home", &body.home)?;
        Ok(server
            .vault()
            .request_bundle_publication(&owner, surface, home)?
            .into())
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
