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

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::response::Json;
use axum::routing::get;
use oneiron::world_keys::{OwnerWorkReceipt, OwnerWorkUnassigned};
use serde::Serialize;

use super::machine_routes::parse_revision;
use super::{OwnerReply, blocking, owner};
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/owner-work/{request}", get(status))
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
}

impl From<OwnerWorkReceipt> for OwnerWorkView {
    fn from(receipt: OwnerWorkReceipt) -> Self {
        Self {
            status_text: receipt.status.text(),
            unassigned_text: receipt.unassigned.map(OwnerWorkUnassigned::text),
            receipt,
        }
    }
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
