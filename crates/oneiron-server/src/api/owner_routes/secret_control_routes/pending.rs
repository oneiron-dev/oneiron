//! `/v1/owner/secrets/custody/pending`: the owner's card over a restore's
//! credentials pending on their source's evidence, and his one typed
//! confirm that keeps a whole batch without it (FIX-LIST 10671 (b)). Any
//! live vault Owner, a co-Owner included, reads and confirms; the confirm
//! is an ask a surface puts in its own words, never a block. Nothing here
//! reads a value.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use axum::routing::get;
use oneiron::secret_custody::{
    PendingCredentialBatch, PendingCredentialConfirmation, PendingCredentialReleaseReceipt,
};
use serde::{Deserialize, Serialize};

use super::super::{OwnerReply, blocking, owner};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/secrets/custody/pending", get(pending).post(release))
}

/// Every batch, and what the owner may confirm.
#[derive(Debug, Serialize)]
struct PendingPage {
    batches: Vec<BatchView>,
}

/// One restore's batch: what waits on its source, and the receipt of the
/// confirm that kept it, if one did.
#[derive(Debug, Serialize)]
struct BatchView {
    /// The batch, as 32 hex.
    batch: String,
    pending: Vec<CardView>,
    released: Option<ReceiptView>,
    /// The one typed confirm `POST` takes for this batch while any waits.
    confirm: Option<&'static str>,
}

/// One pending credential, by handle.
#[derive(Debug, Serialize)]
struct CardView {
    handle: String,
    generation: u32,
}

/// A released batch's receipt.
#[derive(Debug, Serialize)]
struct ReceiptView {
    batch: String,
    /// The owner who confirmed, as 32 hex; absent once his identity is erased.
    by: Option<String>,
    at: u64,
    confirmation: &'static str,
    /// The owner's election, never a check of the source.
    note: &'static str,
    outcomes: Vec<OutcomeView>,
}

/// What one credential came to: `readable`, `still_unavailable`, `erased`,
/// `superseded` or `pending`.
#[derive(Debug, Serialize)]
struct OutcomeView {
    handle: String,
    generation: u32,
    result: &'static str,
}

impl From<PendingCredentialReleaseReceipt> for ReceiptView {
    fn from(receipt: PendingCredentialReleaseReceipt) -> Self {
        Self {
            batch: receipt.batch.to_hex(),
            by: receipt.by.map(|by| by.to_hex()),
            at: receipt.at,
            confirmation: receipt.confirmation.as_str(),
            note: receipt.note(),
            outcomes: receipt
                .outcomes
                .into_iter()
                .map(|outcome| OutcomeView {
                    handle: outcome.handle,
                    generation: outcome.generation,
                    result: outcome.result.as_str(),
                })
                .collect(),
        }
    }
}

impl From<PendingCredentialBatch> for BatchView {
    fn from(batch: PendingCredentialBatch) -> Self {
        Self {
            batch: batch.batch.to_hex(),
            confirm: (!batch.pending.is_empty())
                .then_some(PendingCredentialConfirmation::KeepWithoutSource.as_str()),
            pending: batch
                .pending
                .into_iter()
                .map(|card| CardView {
                    handle: card.handle,
                    generation: card.generation,
                })
                .collect(),
            released: batch.released.map(ReceiptView::from),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseBody {
    /// The batch, as 32 hex.
    batch: String,
    /// `keep_without_source`: "the source is gone, keep these".
    confirm: String,
}

/// `GET /v1/owner/secrets/custody/pending`: each restore batch whose
/// credentials wait on their source's evidence, by handle, and each batch
/// an owner kept, with its receipt.
async fn pending(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<PendingPage> {
    let owner = owner(&auth, &server)?;
    let page = blocking(move || -> OwnerResult<PendingPage> {
        let batches = server.vault().pending_credential_batches_as_owner(&owner)?;
        Ok(PendingPage {
            batches: batches.into_iter().map(BatchView::from).collect(),
        })
    })
    .await?;
    Ok(Json(page))
}

/// `POST /v1/owner/secrets/custody/pending` with `{"batch", "confirm":
/// "keep_without_source"}`: keeps every credential the batch holds pending
/// on its source's evidence as the image carried it, and returns the
/// batch's receipt; a repeat returns it.
async fn release(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ReleaseBody>, JsonRejection>,
) -> OwnerReply<ReceiptView> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let receipt = blocking(move || -> OwnerResult<ReceiptView> {
        let batch = entity_id("batch", &request.batch)?;
        let confirmation = PendingCredentialConfirmation::parse(&request.confirm)
            .ok_or_else(|| OwnerError::Invalid("confirm must be keep_without_source".into()))?;
        let vault = server.vault();
        Ok(vault
            .release_pending_credential_batch_as_owner(
                &owner,
                &batch,
                confirmation,
                vault.now_recorded_at(),
            )?
            .into())
    })
    .await?;
    Ok(Json(receipt))
}
