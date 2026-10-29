//! `/v1/owner/secrets/custody/pending`: the owner's card over a restore's
//! credentials pending on their source's evidence, and his one typed
//! confirm that keeps a whole batch without it (FIX-LIST 10671 (b)). Any
//! live vault Owner, a co-Owner included, reads and confirms; the confirm
//! is an ask a surface puts in its own words, never a block. Nothing here
//! reads a value. The views and each batch's card are shared with `oneiron
//! secrets pending` (FIX 11158, [`crate::owner::pending_custody`]).

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::response::Json;
use axum::routing::get;
use serde::Deserialize;

use super::super::{OwnerReply, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::pending_custody::{self, PendingPage, ReceiptView};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/secrets/custody/pending", get(pending).post(release))
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
/// an owner kept, with its receipt and its card.
async fn pending(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<PendingPage> {
    let owner = owner(&auth, &server)?;
    let page = blocking(move || pending_custody::page(server.vault(), &owner)).await?;
    Ok(Json(page))
}

/// `POST /v1/owner/secrets/custody/pending` with `{"batch", "confirm":
/// "keep_without_source"}`: keeps every credential the batch holds pending
/// on its source's evidence as the image carried it, and returns the
/// batch's receipt; a repeat returns it.
async fn release(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<ReleaseBody>,
) -> OwnerReply<ReceiptView> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let receipt = blocking(move || {
        pending_custody::keep(server.vault(), &owner, &request.batch, &request.confirm)
    })
    .await?;
    Ok(Json(receipt))
}
