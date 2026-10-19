//! `/v1/owner/recovery-kit`: the world kit's public status on a running
//! server (OF-173). The direct ceremony (issue, confirm, restore) stays with
//! `oneiron recovery-kit` on a stopped vault. On a running server a root
//! change goes through the owner's request and its target
//! (`root_routes`, `recovery_kit_target_routes`; FIX 4530, 4736): a piece or
//! a passphrase crosses HTTP only in the target install's own call, for that
//! call alone, and never through a coordinating install's reply.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::response::Json;
use axum::routing::get;

use super::{OwnerReply, blocking, owner};
use crate::auth::CoreAuth;
use crate::owner::recovery_kit::{self as view, KitStatusView};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/recovery-kit", get(status))
}

/// `GET /v1/owner/recovery-kit`: the kits this vault issued, the current
/// one, and each private world's no-kit state here.
async fn status(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<KitStatusView> {
    owner(&auth, &server)?;
    let report = blocking(move || Ok(view::report(server.vault())?)).await?;
    Ok(Json(report))
}
