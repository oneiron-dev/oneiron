//! `/v1/owner/recovery-kit`: the world kit's public status on a running
//! server (OF-173). Issue, confirm and restore stay with `oneiron
//! recovery-kit` on the owner's machine, so no piece or passphrase ever
//! crosses HTTP.

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
