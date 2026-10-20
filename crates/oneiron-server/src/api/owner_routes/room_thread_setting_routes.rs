//! `/v1/owner/settings/room-threads`: the owner's two switches over Admins
//! and private room threads (owner ruling 2026-10-20, FIX 6382). Off, an
//! Admin may not walk into a private thread
//! (`rooms.private_threads.admin_walk_in`), or delete one
//! (`rooms.private_threads.admin_delete`). Both read ON until the Owner
//! turns one off, and the Owner never depends on either.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use axum::routing::get;
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::owner::OwnerResult;
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/settings/room-threads", get(read).post(put))
}

/// The owner's two switches, as they read now.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RoomThreadSettings {
    /// Whether an Admin may walk into a private thread, from now on.
    admin_walk_in: bool,
    /// Whether an Admin may delete a private thread.
    admin_delete: bool,
}

/// A change to either switch, or both; an absent one stays as it is.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoomThreadSettingsChange {
    #[serde(default)]
    admin_walk_in: Option<bool>,
    #[serde(default)]
    admin_delete: Option<bool>,
}

impl From<oneiron::settings::RoomThreadAdminSettings> for RoomThreadSettings {
    fn from(settings: oneiron::settings::RoomThreadAdminSettings) -> Self {
        Self {
            admin_walk_in: settings.admin_walk_in,
            admin_delete: settings.admin_delete,
        }
    }
}

/// `GET /v1/owner/settings/room-threads`.
async fn read(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<RoomThreadSettings> {
    owner(&auth, &server)?;
    let settings = blocking(move || -> OwnerResult<RoomThreadSettings> {
        Ok(server.vault().room_thread_admin_settings()?.into())
    })
    .await?;
    Ok(Json(settings))
}

/// `POST /v1/owner/settings/room-threads`: sets either switch, or both, and
/// answers the two as they now read; the next walk-in or delete reads them.
async fn put(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<RoomThreadSettingsChange>, JsonRejection>,
) -> OwnerReply<RoomThreadSettings> {
    let owner = owner(&auth, &server)?;
    let change = json_payload(payload)?;
    let settings = blocking(move || -> OwnerResult<RoomThreadSettings> {
        Ok(server
            .vault()
            .set_room_thread_admin_settings(&owner, change.admin_walk_in, change.admin_delete)?
            .into())
    })
    .await?;
    Ok(Json(settings))
}
