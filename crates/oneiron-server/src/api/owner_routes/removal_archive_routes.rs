//! The owner's list of the removal archives this vault took in (FIX 11797):
//! each by its receipt id, the shared vault it came from, its term, and
//! whether it is still kept here or has lapsed; never a byte of an archive.
//! A device's receiver imports each archive its home delivers into this, the
//! device's own vault, whose owner is the archive's person.
use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::get;
use oneiron::federation::ReceivedRemovalArchive;

use super::{OwnerReply, OwnerRoute, OwnerTable, blocking, owner};
use crate::auth::CoreAuth;
use crate::owner::OwnerResult;
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![(
        OwnerRoute {
            method: "get",
            path: "/removal-archives",
            summary: "The removal archives this vault took in for its owner: each archive's latest delivery by receipt_id, with vault_id (the shared vault it came from), delivered_at, expires_at, state (imported while kept here within its term, lapsed after) and imported_at. Never an archive's content.",
            row: None,
        },
        get(read),
    )]
}

/// The removal archives this vault took in for its owner.
#[derive(serde::Serialize)]
struct ReceivedArchives {
    archives: Vec<ReceivedRemovalArchive>,
}

async fn read(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<ReceivedArchives> {
    let owner = owner(&auth, &server)?;
    let archives = blocking(move || -> OwnerResult<Vec<ReceivedRemovalArchive>> {
        Ok(server.vault().received_removal_archives(&owner)?)
    })
    .await?;
    Ok(Json(ReceivedArchives { archives }))
}
