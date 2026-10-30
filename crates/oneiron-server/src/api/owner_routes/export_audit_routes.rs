//! `GET /v1/owner/exports`: the vault's export audit (FIX 6427, owner ruling
//! RT-EXPORT 2026-10-20). Each Owner copy of the whole vault, or of an
//! off-record room's talk, is one row: its id, what it copied, whose copy it
//! is, when and in what shape. Every live co-Owner reads every row, whoever
//! exported; no row names a thread, a title, a member or a word of what
//! left.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::get;
use oneiron::memory::ExportReceipt;

use super::{OwnerReply, OwnerRoute, OwnerTable, blocking, owner};
use crate::auth::CoreAuth;
use crate::owner::OwnerResult;
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![(
        OwnerRoute {
            method: "get",
            path: "/exports",
            summary: "The vault's export audit (FIX 6427), oldest first: one row per Owner copy of the whole vault or of an off-record room's talk, with its id, what it copied, whose copy it is, when and in what shape. Every live co-Owner reads every row; no row names a thread, a title, a member or a word of what left.",
            row: None,
        },
        get(list),
    )]
}

/// `GET /v1/owner/exports`: every export audit row, oldest first, read in
/// the snapshot that revalidates the caller's owner proof.
async fn list(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<ExportReceipt>> {
    let owner = owner(&auth, &server)?;
    let rows = blocking(move || -> OwnerResult<Vec<ExportReceipt>> {
        Ok(server.vault().owner_export_audit(&owner)?)
    })
    .await?;
    Ok(Json(rows))
}
