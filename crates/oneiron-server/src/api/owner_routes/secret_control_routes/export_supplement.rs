//! `/v1/owner/secrets/export-supplements/import`: the owner's import, on the
//! recipient machine he chose, of one export secret supplement (FIX 11846).
//! An owner export that could not open a custody secret here asked its
//! holder for it (FIX 4624(b)); `GET /v1/core/export-secret-supplements/
//! {request}` reads the holder's sealed copy, and this route takes that copy
//! back as it was read, opens it on this install and restores its secret
//! through the archive import's custody restore. The value never leaves the
//! engine: the reply names only what the import did. `oneiron secrets
//! import-supplement` runs the same import ([`crate::owner::export_supplement`]).

use std::sync::Arc;

use axum::extract::State;
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use axum::routing::post;
use serde::Deserialize;

use super::super::{OwnerReply, OwnerRoute, OwnerTable, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::export_supplement::{self, SupplementImported};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![(
        OwnerRoute {
            method: "post",
            path: "/secrets/export-supplements/import",
            summary: "With {\"request\", \"sealed\"} as the supplement read returns them: opens the holder's sealed copy on this install, the recipient the owner chose, and restores its secret; returns what the import did.",
            row: None,
        },
        post(import),
    )]
}

/// The OpenAPI schema of `POST /v1/owner/secrets/export-supplements/import`'s
/// body: [`ImportBody`].
pub(crate) fn import_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ImportBody>()
}

/// The OpenAPI schema of `POST /v1/owner/secrets/export-supplements/import`'s
/// answer: [`SupplementImported`].
pub(crate) fn supplement_imported_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<SupplementImported>()
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ImportBody {
    /// The export secret request's signed authority-log entry, as 64 hex:
    /// the supplement read's `request`.
    request: String,
    /// The holder's sealed copy, standard base64: the supplement read's
    /// `sealed`.
    sealed: String,
}

/// `POST /v1/owner/secrets/export-supplements/import` with `{"request",
/// "sealed"}`: opens the sealed copy for the owner whose export asked for
/// it, here, and imports its secret. A copy sealed to another machine, or
/// not the one its holder's signed result names, opens nowhere but there.
/// Its import mark records where his request reached this install, as this
/// request proves it (`machine_routes::act_surface_admitted`): audit only.
async fn import(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<ImportBody>,
) -> OwnerReply<SupplementImported> {
    let owner = owner(&auth, &server)?;
    let surface =
        super::super::machine_routes::act_surface_admitted(&server, &auth, &headers, &extensions);
    let body = payload.read(&server).await?;
    let imported = blocking(move || {
        export_supplement::import(server.vault(), &owner, surface, &body.request, &body.sealed)
    })
    .await?;
    Ok(Json(imported))
}
