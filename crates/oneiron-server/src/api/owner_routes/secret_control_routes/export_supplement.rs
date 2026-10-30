//! `/v1/owner/secrets/export-supplements/import`: the owner's import, on the
//! recipient machine he chose, of one export secret supplement (FIX 11846).
//! An owner export that could not open a custody secret here asked its
//! holder for it (FIX 4624(b)); `GET /v1/core/export-secret-supplements/
//! {request}` reads the holder's sealed copy, and this route takes that copy
//! back as it was read, opens it on this install and restores its secret
//! through the archive import's custody restore. The value never leaves the
//! engine: the reply names only what the import did.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::post;
use base64::Engine as _;
use oneiron::authority::SecretSupplementImport;
use oneiron::consent::AuthenticatedOwner;
use serde::{Deserialize, Serialize};

use super::super::{OwnerReply, OwnerRoute, OwnerTable, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult};
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

/// What the import of one supplement did.
#[derive(Debug, Serialize, schemars::JsonSchema)]
struct SupplementImported {
    /// The export secret request, as 64 hex.
    request: String,
    outcome: SecretSupplementImport,
}

/// `POST /v1/owner/secrets/export-supplements/import` with `{"request",
/// "sealed"}`: opens the sealed copy for the owner whose export asked for
/// it, here, and imports its secret. A copy sealed to another machine, or
/// not the one its holder's signed result names, opens nowhere but there.
async fn import(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<ImportBody>,
) -> OwnerReply<SupplementImported> {
    let owner = owner(&auth, &server)?;
    let body = payload.read(&server).await?;
    let imported = blocking(move || import_supplement(server.vault(), &owner, &body)).await?;
    Ok(Json(imported))
}

fn import_supplement(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    body: &ImportBody,
) -> OwnerResult<SupplementImported> {
    let request = blake3::Hash::from_hex(&body.request)
        .map_err(|_| OwnerError::Invalid("request must be a 64-hex authority entry".to_owned()))?;
    let sealed = base64::engine::general_purpose::STANDARD
        .decode(&body.sealed)
        .map_err(|_| {
            OwnerError::Invalid(
                "sealed must be standard base64, as the supplement read returns it".to_owned(),
            )
        })?;
    let opened = vault.open_export_secret_supplement(owner, *request.as_bytes(), &sealed)?;
    let outcome = vault.import_secret_supplement(owner, &opened)?;
    Ok(SupplementImported {
        request: request.to_hex().to_string(),
        outcome,
    })
}
