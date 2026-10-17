//! `/v1/operator`: the host operator's own acts. Only the host's root
//! credential passes their door, never an owner's or a member's slip, and no
//! SDK verb row reaches them, so no agent does: MCP, code mode and the facade
//! serve verb rows only.
//!
//! `POST /v1/operator/shared/recover-owner` is proof-of-control owner recovery
//! (ARCH-0043, OF-163): a shared vault with no live Owner left takes the
//! claimant as its Owner. The operator judges the claimant's proof that they
//! control the organization owning the vault, outside the engine and outside
//! this route; the engine has no check for that proof and no owner lane takes
//! it. The engine checks what it holds and signs the `OwnerHandover` (cause
//! `proof_of_control`) with the host's slip issuer.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::HeaderMap;
use axum::response::Json;
use axum::routing::post;
use oneiron::EntityId;
use oneiron::federation::SharedActExecutionReceipt;
use serde::Deserialize;

use super::facade::FacadeApiError;
use crate::error::ApiError;
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route(
        "/v1/operator/shared/recover-owner",
        post(recover_shared_owner),
    )
}

/// The host operator's door: the host's own root credential, the
/// unattenuated slip whose holder is `host`, which `ensure_host_root_slip`
/// mints from this host's `auth_secret` (or a managed supervisor's issuer).
/// `check_api_auth`, the host-level admin routes' gate (`/v1/core/slips/revoke`,
/// the org-admin setup), admits any owner-grade credential, the owner's own
/// full slip included; this door narrows it to the root, the test MCP's actor
/// dispatch applies to "the actual configured root".
fn operator(headers: &HeaderMap, server: &SyncServer) -> Result<(), ApiError> {
    let auth = super::check_api_auth(headers, server)?;
    let root = auth.principal_ref().is_none()
        && auth.verified_slip().is_some_and(|proof| {
            proof.claims().holder_ref == "host" && proof.is_full_vault_owner_grade()
        });
    if root {
        Ok(())
    } else {
        Err(ApiError::forbidden_scope("operator"))
    }
}

/// `POST /v1/operator/shared/recover-owner`'s body.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoverSharedOwner {
    /// The shared vault, by the id its creation named.
    vault_id: u64,
    /// The Owner who is gone, PERSON id hex: still holding the Owner role.
    from: String,
    /// The person taking the Owner role, PERSON id hex: a live person.
    claimant: String,
    /// The proof of control the operator judged. The engine takes no note,
    /// so the log carries its BLAKE3 beside the receipt, and nothing here
    /// keeps its text.
    proof_note: String,
}

/// Answers the engine's receipt, the one the `vault.members.*` doors answer:
/// the `owner_recovered` change, the grants rewritten and the slips revoked.
async fn recover_shared_owner(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<RecoverSharedOwner>, JsonRejection>,
) -> Result<Json<SharedActExecutionReceipt>, FacadeApiError> {
    operator(&headers, &server)?;
    let request = super::json_payload(payload)?;
    let person = |field: &'static str, hex: &str| {
        EntityId::from_hex(hex)
            .map_err(|_| ApiError::bad_request(format!("{field} is not a person id"), Some(field)))
    };
    let from = person("from", &request.from)?;
    let claimant = person("claimant", &request.claimant)?;
    if request.proof_note.trim().is_empty() {
        return Err(ApiError::bad_request(
            "name the proof of control you judged",
            Some("proof_note"),
        )
        .into());
    }
    // Logs never carry text a person wrote (owner ruling 2026-10-14): the
    // note's digest ties it to this recovery, and the operator keeps the note.
    let note = blake3::hash(request.proof_note.as_bytes()).to_hex();
    let vault_id = request.vault_id;
    let recovered =
        super::facade::host_doors::operator_recover_shared_owner(&server, vault_id, from, claimant)
            .await;
    match &recovered {
        Ok(receipt) => tracing::info!(
            vault_id,
            from = %from.to_hex(),
            claimant = %claimant.to_hex(),
            receipt = %receipt.id,
            proof_note_blake3 = %note,
            "operator recovered a shared vault's owner on proof of control"
        ),
        Err(error) => tracing::warn!(
            vault_id,
            code = %error.code,
            proof_note_blake3 = %note,
            "operator owner recovery refused"
        ),
    }
    Ok(Json(recovered?))
}
