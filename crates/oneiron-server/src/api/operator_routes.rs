//! `/v1/operator`: the host operator's own acts. The host's root credential
//! passes their door, and on a self-hosted vault the operator's own
//! credential (FIX 1814, `auth::operator_credential`) does too, as a
//! credential class that is never a person or an owner's proof; never an
//! owner's or a member's slip. No SDK verb row reaches them, so no agent
//! does: MCP, code mode and the facade serve verb rows only. On a managed
//! vault the account's owner, whom his supervisor attested for the one
//! request, passes it too, as himself.
//!
//! `POST /v1/operator/shared/recover-owner` is proof-of-control owner recovery
//! (ARCH-0043, OF-163): a shared vault with no live Owner left takes the
//! claimant as its Owner, on an authenticated recovery authorization the
//! writer judges again (FIX 1812): on a managed vault the attested account
//! owner's own say-so (FIX 5255), the hosting account being the
//! organization's control; on a self-hosted vault its host's live root, which
//! acts there as the vault's owner (FIX 2222). A hosted operator's root acts
//! as nobody, so it gets the typed support-grant refusal and recovers no
//! Owner, and so does the operator's own credential, which acts as no owner.
//! The engine checks what it holds and signs the `OwnerHandover` (cause
//! `proof_of_control`) with the host's slip issuer.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::request::Parts;
use axum::response::Json;
use axum::routing::post;
use oneiron::EntityId;
use oneiron::authority::HostActionAuthority;
use oneiron::federation::{OwnerRecoveryAuthorization, SharedActExecutionReceipt};
use serde::Deserialize;

use super::facade::FacadeApiError;
use super::scoped_auth::AdminCaller;
use crate::error::ApiError;
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route(
        "/v1/operator/shared/recover-owner",
        post(recover_shared_owner),
    )
}

/// Who passes the host operator's door ([`operator`]).
enum OperatorCaller {
    /// The host's own root, as the owner its host action names.
    Root(HostActionAuthority),
    /// The operator's own credential on a self-hosted vault (FIX 1814): a
    /// credential class, never a person or an owner's proof.
    Credential(crate::auth::OperatorCredential),
}

/// The host operator's door: the host's own root credential, the
/// unattenuated slip whose holder is `host`, which `ensure_host_root_slip`
/// mints from this host's `auth_secret` (or a managed supervisor's issuer),
/// or on a self-hosted vault the operator's own credential, which the same
/// issuer mints (`oneiron token operator`, FIX 1814).
/// `check_api_auth`, the host-level admin routes' gate (`/v1/core/slips/revoke`,
/// the org-admin setup), admits any owner-grade credential, the owner's own
/// full slip included; this door narrows it to the root, the test MCP's actor
/// dispatch applies to "the actual configured root".
fn operator(request: &Parts, server: &SyncServer) -> Result<OperatorCaller, ApiError> {
    let path = crate::auth::request_path(request);
    let auth = match super::check_api_auth(&request.headers, path, server)? {
        AdminCaller::Operator(credential) => return Ok(OperatorCaller::Credential(credential)),
        AdminCaller::Credential(auth) => auth,
    };
    let root = auth.principal_ref().is_none()
        && auth.verified_slip().is_some_and(|proof| {
            proof.claims().holder_ref == "host" && proof.is_full_vault_owner_grade()
        });
    if !root {
        return Err(ApiError::forbidden_scope("operator"));
    }
    // The root acts as the owner its host action names only on a self-hosted
    // vault; a hosted operator's root gets the typed refusal (FIX 1812).
    match auth.host_root() {
        Some(root) => server
            .vault()
            .host_action_authority(root)
            .map(OperatorCaller::Root)
            .map_err(super::host_action::host_action_refusal),
        None => Err(ApiError::forbidden_scope("operator")),
    }
}

/// Who answers for one owner recovery.
enum Recoverer {
    /// A self-hosted vault's host, on its own root credential, acting as the
    /// owner its host action names.
    Operator(HostActionAuthority),
    /// A managed vault's account owner, whom his supervisor attested for
    /// this one request (`ManagedOwnerAction`, verified at managed ingress),
    /// with no caller slip of its own: the recovery is his own act, never
    /// the host's. He need not be a live Owner, since a vault this door
    /// recovers has none left.
    AccountOwner(EntityId),
}

/// The door of `POST /v1/operator/shared/recover-owner`: a managed vault's
/// attested account owner as himself, else the host operator's root
/// ([`operator`]), unchanged. The operator's own credential passes the
/// operator's door but recovers no Owner: a recovery is the owner's act
/// (FIX 1812), and that credential is no owner's proof (FIX 1814), so it
/// gets the 403 that names the owner's scope.
fn recoverer(request: &Parts, server: &SyncServer) -> Result<Recoverer, ApiError> {
    if let Some(holder) = crate::auth::attested_owner(&request.extensions, server)
        && !crate::auth::carries_caller_slip(&request.headers)
    {
        return Ok(Recoverer::AccountOwner(holder));
    }
    match operator(request, server)? {
        OperatorCaller::Root(action) => Ok(Recoverer::Operator(action)),
        OperatorCaller::Credential(credential) => {
            tracing::info!(
                slip_id = %oneiron_vault_contract::hex(&credential.slip_id()),
                "an operator credential asked for an owner recovery, which is the owner's act"
            );
            Err(ApiError::forbidden_scope("owner"))
        }
    }
}

impl Recoverer {
    /// This recoverer's authorization for the writer (FIX 1812), with the
    /// BLAKE3 of the note it gave.
    fn authorization(&self, note: [u8; 32]) -> OwnerRecoveryAuthorization {
        match self {
            Self::Operator(action) => OwnerRecoveryAuthorization::SelfHostRoot {
                action: action.clone(),
                note,
            },
            Self::AccountOwner(holder) => OwnerRecoveryAuthorization::AccountOwner {
                holder: *holder,
                note,
            },
        }
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
    parts: Parts,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<RecoverSharedOwner>, JsonRejection>,
) -> Result<Json<SharedActExecutionReceipt>, FacadeApiError> {
    let by = recoverer(&parts, &server)?;
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
    // The signed OwnerHandover keeps the same digest (OF-163); a blank note
    // was refused above, so there is always one.
    let digest = blake3::hash(request.proof_note.as_bytes());
    let note = digest.to_hex();
    let vault_id = request.vault_id;
    let recovered = super::facade::host_doors::operator_recover_shared_owner(
        &server,
        vault_id,
        from,
        claimant,
        by.authorization(*digest.as_bytes()),
    )
    .await;
    match (&recovered, by) {
        (Ok(receipt), Recoverer::Operator(_)) => tracing::info!(
            vault_id,
            from = %from.to_hex(),
            claimant = %claimant.to_hex(),
            receipt = %receipt.id,
            proof_note_blake3 = %note,
            "operator recovered a shared vault's owner on proof of control"
        ),
        (Err(error), Recoverer::Operator(_)) => tracing::warn!(
            vault_id,
            code = %error.code,
            proof_note_blake3 = %note,
            "operator owner recovery refused"
        ),
        (Ok(receipt), Recoverer::AccountOwner(owner)) => tracing::info!(
            vault_id,
            owner = %owner.to_hex(),
            from = %from.to_hex(),
            claimant = %claimant.to_hex(),
            receipt = %receipt.id,
            proof_note_blake3 = %note,
            "the attested account owner recovered a shared vault's owner"
        ),
        (Err(error), Recoverer::AccountOwner(owner)) => tracing::warn!(
            vault_id,
            owner = %owner.to_hex(),
            code = %error.code,
            proof_note_blake3 = %note,
            "the attested account owner's owner recovery refused"
        ),
    }
    Ok(Json(recovered?))
}
