//! `/v1/owner/vault-key/generation`: the owner starts a new data-key
//! generation on a running server (DATAKEY-GEN-WHO = C).
//!
//! The WAYS = A flow: the preview names, before the act and with no secret
//! given, every wrap of the current key that no way the owner keeps covers;
//! the owner then presents each kept way (the password, each passkey's PRF
//! output, each escrow's recipient) and confirms each removal by id, and the
//! act rewraps the presented ways and removes the confirmed wraps. Only the
//! owner starts the act; an agent proposes it through
//! `vault.data_key.generation.propose`.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::response::Json;
use axum::routing::post;
use base64::Engine as _;
use oneiron::authority::ActAuthority;
use oneiron::world_keys::{
    DataKeyGenerationCause, DataKeyGenerationKeptWays, DataKeyGenerationWays, HybridPublicKey,
};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::super::machine_routes::act_surface_admitted;
use super::super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner};
use super::{SecretText, prf_bytes, read_secret_json};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::vault_key::{DataKeyGenerationPreviewView, DataKeyGenerationView};
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "post",
                path: "/vault-key/generation/preview",
                summary: "The wraps a new data-key generation would remove: every wrap of the current key that no way the owner keeps covers.",
                row: None,
                shape: Some(RestShape::json(
                    generation_preview_body_schema,
                    generation_preview_schema,
                )),
            },
            post(generation_preview),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/vault-key/generation",
                summary: "Starts a new data-key generation: new data is sealed under a fresh key; each presented way is rewrapped and each confirmed wrap removed.",
                row: None,
                shape: Some(RestShape::json(generation_body_schema, generation_schema)),
            },
            post(start_generation),
        ),
    ]
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct GenerationPreviewRequest {
    /// The owner keeps the vault password.
    #[serde(default)]
    password: bool,
    /// The credential names of the passkeys the owner keeps.
    #[serde(default)]
    passkeys: Vec<String>,
    /// The labels of the escrows the owner keeps.
    #[serde(default)]
    escrows: Vec<String>,
}

/// `POST /v1/owner/vault-key/generation/preview`: the wraps a new data-key
/// generation would remove. It holds no secret: the screen names the
/// removals before the owner types anything.
async fn generation_preview(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<GenerationPreviewRequest>,
) -> OwnerReply<DataKeyGenerationPreviewView> {
    owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let preview = blocking(move || -> OwnerResult<DataKeyGenerationPreviewView> {
        let vault = server.vault();
        let kept = DataKeyGenerationKeptWays {
            password: request.password,
            passkeys: request.passkeys.into_iter().collect(),
            escrows: request.escrows.into_iter().collect(),
        };
        Ok(DataKeyGenerationPreviewView::of(
            &vault.vault_key_vault_id(),
            vault.data_key_generation_preview(&kept)?,
        ))
    })
    .await?;
    Ok(Json(preview))
}

/// A passkey the owner keeps, with its PRF output.
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct KeptPasskey {
    /// The passkey's credential name.
    credential: String,
    /// The PRF output at `GET /vault-key/prf-input`: 32 bytes, hex or
    /// base64url.
    prf: SecretText,
}

/// An escrow the owner keeps, with the recipient it is sealed to.
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct KeptEscrow {
    /// The escrow's label.
    label: String,
    /// The hybrid public key's bytes, base64url without padding.
    recipient: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct GenerationRequest {
    /// The vault password, when the owner keeps it.
    #[serde(default)]
    password: Option<SecretText>,
    /// The passkeys the owner keeps, each with its PRF output.
    #[serde(default)]
    passkeys: Vec<KeptPasskey>,
    /// The escrows the owner keeps, each with the recipient it is sealed to.
    #[serde(default)]
    escrows: Vec<KeptEscrow>,
    /// The ids of the wraps the owner confirmed for removal.
    #[serde(default)]
    confirmed_removals: Vec<String>,
}

/// `POST /v1/owner/vault-key/generation`: starts a new data-key generation.
/// The act unlocks with this device's wrap itself and refuses "unlock the
/// vault key first" otherwise; it mints no key on a vault with none.
async fn start_generation(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    request: Request,
) -> OwnerReply<DataKeyGenerationView> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface_admitted(&server, &auth, request.headers(), request.extensions());
    // The body bytes are wiped after parsing (FIX 6670).
    let request = read_secret_json::<GenerationRequest>(request).await?;
    let view = blocking(move || -> OwnerResult<DataKeyGenerationView> {
        let prfs: Vec<Zeroizing<[u8; 32]>> = request
            .passkeys
            .iter()
            .map(|kept| prf_bytes(&kept.prf))
            .collect::<OwnerResult<_>>()?;
        let recipients: Vec<HybridPublicKey> = request
            .escrows
            .iter()
            .map(|kept| recipient_key(&kept.recipient))
            .collect::<OwnerResult<_>>()?;
        let passkeys: Vec<(&str, &Zeroizing<[u8; 32]>)> = request
            .passkeys
            .iter()
            .zip(&prfs)
            .map(|(kept, prf)| (kept.credential.as_str(), prf))
            .collect();
        let escrows: Vec<(&str, &HybridPublicKey)> = request
            .escrows
            .iter()
            .zip(&recipients)
            .map(|(kept, recipient)| (kept.label.as_str(), recipient))
            .collect();
        let ways = DataKeyGenerationWays {
            password: request.password.as_ref().map(|secret| secret.0.as_bytes()),
            passkeys,
            escrows,
            confirmed_removals: request.confirmed_removals.into_iter().collect(),
        };
        let vault = server.vault();
        let authority = ActAuthority::Owner(owner, surface);
        let outcome = vault
            .start_data_key_generation_as(&authority, DataKeyGenerationCause::OwnerRequest, &ways)
            .map_err(unconfirmed_as_refused)?;
        Ok(DataKeyGenerationView::of(
            &vault.vault_key_vault_id(),
            outcome,
        ))
    })
    .await?;
    Ok(Json(view))
}

/// An escrow's recipient: the hybrid public key's bytes, base64url.
fn recipient_key(recipient: &str) -> OwnerResult<HybridPublicKey> {
    let refused =
        || OwnerError::Invalid("an escrow recipient is a hybrid public key, base64url".to_owned());
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(recipient.trim_end_matches('='))
        .map_err(|_| refused())?;
    HybridPublicKey::from_bytes(&bytes).map_err(|_| refused())
}

/// The act's refusal of a way neither presented nor confirmed, in the
/// owner's words: `ErrorKind::WorldKeyRefused` has no owner mapping, so the
/// engine's error would answer 500 and drop which way it was; as a refusal
/// it answers 409 naming the way to present or confirm.
fn unconfirmed_as_refused(error: oneiron::Error) -> OwnerError {
    if matches!(
        error,
        oneiron::Error::Secret(oneiron::error::SecretError::DataKeyGenerationWayUnconfirmed { .. })
    ) {
        OwnerError::Refused(error.to_string())
    } else {
        OwnerError::Engine(Box::new(error))
    }
}

/// The OpenAPI schema of `POST /v1/owner/vault-key/generation/preview`'s
/// body: [`GenerationPreviewRequest`].
pub(crate) fn generation_preview_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<GenerationPreviewRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/vault-key/generation/preview`'s
/// answer: [`DataKeyGenerationPreviewView`].
pub(crate) fn generation_preview_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<DataKeyGenerationPreviewView>()
}

/// The OpenAPI schema of `POST /v1/owner/vault-key/generation`'s body:
/// [`GenerationRequest`].
pub(crate) fn generation_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<GenerationRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/vault-key/generation`'s answer:
/// [`DataKeyGenerationView`].
pub(crate) fn generation_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<DataKeyGenerationView>()
}
