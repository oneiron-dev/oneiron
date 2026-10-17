//! `/v1/owner/vault-key`: the vault data key's wraps on a running server
//! (OF-570 E1), the host half of the passkey ceremony.
//!
//! A passkey enrolls in three steps. The client asks for the PRF input of the
//! credential name it will use (`GET /vault-key/prf-input`), has the
//! authenticator evaluate its PRF there (`extensions.prf.eval.first`), and
//! hands the 32-byte output in (`POST /vault-key/passkeys`); the engine seals
//! the key to it. The input is fixed by the vault and the name, so a new host
//! holding only a backup asks for the same output (`oneiron restore --inspect`
//! prints it). The engine rechecks the owner in the transaction that adds or
//! removes a wrap. An unlock holds the key on this server's handle only.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::world_keys::{NewVaultKeyWrap, VaultKeyWrapInfo};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{OwnerReply, blocking, owner};
use crate::api::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::owner::vault_key::{self as view, PrfInput, SignerPin, VaultKeyReport, secret32};
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/vault-key", get(status))
        .route("/vault-key/signer", get(signer))
        .route("/vault-key/prf-input", get(prf_input))
        .route("/vault-key/unlock", post(unlock))
        .route("/vault-key/password", post(set_password))
        .route("/vault-key/passkeys", post(add_passkey))
        .route("/vault-key/device", post(add_device))
        .route("/vault-key/remove", post(remove))
}

/// `GET /v1/owner/vault-key`: whether the vault has a data key, whether this
/// server holds it, and its wraps, each passkey's with its PRF input.
async fn status(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<VaultKeyReport> {
    owner(&auth, &server)?;
    let report = blocking(move || Ok(view::report(server.vault())?)).await?;
    Ok(Json(report))
}

/// `GET /v1/owner/vault-key/signer`: this install's checkpoint signer, the pin
/// another host trusts this vault's backups by.
async fn signer(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<SignerPin> {
    owner(&auth, &server)?;
    let pin = blocking(move || Ok(SignerPin::from(server.vault().checkpoint_signer()?))).await?;
    Ok(Json(pin))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialQuery {
    /// The passkey's credential name: 1 to 64 letters, digits, dots, dashes
    /// or underscores.
    credential: String,
}

/// `GET /v1/owner/vault-key/prf-input?credential=NAME`: the PRF input a
/// passkey of that name is asked at.
async fn prf_input(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<CredentialQuery>, QueryRejection>,
) -> OwnerReply<PrfInput> {
    owner(&auth, &server)?;
    let query = query_params(query)?;
    let input =
        blocking(move || Ok(view::prf_input(server.vault(), &query.credential)?)).await?;
    Ok(Json(input))
}

/// A secret the vault key unlocks or seals with.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "method")]
enum KeySecret {
    /// The vault password.
    Password { password: String },
    /// A passkey's PRF output at its input: 32 bytes, hex or base64url.
    Passkey { credential: String, prf: String },
}

/// `POST /v1/owner/vault-key/unlock`: holds the vault key on this server, from
/// the password or a passkey's PRF output.
async fn unlock(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<KeySecret>, JsonRejection>,
) -> OwnerReply<VaultKeyReport> {
    owner(&auth, &server)?;
    let secret = json_payload(payload)?;
    let report = blocking(move || -> OwnerResult<VaultKeyReport> {
        let vault = server.vault();
        match secret {
            KeySecret::Password { password } => {
                let password = Zeroizing::new(password);
                vault.unlock_vault_key_with_password(password.as_bytes())?;
            }
            KeySecret::Passkey { credential, prf } => {
                let prf = prf_bytes(prf)?;
                vault.unlock_vault_key_with_passkey(&credential, *prf)?;
            }
        }
        Ok(view::report(vault)?)
    })
    .await?;
    Ok(Json(report))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordRequest {
    password: String,
}

/// `POST /v1/owner/vault-key/password`: sets the vault password, replacing an
/// earlier one.
async fn set_password(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<PasswordRequest>, JsonRejection>,
) -> OwnerReply<VaultKeyWrapInfo> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let info = blocking(move || -> OwnerResult<VaultKeyWrapInfo> {
        let password = Zeroizing::new(request.password);
        let vault = held(server.vault())?;
        Ok(vault.add_vault_key_wrap_as(
            &owner,
            NewVaultKeyWrap::Password {
                password: password.as_bytes(),
                cost: None,
            },
        )?)
    })
    .await?;
    Ok(Json(info))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasskeyRequest {
    credential: String,
    /// The PRF output at `GET /vault-key/prf-input`: 32 bytes, hex or
    /// base64url.
    prf: String,
}

/// `POST /v1/owner/vault-key/passkeys`: wraps the vault key to a passkey by
/// its PRF output.
async fn add_passkey(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<PasskeyRequest>, JsonRejection>,
) -> OwnerReply<VaultKeyWrapInfo> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let info = blocking(move || -> OwnerResult<VaultKeyWrapInfo> {
        let prf = prf_bytes(request.prf)?;
        let vault = held(server.vault())?;
        Ok(vault.add_vault_key_wrap_as(
            &owner,
            NewVaultKeyWrap::Passkey {
                credential: &request.credential,
                prf: *prf,
            },
        )?)
    })
    .await?;
    Ok(Json(info))
}

/// `POST /v1/owner/vault-key/device`: wraps the vault key to this install's
/// keystore.
async fn add_device(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<VaultKeyWrapInfo> {
    let owner = owner(&auth, &server)?;
    let info = blocking(move || -> OwnerResult<VaultKeyWrapInfo> {
        Ok(held(server.vault())?.add_vault_key_wrap_as(&owner, NewVaultKeyWrap::Device)?)
    })
    .await?;
    Ok(Json(info))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoveRequest {
    /// The wrap's id: `password`, `passkey:<name>`, `escrow:<label>` or
    /// `device:<install>`.
    id: String,
}

#[derive(Debug, Serialize)]
struct Removed {
    removed: String,
}

/// `POST /v1/owner/vault-key/remove`: removes one wrap; the last one stays.
async fn remove(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<RemoveRequest>, JsonRejection>,
) -> OwnerReply<Removed> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let removed = blocking(move || -> OwnerResult<Removed> {
        server
            .vault()
            .remove_vault_key_wrap_as(&owner, &request.id)?;
        Ok(Removed {
            removed: request.id,
        })
    })
    .await?;
    Ok(Json(removed))
}

/// The vault, holding its data key: already held, unlocked with this
/// install's device wrap, or minted when the vault has none.
fn held(vault: &oneiron::Vault) -> OwnerResult<&oneiron::Vault> {
    vault.ensure_vault_key().map_err(|error| {
        OwnerError::Refused(format!(
            "the vault key is locked and this install's keystore does not open it ({error}); \
             unlock it first at /v1/owner/vault-key/unlock"
        ))
    })?;
    Ok(vault)
}

fn prf_bytes(prf: String) -> OwnerResult<Zeroizing<[u8; 32]>> {
    let prf = Zeroizing::new(prf);
    secret32(prf.as_bytes(), "a PRF output").map_err(|error| OwnerError::Invalid(error.to_string()))
}
