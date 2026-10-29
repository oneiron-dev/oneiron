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

use std::fmt;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{FromRequest, Query, Request, State};
use axum::http::header;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::world_keys::{EscrowRetirement, NewVaultKeyWrap, VaultKeyWrapInfo};
use serde::de::{DeserializeOwned, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{OwnerReply, blocking, owner};
use crate::api::body_spool::{OwnerJsonBody, invalid_json};
use crate::api::query_params;
use crate::auth::CoreAuth;
use crate::error::ApiError;
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
        .route("/vault-key/retire-escrow", post(retire_escrow))
}

/// `GET /v1/owner/vault-key`: whether the vault has a data key, whether this
/// server holds it, and its wraps, each passkey's with its PRF input.
async fn status(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<VaultKeyReport> {
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
    let input = blocking(move || Ok(view::prf_input(server.vault(), &query.credential)?)).await?;
    Ok(Json(input))
}

/// Secret text a request carries, read straight into a guard that wipes it
/// when it drops (FIX 6334). It neither prints nor serializes.
struct SecretText(Zeroizing<String>);

impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(|text| Self(Zeroizing::new(text)))
    }
}

/// A secret the vault key unlocks or seals with.
enum KeySecret {
    /// The vault password.
    Password { password: SecretText },
    /// A passkey's PRF output at its input: 32 bytes, hex or base64url.
    Passkey { credential: String, prf: SecretText },
}

// The JSON shape stays as the derived internally tagged enum read it (FIX 6670):
// tag `method`, variants `password` and `passkey`, fields `password`,
// `credential` and `prf`, unknown fields refused. The map visitor reads the
// tag and each secret straight into its guard, with no `Content` buffer.
impl<'de> Deserialize<'de> for KeySecret {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(KeySecretVisitor)
    }
}

struct KeySecretVisitor;

impl<'de> Visitor<'de> for KeySecretVisitor {
    type Value = KeySecret;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a vault key secret with method password or passkey")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut method: Option<String> = None;
        let mut password: Option<SecretText> = None;
        let mut credential: Option<String> = None;
        let mut prf: Option<SecretText> = None;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "method" => {
                    if method.is_some() {
                        return Err(serde::de::Error::duplicate_field("method"));
                    }
                    method = Some(map.next_value::<String>()?);
                }
                "password" => {
                    if password.is_some() {
                        return Err(serde::de::Error::duplicate_field("password"));
                    }
                    password = Some(map.next_value::<SecretText>()?);
                }
                "credential" => {
                    if credential.is_some() {
                        return Err(serde::de::Error::duplicate_field("credential"));
                    }
                    credential = Some(map.next_value::<String>()?);
                }
                "prf" => {
                    if prf.is_some() {
                        return Err(serde::de::Error::duplicate_field("prf"));
                    }
                    prf = Some(map.next_value::<SecretText>()?);
                }
                _ => {
                    return Err(serde::de::Error::unknown_field(
                        &key,
                        &["method", "password", "credential", "prf"],
                    ));
                }
            }
        }
        let method = method.ok_or_else(|| serde::de::Error::missing_field("method"))?;
        match method.as_str() {
            "password" => {
                if credential.is_some() {
                    return Err(serde::de::Error::unknown_field(
                        "credential",
                        &["method", "password"],
                    ));
                }
                if prf.is_some() {
                    return Err(serde::de::Error::unknown_field(
                        "prf",
                        &["method", "password"],
                    ));
                }
                let password =
                    password.ok_or_else(|| serde::de::Error::missing_field("password"))?;
                Ok(KeySecret::Password { password })
            }
            "passkey" => {
                if password.is_some() {
                    return Err(serde::de::Error::unknown_field(
                        "password",
                        &["method", "credential", "prf"],
                    ));
                }
                let credential =
                    credential.ok_or_else(|| serde::de::Error::missing_field("credential"))?;
                let prf = prf.ok_or_else(|| serde::de::Error::missing_field("prf"))?;
                Ok(KeySecret::Passkey { credential, prf })
            }
            _ => Err(serde::de::Error::unknown_variant(
                &method,
                &["password", "passkey"],
            )),
        }
    }
}

/// `POST /v1/owner/vault-key/unlock`: holds the vault key on this server, from
/// the password or a passkey's PRF output.
async fn unlock(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    request: Request,
) -> OwnerReply<VaultKeyReport> {
    owner(&auth, &server)?;
    // The body bytes are wiped after parsing (FIX 6670).
    let secret = read_secret_json::<KeySecret>(request).await?;
    let report = blocking(move || -> OwnerResult<VaultKeyReport> {
        let vault = server.vault();
        match secret {
            KeySecret::Password { password } => {
                vault.unlock_vault_key_with_password(password.0.as_bytes())?;
            }
            KeySecret::Passkey { credential, prf } => {
                let prf = prf_bytes(&prf)?;
                vault.unlock_vault_key_with_passkey(&credential, &prf)?;
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
    // Read straight into its guard, as KeySecret's password is (FIX 6670).
    password: SecretText,
}

/// `POST /v1/owner/vault-key/password`: sets the vault password, replacing an
/// earlier one.
async fn set_password(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    request: Request,
) -> OwnerReply<VaultKeyWrapInfo> {
    let owner = owner(&auth, &server)?;
    // The body bytes are wiped after parsing (FIX 6670).
    let request = read_secret_json::<PasswordRequest>(request).await?;
    let info = blocking(move || -> OwnerResult<VaultKeyWrapInfo> {
        let vault = held(server.vault())?;
        Ok(vault.add_vault_key_wrap_as(
            &owner,
            NewVaultKeyWrap::Password {
                password: request.password.0.as_bytes(),
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
    prf: SecretText,
}

/// `POST /v1/owner/vault-key/passkeys`: wraps the vault key to a passkey by
/// its PRF output.
async fn add_passkey(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    request: Request,
) -> OwnerReply<VaultKeyWrapInfo> {
    let owner = owner(&auth, &server)?;
    // The body bytes are wiped after parsing (FIX 6670).
    let request = read_secret_json::<PasskeyRequest>(request).await?;
    let info = blocking(move || -> OwnerResult<VaultKeyWrapInfo> {
        let prf = prf_bytes(&request.prf)?;
        let vault = held(server.vault())?;
        Ok(vault.add_vault_key_wrap_as(
            &owner,
            NewVaultKeyWrap::Passkey {
                credential: &request.credential,
                prf: &prf,
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
    payload: OwnerJsonBody<RemoveRequest>,
) -> OwnerReply<Removed> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetireEscrowRequest {
    /// The released escrow recipient's label.
    label: String,
}

/// `POST /v1/owner/vault-key/retire-escrow`: retires an escrow recipient
/// whose secret was released. The vault drops its wrap and never seals to
/// its label again; the reply is the owner's receipt.
async fn retire_escrow(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<RetireEscrowRequest>,
) -> OwnerReply<EscrowRetirement> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let retired = blocking(move || -> OwnerResult<EscrowRetirement> {
        Ok(server
            .vault()
            .retire_vault_key_escrow_as(&owner, &request.label)?)
    })
    .await?;
    Ok(Json(retired))
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

fn prf_bytes(prf: &SecretText) -> OwnerResult<Zeroizing<[u8; 32]>> {
    secret32(prf.0.as_bytes(), "a PRF output")
        .map_err(|error| OwnerError::Invalid(error.to_string()))
}

/// Whether the request names JSON exactly as Axum's `Json` judges it (FIX 6670):
/// copied from `OwnerJsonBody`, so secret routes judge as before.
async fn secret_json_content_type(content_type: Option<&header::HeaderValue>) -> bool {
    let mut probe = Request::new(Body::empty());
    if let Some(content_type) = content_type {
        probe
            .headers_mut()
            .insert(header::CONTENT_TYPE, content_type.clone());
    }
    !matches!(
        axum::Json::<IgnoredAny>::from_request(probe, &()).await,
        Err(JsonRejection::MissingJsonContentType(_))
    )
}

/// The body as `T`, its bytes wiped after parsing (FIX 6670): the body's own
/// buffer becomes a `Zeroizing` vector, wiped as it drops after `from_slice`.
/// Its size never refuses it, as for every owner body (FIX 8195).
async fn read_secret_json<T: DeserializeOwned>(request: Request) -> Result<T, ApiError> {
    let (parts, body) = request.into_parts();
    if !secret_json_content_type(parts.headers.get(header::CONTENT_TYPE)).await {
        return Err(invalid_json());
    }
    let bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|_| invalid_json())?;
    // The collected body is uniquely held, so this takes its allocation
    // rather than copying it.
    let wiped = Zeroizing::new(Vec::<u8>::from(bytes));
    serde_json::from_slice(&wiped).map_err(|_| invalid_json())
}
