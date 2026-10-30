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

use super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner};
use crate::api::body_spool::{OwnerJsonBody, invalid_json};
use crate::api::query_params;
use crate::auth::CoreAuth;
use crate::error::ApiError;
use crate::owner::vault_key::{self as view, PrfInput, SignerPin, VaultKeyReport, secret32};
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/vault-key",
                summary: "Whether the vault has a data key, whether this server holds it, and its wraps, each passkey's with its PRF input.",
                row: None,
                shape: None,
            },
            get(status),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/vault-key/signer",
                summary: "This install's checkpoint signer, the pin another host trusts this vault's backups by.",
                row: None,
                shape: None,
            },
            get(signer),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/vault-key/prf-input",
                summary: "The PRF input a passkey of that name is asked at.",
                row: None,
                shape: None,
            },
            get(prf_input),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/vault-key/unlock",
                summary: "Holds the vault key on this server, from the password or a passkey's PRF output.",
                row: None,
                shape: Some(RestShape::json(unlock_body_schema, vault_key_report_schema)),
            },
            post(unlock),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/vault-key/password",
                summary: "Sets the vault password, replacing an earlier one.",
                row: None,
                shape: Some(RestShape::json(
                    set_password_body_schema,
                    vault_key_wrap_info_schema,
                )),
            },
            post(set_password),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/vault-key/passkeys",
                summary: "Wraps the vault key to a passkey by its PRF output.",
                row: None,
                shape: Some(RestShape::json(
                    add_passkey_body_schema,
                    vault_key_wrap_info_schema,
                )),
            },
            post(add_passkey),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/vault-key/device",
                summary: "Wraps the vault key to this install's keystore.",
                row: None,
                shape: Some(RestShape::no_body(vault_key_wrap_info_schema)),
            },
            post(add_device),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/vault-key/remove",
                summary: "Removes one wrap; the last one stays.",
                row: None,
                shape: Some(RestShape::json(
                    remove_wrap_body_schema,
                    wrap_removed_schema,
                )),
            },
            post(remove),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/vault-key/retire-escrow",
                summary: "Retires an escrow recipient whose secret was released.",
                row: None,
                shape: Some(RestShape::json(
                    retire_escrow_body_schema,
                    escrow_retirement_schema,
                )),
            },
            post(retire_escrow),
        ),
    ]
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

/// The wire form is the secret's text.
impl schemars::JsonSchema for SecretText {
    fn schema_name() -> String {
        "SecretText".to_owned()
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        <String as schemars::JsonSchema>::json_schema(generator)
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

/// [`KeySecret`]'s wire shape (FIX 11653 route (b)): the tag `method` with
/// the `password` and `passkey` variants the map visitor reads, unknown
/// fields refused. Never used at runtime.
#[derive(schemars::JsonSchema)]
#[schemars(rename = "KeySecret")]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
#[expect(dead_code, reason = "schema mirror of KeySecret's wire shape")]
enum KeySecretSchema {
    Password { password: String },
    Passkey { credential: String, prf: String },
}

/// The wire form is the internally tagged enum [`KeySecretSchema`] states.
impl schemars::JsonSchema for KeySecret {
    fn schema_name() -> String {
        "KeySecret".to_owned()
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        <KeySecretSchema as schemars::JsonSchema>::json_schema(generator)
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

#[derive(Deserialize, schemars::JsonSchema)]
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

#[derive(Deserialize, schemars::JsonSchema)]
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

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct RemoveRequest {
    /// The wrap's id: `password`, `passkey:<name>`, `escrow:<label>` or
    /// `device:<install>`.
    id: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
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

#[derive(Debug, Deserialize, schemars::JsonSchema)]
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

/// The OpenAPI schema of `POST /v1/owner/vault-key/remove`'s body (FIX 11611):
/// [`RemoveRequest`].
pub(crate) fn remove_wrap_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<RemoveRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/vault-key/remove`'s answer
/// (FIX 11611): [`Removed`].
pub(crate) fn wrap_removed_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<Removed>()
}

/// The OpenAPI schema of `POST /v1/owner/vault-key/retire-escrow`'s body
/// (FIX 11611): [`RetireEscrowRequest`].
pub(crate) fn retire_escrow_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<RetireEscrowRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/vault-key/retire-escrow`'s answer
/// (FIX 11611): [`EscrowRetirement`].
pub(crate) fn escrow_retirement_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<EscrowRetirement>()
}

/// The OpenAPI schema of `POST /v1/owner/vault-key/unlock`'s body
/// (FIX 11611): [`KeySecret`].
pub(crate) fn unlock_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<KeySecret>()
}

/// The OpenAPI schema of `POST /v1/owner/vault-key/unlock`'s answer
/// (FIX 11611): [`VaultKeyReport`].
pub(crate) fn vault_key_report_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<VaultKeyReport>()
}

/// The OpenAPI schema of `POST /v1/owner/vault-key/password`'s body
/// (FIX 11611): [`PasswordRequest`].
pub(crate) fn set_password_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PasswordRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/vault-key/passkeys`'s body
/// (FIX 11611): [`PasskeyRequest`].
pub(crate) fn add_passkey_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PasskeyRequest>()
}

/// The OpenAPI schema of the vault-key wrap answers (FIX 11611): one wrap's
/// public facts as [`VaultKeyWrapInfo`] reads on the wire: its id, its kind
/// and when it was added. Hand-built: `oneiron-crypto` has no schemars
/// dependency, so the kind is [`view::VaultKeyWrapKindSchema`]'s schema
/// (FIX 11653 route (b)).
pub(crate) fn vault_key_wrap_info_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "required": ["created_at", "id", "kind"],
        "properties": {
            "created_at": {"type": "integer", "format": "uint64", "minimum": 0.0},
            "id": {"type": "string"},
            "kind": oneiron_contracts::code_run::vault_read::request_schema::<
                view::VaultKeyWrapKindSchema,
            >(),
        },
    })
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
