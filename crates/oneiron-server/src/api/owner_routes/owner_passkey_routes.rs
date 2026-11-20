//! `/v1/owner/owner-passkeys`: the owner's browser passkey as an owner key of
//! the vault (row WEB-PASSKEY-OWNER-KEY; lead ruling CARRIER-HOSTED-WEB-ACTS
//! = C, Engine ruling WAYBACK-E4 shape (b)). The browser runs the WebAuthn
//! ceremonies; the passkey's key never leaves its authenticator, and each
//! signature is one assertion the person makes there. Each route passes
//! `owner()` first, so a hosted operator's root acts as nobody (FIX 2222),
//! and an agent never reaches the act at all.
//!
//! - `GET` lists every enrolled passkey: its key, its credential id, the
//!   carrier that served its ceremony, whether it is live.
//! - `POST .../challenge` answers the challenge a new passkey's assertion
//!   names to enrol, for the key `navigator.credentials.create` returned.
//! - `POST .../enroll` takes that key, the credential id and the assertion.
//!   This install carries and cosigns the act; this host's root signs it as
//!   the predecessor, as `/owner-signing-keys/enroll` does for a device key.
//! - `POST .../vouch/prepare` builds the enrollment of a new device's key
//!   (as `/owner-signing-keys/enroll` takes it) with an enrolled passkey,
//!   named by its credential id, as the predecessor, and answers the entry
//!   and the challenge the passkey's assertion names.
//! - `POST .../vouch/land` takes the entry back with that assertion; this
//!   install cosigns it and it lands only once the fold counted it. The key
//!   a passkey vouched for acts in part until an owner key that is no
//!   passkey (a device key, the recovery kit's authority key) confirms it
//!   (lead ruling WEBPASSKEY-BLIND-SIGNATURE = B): it re-roots nothing,
//!   revokes no other owner key and vouches for no further key. That
//!   confirmation is the confirming key's own act, outside these routes.
//!
//! Bytes the browser hands over (credential id, SubjectPublicKeyInfo,
//! authenticator data, client data JSON, DER signature, the prepared entry)
//! are base64url, as WebAuthn's JSON forms spell them; engine keys and
//! entries are hex, as the other owner key routes spell them.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use axum::routing::{get, post};
use base64::Engine as _;
use oneiron::authority::{
    ActAuthority, AuthorityKey, EnrolledOwnerPasskey, OwnerKeyEnrollment, OwnerPasskeyEnrollment,
    webauthn_assertion_envelope, webauthn_es256_public_key,
};
use serde::{Deserialize, Serialize};

use super::machine_routes::{act_surface_admitted, parse_revision, revision_hex};
use super::owner_key_enrollment_routes::{no_root_signer, parse_proof, refusal};
use super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/owner-passkeys",
                summary: "Every passkey enrolled as an owner key (row WEB-PASSKEY-OWNER-KEY), ascending by key: its enrollment entry, its key (hex, compressed SEC1), its credential id (base64url), the carrier that served its ceremony, the owner, whether it is live. Empty before any passkey enrollment.",
                row: None,
                shape: None,
            },
            get(list),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/owner-passkeys/challenge",
                summary: "The challenge a new passkey's assertion names to enrol as an owner key (`public_key`, base64url: the SubjectPublicKeyInfo `getPublicKey()` returned): over the vault, this install, the key and the owner this request proves. Answers `challenge` as base64url.",
                row: None,
                shape: Some(RestShape::json(
                    challenge_request_body_schema,
                    challenge_reply_schema,
                )),
            },
            post(challenge),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/owner-passkeys/enroll",
                summary: "The owner enrols his passkey as an owner key (`credential_id`, `public_key`, `authenticator_data`, `client_data_json`, `signature`, all base64url: the credential and its assertion over the challenge). This install carries and cosigns the act, this host's root signs it as the predecessor; answers the receipt only once the fold counted it.",
                row: None,
                shape: Some(RestShape::json(
                    enroll_request_body_schema,
                    enroll_receipt_schema,
                )),
            },
            post(enroll),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/owner-passkeys/vouch/prepare",
                summary: "Builds the enrollment of a new device's owner key (`machine`, 32 hex; `public_key`, 64 hex; `proof`, 128 hex) with the enrolled passkey `credential_id` (base64url) as its predecessor. Answers the unsigned `entry` and the `challenge` the passkey's assertion names, both base64url; nothing is enrolled yet.",
                row: None,
                shape: Some(RestShape::json(
                    vouch_prepare_request_body_schema,
                    vouch_prepare_reply_schema,
                )),
            },
            post(vouch_prepare),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/owner-passkeys/vouch/land",
                summary: "Lands a prepared enrollment (`entry`, base64url, as `/vouch/prepare` answered it) with the passkey's assertion over its challenge (`authenticator_data`, `client_data_json`, `signature`, base64url). This install cosigns it; answers the receipt only once the fold counted it.",
                row: None,
                shape: Some(RestShape::json(
                    vouch_land_request_body_schema,
                    vouch_land_receipt_schema,
                )),
            },
            post(vouch_land),
        ),
    ]
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ChallengeRequest {
    /// The credential's public key as `getPublicKey()` returns it
    /// (SubjectPublicKeyInfo DER), base64url.
    public_key: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct ChallengeReply {
    /// The challenge the assertion names, base64url.
    challenge: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct EnrollRequest {
    /// The credential's id (`rawId`), base64url.
    credential_id: String,
    /// As for the challenge.
    public_key: String,
    /// The assertion's authenticator data, base64url.
    authenticator_data: String,
    /// The assertion's client data JSON, base64url.
    client_data_json: String,
    /// The assertion's DER signature, base64url.
    signature: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct EnrollReceipt {
    /// The enrollment's authority entry, as 64 hex.
    entry: String,
    /// The carrier that served the ceremony, as 32 hex.
    machine: String,
    /// The passkey's key, compressed SEC1, as hex.
    public_key: String,
    /// The passkey's credential id, base64url.
    credential_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct VouchPrepareRequest {
    /// The machine that holds the new device key, as 32 hex.
    machine: String,
    /// The new device key, as 64 lower-case hex.
    public_key: String,
    /// The new key's signature over its challenge, as 128 lower-case hex.
    proof: String,
    /// The enrolled passkey that vouches, by its credential id, base64url.
    credential_id: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct VouchPrepareReply {
    /// The unsigned enrollment, base64url; hand it back unchanged.
    entry: String,
    /// The challenge the passkey's assertion names, base64url.
    challenge: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct VouchLandRequest {
    /// The unsigned enrollment as `/vouch/prepare` answered it, base64url.
    entry: String,
    /// The assertion's authenticator data, base64url.
    authenticator_data: String,
    /// The assertion's client data JSON, base64url.
    client_data_json: String,
    /// The assertion's DER signature, base64url.
    signature: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct VouchLandReceipt {
    /// The enrollment's authority entry, as 64 hex.
    entry: String,
    /// The machine that holds the new device key, as 32 hex.
    machine: String,
    /// The new device key, as 64 hex.
    public_key: String,
}

#[derive(Debug, Serialize)]
struct PasskeyReply {
    /// The enrollment's authority entry, as 64 hex.
    entry: String,
    /// The carrier that served its ceremony, as 32 hex.
    machine: String,
    /// The owner whose act enrolled it, as 32 hex.
    owner: String,
    /// The passkey's key, compressed SEC1, as hex.
    public_key: String,
    /// The passkey's credential id, base64url.
    credential_id: String,
    /// On the roster and not revoked.
    live: bool,
    /// When it was signed, advisory unix seconds.
    at: u64,
}

#[derive(Debug, Serialize)]
struct ListReply {
    /// Ascending by key; empty before any passkey enrollment.
    passkeys: Vec<PasskeyReply>,
}

/// The OpenAPI schema of `POST /v1/owner/owner-passkeys/challenge`'s body: [`ChallengeRequest`].
pub(crate) fn challenge_request_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ChallengeRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/owner-passkeys/challenge`'s answer: [`ChallengeReply`].
pub(crate) fn challenge_reply_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ChallengeReply>()
}

/// The OpenAPI schema of `POST /v1/owner/owner-passkeys/enroll`'s body: [`EnrollRequest`].
pub(crate) fn enroll_request_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<EnrollRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/owner-passkeys/enroll`'s answer: [`EnrollReceipt`].
pub(crate) fn enroll_receipt_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<EnrollReceipt>()
}

/// The OpenAPI schema of `POST /v1/owner/owner-passkeys/vouch/prepare`'s body: [`VouchPrepareRequest`].
pub(crate) fn vouch_prepare_request_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<VouchPrepareRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/owner-passkeys/vouch/prepare`'s answer: [`VouchPrepareReply`].
pub(crate) fn vouch_prepare_reply_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<VouchPrepareReply>()
}

/// The OpenAPI schema of `POST /v1/owner/owner-passkeys/vouch/land`'s body: [`VouchLandRequest`].
pub(crate) fn vouch_land_request_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<VouchLandRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/owner-passkeys/vouch/land`'s answer: [`VouchLandReceipt`].
pub(crate) fn vouch_land_receipt_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<VouchLandReceipt>()
}

/// Bytes the browser spelled as base64url, padded or not.
fn b64url(field: &str, value: &str) -> OwnerResult<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value.trim_end_matches('='))
        .map_err(|_| OwnerError::Invalid(format!("{field} must be base64url")))
}

fn to_b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The credential's key from its SubjectPublicKeyInfo, as SEC1.
fn passkey_key(value: &str) -> OwnerResult<Vec<u8>> {
    webauthn_es256_public_key(&b64url("public_key", value)?).map_err(|_| {
        OwnerError::Invalid(
            "public_key must be the SubjectPublicKeyInfo of an ES256 (P-256) credential".to_owned(),
        )
    })
}

/// The predecessor signature a passkey's assertion makes: its envelope.
fn assertion_envelope(
    authenticator_data: &str,
    client_data_json: &str,
    signature: &str,
) -> OwnerResult<Vec<u8>> {
    webauthn_assertion_envelope(
        &b64url("authenticator_data", authenticator_data)?,
        &b64url("client_data_json", client_data_json)?,
        &b64url("signature", signature)?,
    )
    .map_err(|_| {
        OwnerError::Invalid(
            "the assertion must carry authenticator data, client data JSON and a DER ES256 \
             signature within their bounds"
                .to_owned(),
        )
    })
}

fn passkey_reply(passkey: &EnrolledOwnerPasskey) -> PasskeyReply {
    PasskeyReply {
        entry: revision_hex(&passkey.entry),
        machine: passkey.machine.to_hex(),
        owner: passkey.owner.to_hex(),
        public_key: oneiron_hex::encode(&passkey.public_key),
        credential_id: to_b64url(&passkey.credential_id),
        live: passkey.live,
        at: passkey.at,
    }
}

/// `GET /v1/owner/owner-passkeys`: every enrolled passkey, ascending by key,
/// a revoked one included.
async fn list(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<ListReply> {
    owner(&auth, &server)?;
    let reply = blocking(move || -> OwnerResult<ListReply> {
        let passkeys = server.vault().enrolled_owner_passkeys()?;
        Ok(ListReply {
            passkeys: passkeys.iter().map(passkey_reply).collect(),
        })
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/owner-passkeys/challenge`: the challenge a new passkey's
/// assertion names to enrol for the owner this request proves.
async fn challenge(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<ChallengeRequest>,
) -> OwnerReply<ChallengeReply> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let body = payload.read(&server).await?;
    let reply = blocking(move || -> OwnerResult<ChallengeReply> {
        let public_key = passkey_key(&body.public_key)?;
        let authority = ActAuthority::Owner(owner, surface);
        let challenge = server
            .vault()
            .owner_passkey_enrollment_challenge_as(&authority, &public_key)
            .map_err(refusal)?;
        Ok(ChallengeReply {
            challenge: to_b64url(&challenge),
        })
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/owner-passkeys/enroll`: the owner enrols his passkey,
/// carried by this install, with this host's root as its predecessor.
async fn enroll(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<EnrollRequest>,
) -> OwnerReply<EnrollReceipt> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let body = payload.read(&server).await?;
    let reply = blocking(move || -> OwnerResult<EnrollReceipt> {
        let input = OwnerPasskeyEnrollment {
            credential_id: b64url("credential_id", &body.credential_id)?,
            public_key: passkey_key(&body.public_key)?,
            authenticator_data: b64url("authenticator_data", &body.authenticator_data)?,
            client_data_json: b64url("client_data_json", &body.client_data_json)?,
            signature: b64url("signature", &body.signature)?,
        };
        let authority = ActAuthority::Owner(owner, surface);
        let issuer = server.host_issuer().ok_or_else(no_root_signer)?;
        let receipt = server
            .vault()
            .enrol_owner_passkey_as_host(&authority, &input, issuer)
            .map_err(refusal)?;
        Ok(EnrollReceipt {
            entry: revision_hex(&receipt.entry),
            machine: receipt.machine.to_hex(),
            public_key: oneiron_hex::encode(&receipt.public_key),
            credential_id: to_b64url(&receipt.credential_id),
        })
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/owner-passkeys/vouch/prepare`: the enrollment of a new
/// device's key with an enrolled passkey as its predecessor, unsigned, and
/// the challenge the passkey's assertion names.
async fn vouch_prepare(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<VouchPrepareRequest>,
) -> OwnerReply<VouchPrepareReply> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let body = payload.read(&server).await?;
    let reply = blocking(move || -> OwnerResult<VouchPrepareReply> {
        let input = OwnerKeyEnrollment {
            machine: entity_id("machine", &body.machine)?,
            public_key: parse_revision("public_key", &body.public_key)?,
            proof: parse_proof(&body.proof)?,
        };
        let credential_id = b64url("credential_id", &body.credential_id)?;
        let passkey = server
            .vault()
            .enrolled_owner_passkeys()?
            .into_iter()
            .find(|passkey| passkey.live && passkey.credential_id == credential_id)
            .ok_or_else(|| {
                OwnerError::Refused(
                    "no live passkey of this vault has that credential id".to_owned(),
                )
            })?;
        let authority = ActAuthority::Owner(owner, surface);
        let prepared = server
            .vault()
            .prepare_owner_key_enrollment_as(
                &authority,
                input,
                AuthorityKey::P256(passkey.public_key),
            )
            .map_err(refusal)?;
        Ok(VouchPrepareReply {
            entry: to_b64url(&prepared.entry),
            challenge: to_b64url(&prepared.challenge),
        })
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/owner-passkeys/vouch/land`: the prepared enrollment with
/// the passkey's assertion, cosigned by this install and counted.
async fn vouch_land(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<VouchLandRequest>,
) -> OwnerReply<VouchLandReceipt> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let body = payload.read(&server).await?;
    let reply = blocking(move || -> OwnerResult<VouchLandReceipt> {
        let entry = b64url("entry", &body.entry)?;
        let signature = assertion_envelope(
            &body.authenticator_data,
            &body.client_data_json,
            &body.signature,
        )?;
        let authority = ActAuthority::Owner(owner, surface);
        let receipt = server
            .vault()
            .land_owner_key_enrollment_as(&authority, &entry, signature)
            .map_err(refusal)?;
        Ok(VouchLandReceipt {
            entry: revision_hex(&receipt.entry),
            machine: receipt.machine.to_hex(),
            public_key: revision_hex(&receipt.public_key),
        })
    })
    .await?;
    Ok(Json(reply))
}
