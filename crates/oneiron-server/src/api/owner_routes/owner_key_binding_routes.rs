//! `/v1/owner/owner-signing-keys/bind`: the owner's device binds them, as
//! `human`, to the owner key it enrolled, and signs that binding with the
//! key (lead ruling HOSTED-RELAY-OWNER-HUMAN-BIND-CEREMONY = B). Each route
//! passes `owner()` first, so a hosted operator's root acts as nobody (FIX
//! 2222), and an agent never reaches the act at all.
//!
//! On a managed host the enrolment's predecessor is the host's custodial
//! root, and the vault counts no `human` binding that only a key in the
//! host's custody signs, so an enrolment there binds no one; a relay vault
//! holds no root. Until a binding names them, the owner's owner verbs answer
//! `OWNER_BINDING_REQUIRED`. The device runs this pair right after
//! `/owner-signing-keys/enroll`, or later with any owner device key of
//! theirs that is live:
//!
//! - `POST .../bind/prepare` takes the key and answers the binding entry,
//!   built here with the key as its one signer and no signature, and the
//!   transcript the key signs. Nothing is bound yet.
//! - `POST .../bind/land` takes the entry back with the key's Ed25519
//!   signature over that transcript. It lands only once the fold counted it
//!   and the owner's binding stands; the reply is its receipt.
//!
//! Neither route needs a root this host holds: the key signs the binding
//! itself. Only an Ed25519 owner device key that a counted enrolment names
//! this owner for binds; a passkey signs no binding. The wire form is the
//! owner key routes': a key, an entry, a transcript and a signature as
//! lower-case hex.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use axum::routing::post;
use oneiron::authority::ActAuthority;
use serde::{Deserialize, Serialize};

use super::machine_routes::{act_surface_admitted, parse_revision, revision_hex};
use super::owner_key_enrollment_routes::refusal;
use super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "post",
                path: "/owner-signing-keys/bind/prepare",
                summary: "Builds the owner's `human` binding to an owner device key of theirs (`public_key`, 64 hex): a live Ed25519 key a counted enrollment names them for, while no live binding names them. The key is the entry's one signer. Answers the unsigned `entry` and the `transcript` the key signs, both hex; nothing is bound yet.",
                row: None,
                shape: Some(RestShape::json(
                    prepare_request_body_schema,
                    prepare_reply_schema,
                )),
            },
            post(prepare),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/owner-signing-keys/bind/land",
                summary: "Lands a prepared binding (`entry`, hex, as `/bind/prepare` answered it) with the key's Ed25519 signature over its transcript (`signature`, 128 hex). Answers the receipt only once the fold counted it and the owner's binding stands; after it the owner's owner verbs pass.",
                row: None,
                shape: Some(RestShape::json(land_request_body_schema, receipt_schema)),
            },
            post(land),
        ),
    ]
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct PrepareRequest {
    /// The owner device key to bind, as 64 lower-case hex.
    public_key: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct PrepareReply {
    /// The unsigned binding entry, canonical MessagePack, as lower-case hex.
    entry: String,
    /// The bytes the key signs with Ed25519, as lower-case hex.
    transcript: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct LandRequest {
    /// The entry exactly as `/bind/prepare` answered it.
    entry: String,
    /// The key's signature over the transcript, as 128 lower-case hex.
    signature: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct ReceiptReply {
    /// The binding's authority entry, as 64 hex.
    entry: String,
    /// The owner the binding names, as 32 hex.
    owner: String,
    /// The bound key, as 64 hex.
    public_key: String,
    /// The binding's epoch.
    epoch: u64,
}

/// The OpenAPI schema of `POST /v1/owner/owner-signing-keys/bind/prepare`'s body: [`PrepareRequest`].
pub(crate) fn prepare_request_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PrepareRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/owner-signing-keys/bind/prepare`'s answer: [`PrepareReply`].
pub(crate) fn prepare_reply_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PrepareReply>()
}

/// The OpenAPI schema of `POST /v1/owner/owner-signing-keys/bind/land`'s body: [`LandRequest`].
pub(crate) fn land_request_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<LandRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/owner-signing-keys/bind/land`'s answer: [`ReceiptReply`].
pub(crate) fn receipt_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ReceiptReply>()
}

/// A prepared entry as the client sent it back: lower-case hex.
fn parse_entry(value: &str) -> OwnerResult<Vec<u8>> {
    oneiron_hex::decode_vec(value).ok_or_else(|| {
        OwnerError::Invalid(
            "entry must be lower-case hex, exactly as /bind/prepare answered it".to_owned(),
        )
    })
}

/// The key's signature as the client sent it: one raw Ed25519 signature, 128
/// lower-case hex.
fn parse_signature(value: &str) -> OwnerResult<Vec<u8>> {
    oneiron_hex::decode::<64>(value)
        .map(|signature| signature.to_vec())
        .ok_or_else(|| {
            OwnerError::Invalid(
                "signature must be 128 lower-case hex: the key's signature over the binding's \
                 transcript"
                    .to_owned(),
            )
        })
}

/// `POST /v1/owner/owner-signing-keys/bind/prepare`: the binding of the owner
/// this request proves to the key, built for the key to sign.
async fn prepare(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<PrepareRequest>,
) -> OwnerReply<PrepareReply> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let body = payload.read(&server).await?;
    let reply = blocking(move || -> OwnerResult<PrepareReply> {
        let public_key = parse_revision("public_key", &body.public_key)?;
        let authority = ActAuthority::Owner(owner, surface);
        let prepared = server
            .vault()
            .prepare_owner_key_binding_as(&authority, public_key)
            .map_err(refusal)?;
        Ok(PrepareReply {
            entry: oneiron_hex::encode(&prepared.entry),
            transcript: oneiron_hex::encode(&prepared.transcript),
        })
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/owner-signing-keys/bind/land`: the prepared binding with
/// the key's signature in place, landed once the fold counted it.
async fn land(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<LandRequest>,
) -> OwnerReply<ReceiptReply> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let body = payload.read(&server).await?;
    let reply = blocking(move || -> OwnerResult<ReceiptReply> {
        let entry = parse_entry(&body.entry)?;
        let signature = parse_signature(&body.signature)?;
        let authority = ActAuthority::Owner(owner, surface);
        let receipt = server
            .vault()
            .land_owner_key_binding_as(&authority, &entry, signature)
            .map_err(refusal)?;
        Ok(ReceiptReply {
            entry: revision_hex(&receipt.entry),
            owner: receipt.owner.to_hex(),
            public_key: revision_hex(&receipt.public_key),
            epoch: receipt.epoch,
        })
    })
    .await?;
    Ok(Json(reply))
}
