//! `/v1/owner/owner-passkeys/bind`: the owner's own passkey binds them, as
//! `human`, as the vault's owner (the Oneiron lead 21 Nov 04:5x: "a passkey
//! may sign its own human binding, while the binding itself grants nothing
//! the passkey limits bar"; row PASSKEY-SELF-BIND). Each route passes
//! `owner()` first, so a hosted operator's root acts as nobody (FIX 2222),
//! and an agent never reaches the act at all.
//!
//! On a managed host the passkey's enrolment (`/owner-passkeys/enroll`) is
//! signed by the host's custodial root, and the vault counts no `human`
//! binding that only a key in the host's custody signs, so the enrolment
//! binds no one. Until a binding names them, the owner's owner verbs answer
//! `OWNER_BINDING_REQUIRED`. The browser runs this pair right after the
//! enrolment, with a second assertion of the same passkey, or later with any
//! live passkey the host enrolled for the owner:
//!
//! - `POST .../bind/prepare` takes the passkey's credential id and answers
//!   the binding entry, built here with the passkey as its one signer at
//!   epoch 1 and no signature, and the challenge the passkey's assertion
//!   names. Nothing is bound yet.
//! - `POST .../bind/land` takes the entry back with that assertion. It lands
//!   only once the fold counted it and the owner's binding stands; the reply
//!   is its receipt.
//!
//! A passkey signs this one binding and no other: its own first one, of the
//! owner the host enrolled it for. The binding names the owner for their
//! owner verbs and writes alone; the passkey still re-roots nothing, revokes
//! no other owner key and proves nothing for the owner. Every owner device
//! lists the binding as `bound_by_passkey` in `/owner-signing-keys/changes`. The
//! wire form is the passkey routes': the browser's bytes and the prepared
//! entry base64url, engine keys and entries hex.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use axum::routing::post;
use oneiron::authority::ActAuthority;
use serde::{Deserialize, Serialize};

use super::machine_routes::{act_surface_admitted, revision_hex};
use super::owner_key_enrollment_routes::refusal;
use super::owner_passkey_routes::{assertion_envelope, b64url, to_b64url};
use super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::OwnerResult;
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "post",
                path: "/owner-passkeys/bind/prepare",
                summary: "Builds the owner's `human` binding to their own passkey (`credential_id`, base64url): a live passkey this host enrolled for them that was never bound, while no live binding names them. The passkey is the entry's one signer, at epoch 1. Answers the unsigned `entry` and the `challenge` the passkey's assertion names, both base64url; nothing is bound yet.",
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
                path: "/owner-passkeys/bind/land",
                summary: "Lands a prepared binding (`entry`, base64url, as `/bind/prepare` answered it) with the passkey's assertion over its challenge, made with the user verified (`authenticator_data`, `client_data_json`, `signature`, base64url). Answers the receipt only once the fold counted it and the owner's binding stands; after it the owner's owner verbs pass.",
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
    /// The passkey's credential id (`rawId`), base64url.
    credential_id: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct PrepareReply {
    /// The unsigned binding entry, base64url; hand it back unchanged.
    entry: String,
    /// The challenge the passkey's assertion names, base64url.
    challenge: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct LandRequest {
    /// The unsigned binding as `/bind/prepare` answered it, base64url.
    entry: String,
    /// The assertion's authenticator data, base64url.
    authenticator_data: String,
    /// The assertion's client data JSON, base64url.
    client_data_json: String,
    /// The assertion's DER signature, base64url.
    signature: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct ReceiptReply {
    /// The binding's authority entry, as 64 hex.
    entry: String,
    /// The owner the binding names, as 32 hex.
    owner: String,
    /// The bound passkey's key, compressed SEC1, as hex.
    public_key: String,
    /// The binding's epoch: 1, a passkey's first binding.
    epoch: u64,
}

/// The OpenAPI schema of `POST /v1/owner/owner-passkeys/bind/prepare`'s body: [`PrepareRequest`].
pub(crate) fn prepare_request_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PrepareRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/owner-passkeys/bind/prepare`'s answer: [`PrepareReply`].
pub(crate) fn prepare_reply_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PrepareReply>()
}

/// The OpenAPI schema of `POST /v1/owner/owner-passkeys/bind/land`'s body: [`LandRequest`].
pub(crate) fn land_request_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<LandRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/owner-passkeys/bind/land`'s answer: [`ReceiptReply`].
pub(crate) fn receipt_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ReceiptReply>()
}

/// `POST /v1/owner/owner-passkeys/bind/prepare`: the binding of the owner
/// this request proves to their passkey, built for the passkey to sign.
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
        let credential_id = b64url("credential_id", &body.credential_id)?;
        let authority = ActAuthority::Owner(owner, surface);
        let prepared = server
            .vault()
            .prepare_owner_passkey_binding_as(&authority, &credential_id)
            .map_err(refusal)?;
        Ok(PrepareReply {
            entry: to_b64url(&prepared.entry),
            challenge: to_b64url(&prepared.challenge),
        })
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/owner-passkeys/bind/land`: the prepared binding with the
/// passkey's assertion in place, landed once the fold counted it.
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
        let entry = b64url("entry", &body.entry)?;
        let assertion = assertion_envelope(
            &body.authenticator_data,
            &body.client_data_json,
            &body.signature,
        )?;
        let authority = ActAuthority::Owner(owner, surface);
        let receipt = server
            .vault()
            .land_owner_passkey_binding_as(&authority, &entry, assertion)
            .map_err(refusal)?;
        Ok(ReceiptReply {
            entry: revision_hex(&receipt.entry),
            owner: receipt.owner.to_hex(),
            public_key: oneiron_hex::encode(&receipt.public_key),
            epoch: receipt.epoch,
        })
    })
    .await?;
    Ok(Json(reply))
}
