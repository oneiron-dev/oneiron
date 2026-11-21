//! `/v1/owner/recovery-holds` and the passkey's Cancel of a recovery hold
//! (row RECOVERY-HOLD-PASSKEY-CANCEL-ROUTE): the owner reads every recovery
//! hold this install's log holds, the "recovery started, lands at <time>,
//! cancel?" list, and an owner whose only live owner key is a browser
//! passkey stops a box recovery's attempt from the browser. Each route
//! passes `owner()` first, so a hosted operator's root acts as nobody (FIX
//! 2222), and an agent never reaches the act at all.
//!
//! - `GET /recovery-holds` lists each hold with its state on this install's
//!   clock, as `Vault::recovery_holds` judges it from the counted log.
//! - `POST /owner-passkeys/recovery-hold-cancel/prepare` takes the hold and
//!   the passkey's credential id, and answers the Cancel entry, built here
//!   with the passkey as its one signer and no signature, and the challenge
//!   the passkey's assertion names. Nothing is cancelled yet.
//! - `POST /owner-passkeys/recovery-hold-cancel/land` takes the entry back
//!   with that assertion. It lands only once the fold counted it; the hold
//!   is then Cancelled and never lands.
//!
//! Any owner of the vault may cancel any live hold
//! (WAYBACK-COOWNER-CANCEL-OTHER-OWNERS-RECOVERY = B). A passkey answers a
//! hold with a Cancel alone: an `ItIsMe` lands the hold's revocations of
//! the owner's other keys at once, and a passkey revokes no other owner key
//! (WEBPASSKEY-PASSKEY-OWN-REVOKE = B). The wire form is the passkey
//! routes': the browser's bytes and the prepared entry base64url, engine
//! keys and entries hex.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::authority::{ActAuthority, AuthorityKey, RecoveryHoldState, RecoveryHoldView};
use serde::{Deserialize, Serialize};

use super::machine_routes::{act_surface_admitted, parse_revision, revision_hex};
use super::owner_key_enrollment_routes::{authority_key_hex, refusal};
use super::owner_passkey_routes::{assertion_envelope, b64url, to_b64url};
use super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/recovery-holds",
                summary: "Every recovery hold this install's log holds (row RECOVERY-HOLD-PASSKEY-CANCEL-ROUTE): the attempt (`hold`, 64 hex), whose recovery it is, the successor machine and key it enrols, the lost keys it revokes, `lands_at` (unix seconds), its `state` on this install's clock (`waiting`, `due`, `landed`, `cancelled` or `void`) and who cancelled it. Landed first, then cancelled, void, and the live ones; empty before any hold.",
                row: None,
                shape: None,
            },
            get(list),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/owner-passkeys/recovery-hold-cancel/prepare",
                summary: "Builds the Cancel of the live recovery hold `hold` (64 hex) that the owner's live passkey `credential_id` (base64url) signs alone; any owner of the vault may cancel any live hold. Answers the unsigned `entry` and the `challenge` the passkey's assertion names, both base64url; nothing is cancelled yet.",
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
                path: "/owner-passkeys/recovery-hold-cancel/land",
                summary: "Lands a prepared Cancel (`entry`, base64url, as `/recovery-hold-cancel/prepare` answered it) with the passkey's assertion over its challenge, made with the user verified (`authenticator_data`, `client_data_json`, `signature`, base64url). Answers the Cancel's `entry` (64 hex) only once the fold counted it; the hold is then cancelled and never lands.",
                row: None,
                shape: Some(RestShape::json(land_request_body_schema, receipt_schema)),
            },
            post(land),
        ),
    ]
}

#[derive(Debug, Serialize)]
struct HoldReply {
    /// The hold's entry hash, the attempt id, as 64 hex.
    hold: String,
    /// The owner whose recovery this is, as 32 hex.
    owner: String,
    /// The machine that holds the successor key, as 32 hex.
    successor_machine: String,
    /// The successor key the landing enrols, as hex.
    successor_key: String,
    /// The lost keys the landing revokes, as hex.
    lost: Vec<String>,
    /// Unix seconds the wait ends at, on the door install's clock.
    lands_at: u64,
    /// `waiting`, `due`, `landed`, `cancelled` or `void`.
    state: &'static str,
    /// Who stopped the attempt, as 32 hex each; empty unless cancelled.
    cancelled_by: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ListReply {
    /// Landed, then cancelled, void, and the live ones; within each by
    /// `lands_at`. Empty before any hold.
    holds: Vec<HoldReply>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct PrepareRequest {
    /// The live hold to cancel, as 64 hex.
    hold: String,
    /// The owner's live passkey that signs the Cancel, by its credential id
    /// (`rawId`), base64url.
    credential_id: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct PrepareReply {
    /// The unsigned Cancel entry, base64url; hand it back unchanged.
    entry: String,
    /// The challenge the passkey's assertion names, base64url.
    challenge: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct LandRequest {
    /// The unsigned Cancel as `/recovery-hold-cancel/prepare` answered it,
    /// base64url.
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
    /// The Cancel's authority entry, as 64 hex.
    entry: String,
}

/// The OpenAPI schema of `POST /v1/owner/owner-passkeys/recovery-hold-cancel/prepare`'s body: [`PrepareRequest`].
pub(crate) fn prepare_request_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PrepareRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/owner-passkeys/recovery-hold-cancel/prepare`'s answer: [`PrepareReply`].
pub(crate) fn prepare_reply_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PrepareReply>()
}

/// The OpenAPI schema of `POST /v1/owner/owner-passkeys/recovery-hold-cancel/land`'s body: [`LandRequest`].
pub(crate) fn land_request_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<LandRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/owner-passkeys/recovery-hold-cancel/land`'s answer: [`ReceiptReply`].
pub(crate) fn receipt_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ReceiptReply>()
}

fn state_name(state: RecoveryHoldState) -> &'static str {
    match state {
        RecoveryHoldState::Waiting => "waiting",
        RecoveryHoldState::Due => "due",
        RecoveryHoldState::Landed => "landed",
        RecoveryHoldState::Cancelled => "cancelled",
        RecoveryHoldState::Void => "void",
    }
}

fn hold_reply(view: &RecoveryHoldView) -> HoldReply {
    HoldReply {
        hold: revision_hex(&view.hold),
        owner: view.owner.to_hex(),
        successor_machine: view.successor_machine.to_hex(),
        successor_key: authority_key_hex(&view.successor_key),
        lost: view.lost.iter().map(authority_key_hex).collect(),
        lands_at: view.lands_at,
        state: state_name(view.state),
        cancelled_by: view
            .cancelled_by
            .iter()
            .map(oneiron::EntityId::to_hex)
            .collect(),
    }
}

/// `GET /v1/owner/recovery-holds`: every recovery hold this install's log
/// holds, with its state on this install's clock.
async fn list(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<ListReply> {
    owner(&auth, &server)?;
    let reply = blocking(move || -> OwnerResult<ListReply> {
        let holds = server.vault().recovery_holds()?;
        Ok(ListReply {
            holds: holds.iter().map(hold_reply).collect(),
        })
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/owner-passkeys/recovery-hold-cancel/prepare`: the Cancel
/// of a live hold, built for the owner's passkey to sign alone.
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
        let hold = parse_revision("hold", &body.hold)?;
        let credential_id = b64url("credential_id", &body.credential_id)?;
        // A credential id names no key across owners: enrolment takes the
        // one the browser posts, so another owner's live passkey may carry
        // the same id. The acting owner's own is the one that signs (as the
        // binding door picks it); the door revalidates the owner when it
        // acts.
        let actor = owner.actor_for_read(server.vault())?;
        let passkey = server
            .vault()
            .enrolled_owner_passkeys()?
            .into_iter()
            .find(|passkey| {
                passkey.live && passkey.owner == actor && passkey.credential_id == credential_id
            })
            .ok_or_else(|| {
                OwnerError::Refused(
                    "no live passkey of the acting owner has that credential id".to_owned(),
                )
            })?;
        let authority = ActAuthority::Owner(owner, surface);
        let prepared = server
            .vault()
            .prepare_recovery_hold_cancel_as(
                &authority,
                hold,
                &AuthorityKey::P256(passkey.public_key),
            )
            .map_err(refusal)?;
        Ok(PrepareReply {
            entry: to_b64url(&prepared.entry),
            challenge: to_b64url(&prepared.challenge),
        })
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/owner-passkeys/recovery-hold-cancel/land`: the prepared
/// Cancel with the passkey's assertion as its one signature, landed once
/// the fold counted it.
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
        let cancel = server
            .vault()
            .land_recovery_hold_cancel_as(&authority, &entry, assertion)
            .map_err(refusal)?;
        Ok(ReceiptReply {
            entry: revision_hex(&cancel),
        })
    })
    .await?;
    Ok(Json(reply))
}
