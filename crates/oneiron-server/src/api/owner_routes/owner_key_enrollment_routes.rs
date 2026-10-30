//! `/v1/owner/owner-signing-keys`: the owner enrols a device's own Ed25519
//! owner signing key on the vault's roster, from any surface where he is
//! authenticated, on any host, the hosted console included (FIX 4920 part 2;
//! Engine 10-20 00:5x, ruling D). Each route passes `owner()` first, so a
//! hosted operator's root acts as nobody (FIX 2222), and an agent never
//! reaches the act at all.
//!
//! - `GET` lists every enrolled owner key: the machine that holds it, the
//!   install that carried the act, the owner, whether it is live and whether
//!   his checkpoint policy may name it now. Empty before any enrollment.
//! - `POST .../challenge` answers the bytes the device's new key signs: the
//!   vault, the machine, the key and the owner this request proves, fixed
//!   here; the act's target and zero `seen` follow from them.
//! - `POST .../enroll` takes the machine, the key and that signature. This
//!   server's install carries the owner's act under its own live profile
//!   and cosigns it; this host's own root signs it as the predecessor. Only
//!   a counted enrollment answers its receipt.
//!
//! The wire form is CALLS "FIX 4920 enrollment HTTP representation": a
//! machine as 32 hex, a key as 64 hex, a proof and a challenge as hex. The
//! client supplies no owner, vault, target, `seen`, seed or signature but
//! the new key's own. Where he spoke from is the act's audit only
//! (`machine_routes::act_surface_admitted`).

use std::sync::Arc;

use axum::extract::State;
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::authority::{
    ActAuthority, EnrolledOwnerKey, OWNER_KEY_POSSESSION_PROOF_LEN, OwnerKeyEnrollment,
    OwnerKeyEnrollmentReceipt,
};
use oneiron::error::RecordError;
use serde::{Deserialize, Serialize};

use super::machine_routes::{act_surface_admitted, parse_revision, revision_hex};
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
                path: "/owner-signing-keys",
                summary: "Every owner signing key enrolled on the vault's roster (FIX 4920), ascending by key: its enrollment entry, the machine that holds it, the install that carried the act, the owner, whether it is live and whether a checkpoint policy may name it now. Empty before any enrollment.",
                row: None,
                shape: None,
            },
            get(list),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/owner-signing-keys/challenge",
                summary: "The bytes a device's new owner key signs to enrol (`machine`, 32 hex; `public_key`, 64 hex): the vault, the machine, the key and the owner this request proves. Answers `challenge` as hex.",
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
                path: "/owner-signing-keys/enroll",
                summary: "The owner enrols a device's own Ed25519 owner signing key (`machine`, 32 hex; `public_key`, 64 hex; `proof`, 128 hex: the key's signature over its challenge). This install carries and cosigns the act, this host's root signs it as the predecessor; answers the receipt only once the fold counted it.",
                row: None,
                shape: Some(RestShape::json(
                    enroll_request_body_schema,
                    enroll_receipt_schema,
                )),
            },
            post(enroll),
        ),
    ]
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ChallengeRequest {
    /// The machine that holds the key, as 32 hex.
    machine: String,
    /// The new key, as 64 lower-case hex.
    public_key: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct EnrollRequest {
    /// As for the challenge.
    machine: String,
    /// As for the challenge.
    public_key: String,
    /// The new key's signature over the challenge, as 128 lower-case hex.
    proof: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct ChallengeReply {
    /// The bytes the new key signs, as lower-case hex.
    challenge: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct ReceiptReply {
    /// The enrollment's authority entry, as 64 hex.
    entry: String,
    machine: String,
    public_key: String,
}

#[derive(Debug, Serialize)]
struct KeyReply {
    /// The enrollment's authority entry, as 64 hex.
    entry: String,
    /// The machine that holds the key, as 32 hex.
    machine: String,
    /// The install that carried the owner's act, as 32 hex.
    carrier: String,
    /// The owner whose act enrolled it, as 32 hex.
    owner: String,
    /// The key, as 64 hex.
    public_key: String,
    /// On the roster and not revoked.
    live: bool,
    /// A root his checkpoint policy may name now.
    eligible: bool,
    /// When it was signed, advisory unix seconds.
    at: u64,
}

#[derive(Debug, Serialize)]
struct ListReply {
    /// Ascending by key; empty before any enrollment.
    keys: Vec<KeyReply>,
}

/// The OpenAPI schema of `POST /v1/owner/owner-signing-keys/challenge`'s body (FIX 11617): [`ChallengeRequest`].
pub(crate) fn challenge_request_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ChallengeRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/owner-signing-keys/challenge`'s answer (FIX 11617): [`ChallengeReply`].
pub(crate) fn challenge_reply_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ChallengeReply>()
}

/// The OpenAPI schema of `POST /v1/owner/owner-signing-keys/enroll`'s body (FIX 11617): [`EnrollRequest`].
pub(crate) fn enroll_request_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<EnrollRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/owner-signing-keys/enroll`'s answer (FIX 11617): [`ReceiptReply`].
pub(crate) fn enroll_receipt_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ReceiptReply>()
}

/// Policy hook (CALLS "FIX 4920 enrollment HTTP representation"): the hex
/// digits of a proof, one raw Ed25519 signature.
const PROOF_HEX_DIGITS: usize = 2 * OWNER_KEY_POSSESSION_PROOF_LEN;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A proof as the client sent it: [`PROOF_HEX_DIGITS`] lower-case hex.
fn parse_proof(value: &str) -> OwnerResult<Vec<u8>> {
    let refused = || {
        OwnerError::Invalid(format!(
            "proof must be {PROOF_HEX_DIGITS} lower-case hex: the new key's signature over its \
             challenge"
        ))
    };
    if value.len() != PROOF_HEX_DIGITS
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(refused());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(refused)
        })
        .collect()
}

/// Policy hook (CALLS "FIX 4920 enrollment refusal mapping"): the engine's
/// typed refusals as the owner's. An enrollment that does not verify (a
/// key the roster names, a proof that is not the key's) is a malformed
/// request; an agent's act, an install that cannot carry it, or an
/// enrollment the fold does not count is a refusal naming its rule.
/// Anything else stays the engine's.
fn refusal(error: oneiron::Error) -> OwnerError {
    match &error {
        oneiron::Error::Record(RecordError::InvalidAuthorityLogBody(_)) => {
            OwnerError::Invalid(error.to_string())
        }
        oneiron::Error::Record(RecordError::AuthorityRefused(_)) => {
            OwnerError::Refused(error.to_string())
        }
        _ => OwnerError::Engine(Box::new(error)),
    }
}

/// What a route answers when this host holds no root key to sign the
/// enrollment as its predecessor: this enrollment does not happen here.
fn no_root_signer() -> OwnerError {
    OwnerError::Refused(
        "this host holds no root signing key to authorize an owner key enrollment".to_owned(),
    )
}

/// Enrols `input` as `authority`, with this host's root as the predecessor:
/// the managed issuer, else this install's own self-host root issuer
/// (FIX-LIST 3018).
fn enrol_as_host(
    server: &SyncServer,
    authority: &ActAuthority,
    input: OwnerKeyEnrollment,
) -> OwnerResult<OwnerKeyEnrollmentReceipt> {
    let issuer = server.host_issuer().ok_or_else(no_root_signer)?;
    server
        .vault()
        .enrol_owner_signing_key_as_host(authority, input, issuer)
        .map_err(refusal)
}

fn key_reply(key: &EnrolledOwnerKey) -> KeyReply {
    KeyReply {
        entry: revision_hex(&key.entry),
        machine: key.machine.to_hex(),
        carrier: key.carrier.to_hex(),
        owner: key.owner.to_hex(),
        public_key: revision_hex(&key.public_key),
        live: key.live,
        eligible: key.eligible,
        at: key.at,
    }
}

/// `GET /v1/owner/owner-signing-keys`: every enrolled owner key, ascending
/// by key, a revoked or ineligible one included.
async fn list(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<ListReply> {
    owner(&auth, &server)?;
    let reply = blocking(move || -> OwnerResult<ListReply> {
        let keys = server.vault().enrolled_owner_keys()?;
        Ok(ListReply {
            keys: keys.iter().map(key_reply).collect(),
        })
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/owner-signing-keys/challenge`: the bytes the device's
/// new key signs to enrol for the owner this request proves.
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
        let machine = entity_id("machine", &body.machine)?;
        let public_key = parse_revision("public_key", &body.public_key)?;
        let authority = ActAuthority::Owner(owner, surface);
        let challenge = server
            .vault()
            .owner_key_enrollment_challenge_as(&authority, machine, &public_key)
            .map_err(refusal)?;
        Ok(ChallengeReply {
            challenge: hex(&challenge),
        })
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/owner-signing-keys/enroll`: the owner enrols the key,
/// carried by this install, with this host's root as its predecessor.
async fn enroll(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<EnrollRequest>,
) -> OwnerReply<ReceiptReply> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let body = payload.read(&server).await?;
    let reply = blocking(move || -> OwnerResult<ReceiptReply> {
        let input = OwnerKeyEnrollment {
            machine: entity_id("machine", &body.machine)?,
            public_key: parse_revision("public_key", &body.public_key)?,
            proof: parse_proof(&body.proof)?,
        };
        let authority = ActAuthority::Owner(owner, surface);
        let receipt = enrol_as_host(&server, &authority, input)?;
        Ok(ReceiptReply {
            entry: revision_hex(&receipt.entry),
            machine: receipt.machine.to_hex(),
            public_key: revision_hex(&receipt.public_key),
        })
    })
    .await?;
    Ok(Json(reply))
}
