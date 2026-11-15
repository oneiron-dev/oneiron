//! `/v1/owner/owner-signing-keys`: the owner enrols a device's own Ed25519
//! owner signing key on the vault's roster, from any surface where he is
//! authenticated, on any host, the hosted console included (FIX 4920 part 2;
//! Engine 10-20 00:5x, ruling D). Each route passes `owner()` first, so a
//! hosted operator's root acts as nobody (FIX 2222), and an agent never
//! reaches the act at all.
//!
//! - `GET` lists every enrolled owner key: the machine that holds it, the
//!   install that carried the act, the owner, whether it is live, whether
//!   his checkpoint policy may name it now, what kind of key it is,
//!   whether this install holds it, every machine whose removal ends it
//!   while it is live and whether it is the recovery root's authority key,
//!   so a removal screen can say before the act which keys end and whether
//!   the recovery kit ends with them. Empty before any enrollment.
//! - `POST .../challenge` answers the bytes the device's new key signs: the
//!   vault, the machine, the key and the owner this request proves, fixed
//!   here; the act's target and zero `seen` follow from them.
//! - `POST .../enroll` takes the machine, the key and that signature. This
//!   server's install carries the owner's act under its own live profile
//!   and cosigns it; this host's own root signs it as the predecessor. Only
//!   a counted enrollment answers its receipt.
//! - `POST .../enroll-this-install` enrols this server's own install's key,
//!   made in its keystore on first use, by the same act, and the server then
//!   holds it as a checkpoint root signer (FIX 4921). A managed host's
//!   server refuses it (409): an enrolled owner key proves the owner acts
//!   its install carries, and a managed host holds no owner key.
//! - `POST .../remove` ends one enrolled device key and keeps its machine
//!   (the owner's ruling AUTH-5). The owner key this install holds signs the
//!   revocation, so an install that holds none answers 409
//!   `owner_key_required`. A removal that would end the last owner key held
//!   on a device answers 409 `last_device_key` and writes nothing, until
//!   the request carries `confirm`.
//! - `GET .../changes` lists every enrollment and removal of an enrolled
//!   owner key, newest first. It is the notice of a key change: every owner
//!   device holds the log, reads the same list, and shows what it has not
//!   shown yet.
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
    ActAuthority, AuthorityKey, CheckpointRootSigner, EnrolledOwnerKey, EnrolledOwnerKeyKind,
    LastDeviceKeyConfirmation, OWNER_KEY_POSSESSION_PROOF_LEN, OwnerKeyChange, OwnerKeyChangeKind,
    OwnerKeyEnrollment, OwnerKeyEnrollmentReceipt, OwnerKeyRemoval, RemainingOwnerKeys,
};
use oneiron::error::RecordError;
use serde::{Deserialize, Serialize};

use super::machine_routes::{act_surface_admitted, parse_revision, revision_hex};
use super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::error::{ApiError, ApiErrorDetails};
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/owner-signing-keys",
                summary: "Every owner signing key enrolled on the vault's roster (FIX 4920), ascending by key: its enrollment entry, the machine that holds it, the install that carried the act, the owner, whether it is live, whether a checkpoint policy may name it now, its kind (`device` or `recovery_authority`), whether this install holds it, every machine whose removal ends it while it is live (`device_machines`) and whether a counted enrollment marks it the recovery root's authority key (`recovery_authority`). Empty before any enrollment.",
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
        (
            OwnerRoute {
                method: "post",
                path: "/owner-signing-keys/enroll-this-install",
                summary: "The owner enrols this install's own Ed25519 owner signing key, made in its keystore on first use (FIX 4921): the same act as `/enroll`, and the server then holds the key as a checkpoint root signer. A key already enrolled and live answers its receipt; one the roster revoked is replaced by a fresh key, which is enrolled. On a managed host the route refuses: a managed host holds no owner key, and the owner enrols one on his own device.",
                row: None,
                shape: Some(RestShape::no_body(enroll_receipt_schema)),
            },
            post(enroll_this_install),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/owner-signing-keys/remove",
                summary: "The owner removes one enrolled device owner key (`public_key`, 64 hex) and keeps its machine. The owner key this install holds signs the revocation; an install that holds none answers 409 `owner_key_required`. A removal that would end the last owner key held on a device answers 409 `last_device_key` and writes nothing until the request carries `confirm`: `last_device_key`. Answers the revocation only once the fold counted it, with what remains and whether the removal also ended the recovery root's authority key (`ends_recovery_root`).",
                row: None,
                shape: Some(RestShape::json(
                    remove_request_body_schema,
                    removal_reply_schema,
                )),
            },
            post(remove),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/owner-signing-keys/changes",
                summary: "Every enrollment and removal of an enrolled owner key that the vault's log holds, newest first: the entry, `enrolled`, `removed` or `removed_by_ended_key` (two removals that crossed ended both keys), the key, the machine its enrollment names, its kind, the key that signed the entry and when. Every owner device reads the same list, so it is the notice of a key change. Empty before any enrollment.",
                row: None,
                shape: None,
            },
            get(changes),
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

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct RemoveRequest {
    /// The enrolled owner key to remove, as 64 lower-case hex.
    public_key: String,
    /// `last_device_key`: the owner read that this ends the last owner key
    /// held on a device, and confirmed. Absent otherwise.
    #[serde(default)]
    confirm: Option<String>,
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

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct RemovalReply {
    /// The revocation's authority entry, as 64 hex.
    entry: String,
    /// The key that ended, as 64 hex.
    public_key: String,
    /// The machine its enrollment names, as 32 hex.
    machine: String,
    /// The owner key that signed the revocation, as hex.
    signed_by: String,
    /// The owner keys still held on a device.
    remaining_device_keys: usize,
    /// Whether the recovery root's authority key is live.
    recovery_root: bool,
    /// Whether this removal ended the recovery root's authority key, and
    /// with it the recovery kit: the key was also enrolled as the root's.
    ends_recovery_root: bool,
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
    /// `device`: a device's own key; `recovery_authority`: the recovery
    /// root's authority key, which this route's removal refuses. The names
    /// are the enum's own serde names.
    kind: EnrolledOwnerKeyKind,
    /// Whether this install holds the key, so it can sign a removal.
    held_here: bool,
    /// Every machine a counted enrollment names as holding the key as a
    /// device's key, each as 32 hex, ascending. While the key is live, the
    /// removal of one of them ends it, when that removal stands on an
    /// install that holds an owner key. Empty for a key enrolled only as
    /// the recovery root's.
    device_machines: Vec<String>,
    /// A counted enrollment marks the key the recovery root's authority
    /// key, whatever `kind` says of the listed one. With a machine in
    /// `device_machines` the key is both, and the recovery kit ends when
    /// that machine's removal, or the key's own, ends the key.
    recovery_authority: bool,
}

#[derive(Debug, Serialize)]
struct ListReply {
    /// Ascending by key; empty before any enrollment.
    keys: Vec<KeyReply>,
}

#[derive(Debug, Serialize)]
struct ChangeReply {
    /// The change's authority entry, as 64 hex.
    entry: String,
    /// `enrolled`, `removed`, or `removed_by_ended_key`: the key ended
    /// through a removal the vault did not count, because a crossing removal
    /// ended that removal's own signer.
    change: &'static str,
    /// The key, as 64 hex.
    public_key: String,
    /// The machine the key's enrollment names, as 32 hex.
    machine: String,
    /// `device` or `recovery_authority`, as the list's `kind`.
    kind: EnrolledOwnerKeyKind,
    /// The key that signed the entry, as hex: an enrollment's predecessor, a
    /// removal's proof.
    signed_by: String,
    /// When it was signed, advisory unix seconds.
    at: u64,
}

#[derive(Debug, Serialize)]
struct ChangesReply {
    /// Newest first; empty before any enrollment.
    changes: Vec<ChangeReply>,
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

/// The OpenAPI schema of `POST /v1/owner/owner-signing-keys/remove`'s body: [`RemoveRequest`].
pub(crate) fn remove_request_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<RemoveRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/owner-signing-keys/remove`'s answer: [`RemovalReply`].
pub(crate) fn removal_reply_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<RemovalReply>()
}

/// The state of the 409 a removal answers when it would end the last owner
/// key held on a device and the request carries no confirmation, and the
/// value of `confirm` that gives it.
const LAST_DEVICE_KEY: &str = "last_device_key";

/// The confirmation a removal request carries in `confirm`.
pub(super) fn last_device_key_confirmation(
    confirm: Option<&str>,
) -> OwnerResult<LastDeviceKeyConfirmation> {
    match confirm {
        None => Ok(LastDeviceKeyConfirmation::NotGiven),
        Some(LAST_DEVICE_KEY) => Ok(LastDeviceKeyConfirmation::Given),
        Some(_) => Err(OwnerError::Invalid(format!(
            "confirm must be `{LAST_DEVICE_KEY}` or absent"
        ))),
    }
}

/// What a removal answers when it would end the last owner key held on a
/// device and the owner has not confirmed (the owner's ruling AUTH-5): 409,
/// state `last_device_key`, with what remains, and whether it would also
/// end the recovery kit's key. Nothing was written.
pub(super) fn last_device_key_refusal(remaining: RemainingOwnerKeys) -> ApiError {
    let recovery = if remaining.ends_recovery_root {
        "it also ends the recovery kit's key"
    } else if remaining.recovery_root {
        "the recovery kit's key stays enrolled"
    } else {
        "no recovery kit's key stays enrolled"
    };
    ApiError::new(
        format!(
            "this ends the last owner key held on a device; {recovery}. After it a change of the \
             owner's needs recovery, and the vault keeps asking for an owner key. Nothing was \
             written."
        ),
        ApiErrorDetails::InvalidState {
            state: Some(LAST_DEVICE_KEY.to_owned()),
        },
        [format!(
            "To go on, send the request again with `confirm`: `{LAST_DEVICE_KEY}`."
        )],
    )
}

/// Policy hook (CALLS "FIX 4920 enrollment HTTP representation"): the hex
/// digits of a proof, one raw Ed25519 signature.
const PROOF_HEX_DIGITS: usize = 2 * OWNER_KEY_POSSESSION_PROOF_LEN;

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

/// An authority key as lower-case hex: an Ed25519 key's 32 bytes, a P-256
/// key's compressed encoding.
fn authority_key_hex(key: &AuthorityKey) -> String {
    match key {
        AuthorityKey::Ed25519(bytes) => hex(bytes),
        AuthorityKey::P256(bytes) => hex(bytes),
    }
}

fn change_reply(change: &OwnerKeyChange) -> ChangeReply {
    ChangeReply {
        entry: revision_hex(&change.entry),
        change: match change.change {
            OwnerKeyChangeKind::Enrolled => "enrolled",
            OwnerKeyChangeKind::Removed => "removed",
            OwnerKeyChangeKind::RemovedByEndedKey => "removed_by_ended_key",
        },
        public_key: revision_hex(&change.public_key),
        machine: change.machine.to_hex(),
        kind: change.kind,
        signed_by: authority_key_hex(&change.signed_by),
        at: change.at,
    }
}

fn key_reply(key: &EnrolledOwnerKey, held: &[AuthorityKey]) -> KeyReply {
    KeyReply {
        entry: revision_hex(&key.entry),
        machine: key.machine.to_hex(),
        carrier: key.carrier.to_hex(),
        owner: key.owner.to_hex(),
        public_key: revision_hex(&key.public_key),
        live: key.live,
        eligible: key.eligible,
        at: key.at,
        kind: key.kind,
        held_here: held.contains(&AuthorityKey::Ed25519(key.public_key)),
        device_machines: key
            .device_machines
            .iter()
            .map(oneiron::EntityId::to_hex)
            .collect(),
        recovery_authority: key.recovery_authority,
    }
}

/// `GET /v1/owner/owner-signing-keys`: every enrolled owner key, ascending
/// by key, a revoked or ineligible one included.
async fn list(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<ListReply> {
    owner(&auth, &server)?;
    let reply = blocking(move || -> OwnerResult<ListReply> {
        let keys = server.vault().enrolled_owner_keys()?;
        let held: Vec<AuthorityKey> = server
            .vault()
            .checkpoint_root_signers()
            .iter()
            .map(|signer| signer.as_ref().root())
            .collect();
        Ok(ListReply {
            keys: keys.iter().map(|key| key_reply(key, &held)).collect(),
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
            challenge: oneiron_hex::encode(&challenge),
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

/// `POST /v1/owner/owner-signing-keys/enroll-this-install`: the owner enrols
/// this install's own owner signing key, made in its keystore on first use,
/// carried by this install, with this host's root as its predecessor; the
/// server then holds it as a checkpoint root signer (FIX 4921). A key
/// already enrolled and live answers its receipt. On a `Hosted` vault the
/// route refuses (409, state `refused`): the key would prove the owner acts
/// this server carries, and a managed host holds no owner key. The owner
/// enrols a key on his own device (`POST .../enroll`).
async fn enroll_this_install(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<ReceiptReply> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let reply = blocking(move || -> OwnerResult<ReceiptReply> {
        let authority = ActAuthority::Owner(owner, surface);
        let issuer = server.host_issuer().ok_or_else(no_root_signer)?;
        let receipt = server
            .vault()
            .enrol_serving_install_owner_signing_key(&authority, issuer)
            .map_err(refusal)?;
        Ok(ReceiptReply {
            entry: revision_hex(&receipt.entry),
            machine: receipt.machine.to_hex(),
            public_key: revision_hex(&receipt.public_key),
        })
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/owner-signing-keys/remove`: the owner removes one enrolled
/// device owner key and keeps its machine (the owner's ruling AUTH-5). The
/// owner key this install holds signs the revocation as its primary signer;
/// an install that holds none answers 409, state `owner_key_required`. A
/// removal that would end the last owner key held on a device answers 409,
/// state `last_device_key`, and writes nothing until the request carries
/// `confirm`. The recovery root's authority key is refused: the recovery
/// root's door changes it.
async fn remove(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<RemoveRequest>,
) -> OwnerReply<RemovalReply> {
    let owner = owner(&auth, &server)?;
    let body = payload.read(&server).await?;
    let removal = blocking(move || -> OwnerResult<OwnerKeyRemoval> {
        let key = parse_revision("public_key", &body.public_key)?;
        let confirmation = last_device_key_confirmation(body.confirm.as_deref())?;
        server
            .vault()
            .remove_owner_key(&owner, key, confirmation)
            .map_err(refusal)
    })
    .await?;
    match removal {
        OwnerKeyRemoval::Removed { ended, remaining } => Ok(Json(RemovalReply {
            entry: revision_hex(&ended.entry),
            public_key: revision_hex(&ended.public_key),
            machine: ended.machine.to_hex(),
            signed_by: authority_key_hex(&ended.signed_by),
            remaining_device_keys: remaining.device_keys,
            recovery_root: remaining.recovery_root,
            ends_recovery_root: remaining.ends_recovery_root,
        })),
        OwnerKeyRemoval::LastDeviceKey(remaining) => Err(last_device_key_refusal(remaining).into()),
    }
}

/// `GET /v1/owner/owner-signing-keys/changes`: every enrollment and removal
/// of an enrolled owner key, newest first (the owner's ruling AUTH-5). The
/// list is read from the vault's log, which every owner device holds, so
/// each device shows the same changes.
async fn changes(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<ChangesReply> {
    let owner = owner(&auth, &server)?;
    let reply = blocking(move || -> OwnerResult<ChangesReply> {
        let changes = server.vault().owner_key_changes(&owner)?;
        Ok(ChangesReply {
            changes: changes.iter().map(change_reply).collect(),
        })
    })
    .await?;
    Ok(Json(reply))
}
