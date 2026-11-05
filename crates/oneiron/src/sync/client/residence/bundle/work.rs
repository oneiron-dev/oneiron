//! Durable sealed-bundle execution from the publisher's side (FIX 9254, CALLS
//! BUNDLE_PUBLISH_RECONCILE). The executor persists its exact attempt (see
//! `super::attempt`) before the first commit send, then addresses the home's
//! immutable work for it: the work id derives from the caller-known home or
//! the explicit unknown-home address, the executor, the input and both
//! objects' lengths and digests, so a begin resent
//! after a lost ack resumes the same work instead of starting another. A
//! saved attempt reconciles before any reassembly or upload on the same
//! pass; a pending or unanswered one stays uncertain and the pass ends
//! without moving anything, and only a genuine refusal or rebase settles
//! the exact attempt and frees a retry. The work id is an address, never
//! an authority: every echoed binding reconciles exactly against the saved
//! attempt before anything commits or enacts.

use serde::Deserialize;
use serde_json::json;

use super::attempt::{self, AttemptKey, BundleAttempt};
use super::{ResidenceRpc, refused, storage};
use crate::Vault;
use crate::authority::AuthorityEntryHash;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::sync::residence::{
    SealedBundleCommitInput, sealed_bundle_work_id, sealed_digest_from_hex, sealed_digest_hex,
    sealed_generation_from_hex, sealed_generation_hex,
};
use crate::sync::transport::TransportError;
use crate::world_keys::SealedBundleGeneration;

const COMMIT_RPC: &str = "residence.bundle.commit";
const STATUS_RPC: &str = "residence.bundle.commit.status";

/// A begin's accepted reply: the home's execution wrapper for the work.
#[derive(Deserialize)]
struct WorkReply {
    work: WorkJson,
}

/// A work-id status read: the wrapper, or nothing recorded.
#[derive(Deserialize)]
struct WorkStatusReply {
    work: Option<WorkJson>,
}

/// A request status read: the request's commit record, plus any work for
/// it. Read-only: it never frees or reuploads pending work by itself, and
/// its work is never bound to this install's attempt.
#[derive(Deserialize)]
struct RequestStatusReply {
    receipt: Option<StatusReceipt>,
    work: Option<WorkJson>,
}

/// The home's commit record for the request and the machine that made it,
/// when the home recorded one.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StatusReceipt {
    generation: String,
    bundle_digest: String,
}

/// One execution wrapper, as the home sends it.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WorkJson {
    work_id: String,
    state: String,
    home: Option<String>,
    executor: String,
    generation: String,
    parent: Option<String>,
    request: Option<String>,
    bundle_digest: String,
    pads_digest: String,
    progress: u64,
    total: u64,
    phase: String,
    entry: Option<WorkEntryJson>,
}

/// The committed generation's entry, which rides only on a committed
/// wrapper: the existing full bundle entry payload.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WorkEntryJson {
    generation: String,
    commit_order: u64,
    bundle_length: u64,
    bundle_digest: String,
    pads_length: u64,
    pads_digest: String,
}

/// One immutable attempt's state, as the home reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WorkState {
    Pending,
    Committed,
    NeedsRebase,
    Refused,
}

/// A parsed execution wrapper, reconciled against the caller's attempt.
#[derive(Clone, Debug)]
pub(super) struct WorkStatus {
    pub(super) id: [u8; 32],
    pub(super) state: WorkState,
    pub(super) home: Option<EntityId>,
    pub(super) executor: EntityId,
    pub(super) generation: SealedBundleGeneration,
    pub(super) parent: Option<SealedBundleGeneration>,
    pub(super) request: Option<AuthorityEntryHash>,
    pub(super) bundle_digest: [u8; 32],
    pub(super) pads_digest: [u8; 32],
    pub(super) progress: u64,
    pub(super) total: u64,
    pub(super) phase: String,
    pub(super) entry: Option<WorkEntry>,
}

/// A committed wrapper's entry.
#[derive(Clone, Copy, Debug)]
pub(super) struct WorkEntry {
    pub(super) generation: SealedBundleGeneration,
    pub(super) commit_order: u64,
    pub(super) bundle_length: u64,
    pub(super) bundle_digest: [u8; 32],
    pub(super) pads_length: u64,
    pub(super) pads_digest: [u8; 32],
}

/// What a begin send returns: the home's wrapper for the work, or its
/// genuine refusal, which is never a commit.
pub(super) enum WorkOutcome {
    Accepted(WorkStatus),
    Refused,
}

/// What a work-id status read says: the wrapper, nothing recorded, or no
/// answer. Only a parsed null is missing.
pub(super) enum WorkRead {
    Found(WorkStatus),
    Missing,
    Unknown,
}

/// What a request status read says: the record and any work for it, or no
/// answer. Only a parsed reply reads; a refused read never resolves.
enum RequestRead {
    Read {
        receipt: Option<StatusReceipt>,
        work: Option<WorkJson>,
    },
    Unknown,
}

/// What a saved attempt's home says, after its work status is read.
pub(super) enum WorkFate {
    /// No work stands unresolved: an upload may be assembled and sent.
    Open,
    /// Work stands pending, or the home did not answer for it: the attempt
    /// stays, and the pass ends without moving anything.
    Uncertain,
    /// The home finished the exact saved attempt.
    Committed(BundleAttempt),
}

/// What the caller bound before the first send: the work id and the exact
/// attempt it addresses.
struct WorkAddress {
    id: [u8; 32],
    home: Option<EntityId>,
    executor: EntityId,
    input: SealedBundleCommitInput,
    bundle: (u64, [u8; 32]),
    pads: (u64, [u8; 32]),
}

impl WorkAddress {
    fn of(attempt: &BundleAttempt) -> Self {
        let input = attempt.input();
        let objects = attempt.objects();
        Self {
            id: sealed_bundle_work_id(attempt.home, attempt.executor, input, objects),
            home: attempt.home,
            executor: attempt.executor,
            input,
            bundle: objects[0],
            pads: objects[1],
        }
    }
}

/// This install's executor identity, when it has one. Never invented: the
/// caller leaves the pass pending without it.
pub(super) fn executor_id(vault: &Vault) -> Result<Option<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    crate::identity::read_machine_id_in_txn(vault, &txn)
}

/// One wrapper's state. Unknown states are refused replies, never guesses.
fn work_state_of(json: &WorkJson) -> std::result::Result<WorkState, TransportError> {
    match json.state.as_str() {
        "pending" => Ok(WorkState::Pending),
        "committed" => Ok(WorkState::Committed),
        "needsRebase" => Ok(WorkState::NeedsRebase),
        "refused" => Ok(WorkState::Refused),
        _ => Err(refused()),
    }
}

/// Parses one execution wrapper, bound to the attempt `expected` names: the
/// id, the input, both object digests and both object lengths must match
/// exactly. Anything else is a refused reply, never a guess.
fn parse_work(
    json: WorkJson,
    expected: &WorkAddress,
) -> std::result::Result<WorkStatus, TransportError> {
    let id = sealed_digest_from_hex(&json.work_id).ok_or_else(refused)?;
    if id != expected.id {
        return Err(refused());
    }
    let state = work_state_of(&json)?;
    let home = json
        .home
        .as_deref()
        .map(EntityId::from_hex)
        .transpose()
        .map_err(|_| refused())?;
    // The server echoes its actual home. It binds only when this install
    // knew the home when it saved the attempt; a saved-unknown echo is
    // untrusted metadata, never authority. Every other binding stays exact.
    match (expected.home, home) {
        (None, _) => {}
        (Some(want), Some(got)) if want == got => {}
        (Some(_), _) => return Err(refused()),
    }
    let executor = EntityId::from_hex(&json.executor).map_err(|_| refused())?;
    if executor != expected.executor {
        return Err(refused());
    }
    let generation = sealed_generation_from_hex(&json.generation).ok_or_else(refused)?;
    if generation != expected.input.generation {
        return Err(refused());
    }
    let parent = match json.parent.as_deref() {
        Some(text) => Some(sealed_generation_from_hex(text).ok_or_else(refused)?),
        None => None,
    };
    if parent != expected.input.parent {
        return Err(refused());
    }
    let request = match json.request.as_deref() {
        Some(text) => Some(sealed_digest_from_hex(text).ok_or_else(refused)?),
        None => None,
    };
    if request != expected.input.request {
        return Err(refused());
    }
    let bundle_digest = sealed_digest_from_hex(&json.bundle_digest).ok_or_else(refused)?;
    if bundle_digest != expected.bundle.1 {
        return Err(refused());
    }
    let pads_digest = sealed_digest_from_hex(&json.pads_digest).ok_or_else(refused)?;
    if pads_digest != expected.pads.1 {
        return Err(refused());
    }
    let entry = json
        .entry
        .map(|entry| {
            Ok::<WorkEntry, TransportError>(WorkEntry {
                generation: sealed_generation_from_hex(&entry.generation).ok_or_else(refused)?,
                commit_order: entry.commit_order,
                bundle_length: entry.bundle_length,
                bundle_digest: sealed_digest_from_hex(&entry.bundle_digest).ok_or_else(refused)?,
                pads_length: entry.pads_length,
                pads_digest: sealed_digest_from_hex(&entry.pads_digest).ok_or_else(refused)?,
            })
        })
        .transpose()?;
    // The entry rides only on a committed wrapper, and names the work
    // exactly: generation, both digests, and both lengths.
    match (state, entry) {
        (WorkState::Committed, Some(entry))
            if entry.generation == generation
                && entry.bundle_digest == bundle_digest
                && entry.pads_digest == pads_digest
                && entry.bundle_length == expected.bundle.0
                && entry.pads_length == expected.pads.0 => {}
        (WorkState::Committed, _) => return Err(refused()),
        (_, None) => {}
        (_, Some(_)) => return Err(refused()),
    }
    Ok(WorkStatus {
        id,
        state,
        home,
        executor,
        generation,
        parent,
        request,
        bundle_digest,
        pads_digest,
        progress: json.progress,
        total: json.total,
        phase: json.phase,
        entry,
    })
}

/// Sends the exact begin for the saved `attempt`, deriving the caller-known
/// work id first: the home's execution wrapper, or its refusal. A refused
/// call is a genuine refusal, never a commit; a call that did not reach
/// the home, or a reply that does not bind, is an error and leaves the
/// attempt uncertain.
pub(super) async fn begin_work(
    rpc: &mut ResidenceRpc,
    attempt: &BundleAttempt,
) -> std::result::Result<WorkOutcome, TransportError> {
    let expected = WorkAddress::of(attempt);
    let input = expected.input;
    let mut params = json!({
        "generation": sealed_generation_hex(&input.generation),
        "parent": input.parent.as_ref().map(sealed_generation_hex),
        "root": input.root.as_ref().map(|root| sealed_digest_hex(&root.0)),
        "workId": sealed_digest_hex(&expected.id),
    });
    if let Some(request) = input.request {
        params["request"] = json!(sealed_digest_hex(&request));
    }
    let Ok(reply) = rpc.call(COMMIT_RPC, params).await? else {
        return Ok(WorkOutcome::Refused);
    };
    let reply: WorkReply = serde_json::from_value(reply).map_err(|_| refused())?;
    Ok(WorkOutcome::Accepted(parse_work(reply.work, &expected)?))
}

/// Reads the work `expected` addresses on this socket, resuming it when pending.
async fn status_by_id(
    rpc: &mut ResidenceRpc,
    expected: &WorkAddress,
) -> std::result::Result<WorkRead, TransportError> {
    let Ok(reply) = rpc
        .call(
            STATUS_RPC,
            json!({ "workId": sealed_digest_hex(&expected.id) }),
        )
        .await?
    else {
        return Ok(WorkRead::Unknown);
    };
    let reply: WorkStatusReply = serde_json::from_value(reply).map_err(|_| refused())?;
    match reply.work {
        Some(work) => Ok(WorkRead::Found(parse_work(work, expected)?)),
        None => Ok(WorkRead::Missing),
    }
}

/// Reads the request's commit record plus any work for it. The request
/// selector names exactly one of request or work id, and stays read-only:
/// it never executes, and its work is never this install's address.
async fn status_by_request(
    rpc: &mut ResidenceRpc,
    request: AuthorityEntryHash,
) -> std::result::Result<RequestRead, TransportError> {
    let Ok(reply) = rpc
        .call(
            STATUS_RPC,
            json!({ "request": sealed_digest_hex(&request) }),
        )
        .await?
    else {
        return Ok(RequestRead::Unknown);
    };
    let reply: RequestStatusReply = serde_json::from_value(reply).map_err(|_| refused())?;
    Ok(RequestRead::Read {
        receipt: reply.receipt,
        work: reply.work,
    })
}

/// Holds a pending attempt, commits a finished exact one, and settles a
/// terminally refused or rebased one back to open. The status already
/// bound to the attempt; only its state decides.
fn settle_or_hold(
    vault: &Vault,
    key: AttemptKey,
    attempt: BundleAttempt,
    status: WorkStatus,
) -> std::result::Result<WorkFate, TransportError> {
    match status.state {
        WorkState::Pending => Ok(WorkFate::Uncertain),
        WorkState::Committed => Ok(WorkFate::Committed(attempt)),
        WorkState::NeedsRebase | WorkState::Refused => {
            attempt::settle_one(vault, key, &attempt).map_err(storage)?;
            Ok(WorkFate::Open)
        }
    }
}

/// The request selector's commit record against the saved attempt: only an
/// exact generation plus bundle digest commits. Anything else stays
/// uncertain, never enacted, never freed.
fn reconcile_receipt(
    attempt: BundleAttempt,
    receipt: StatusReceipt,
) -> std::result::Result<WorkFate, TransportError> {
    let generation = sealed_generation_from_hex(&receipt.generation).ok_or_else(refused)?;
    let digest = sealed_digest_from_hex(&receipt.bundle_digest).ok_or_else(refused)?;
    if generation == attempt.generation && digest == attempt.bundle_digest {
        Ok(WorkFate::Committed(attempt))
    } else {
        Ok(WorkFate::Uncertain)
    }
}

/// Reissues the SAME begin for a saved attempt the home holds no work for:
/// no upload, no new assembly. Only a genuine refusal or terminal state
/// settles it back to open.
async fn resend(
    vault: &Vault,
    rpc: &mut ResidenceRpc,
    key: AttemptKey,
    attempt: BundleAttempt,
) -> std::result::Result<WorkFate, TransportError> {
    let outcome = begin_work(rpc, &attempt).await?;
    match outcome {
        WorkOutcome::Accepted(status) => settle_or_hold(vault, key, attempt, status),
        WorkOutcome::Refused => {
            attempt::settle_one(vault, key, &attempt).map_err(storage)?;
            Ok(WorkFate::Open)
        }
    }
}

/// Reconciles this install's saved attempt for the owner `request` with the
/// home `rpc` reaches: a finished exact attempt commits, a pending or
/// unanswered one stays uncertain, and only a terminal refusal or rebase,
/// after settling the exact attempt, frees a retry. The saved work id
/// reads first, which resumes the server's driver for it after a
/// disconnect, and another pending execution for the request cannot block
/// this install's own lookup. Only a missing work record falls back to the
/// request's receipt; a missing record with no exact receipt and no known
/// pending execution resends the SAME begin, never a new upload.
pub(super) async fn reconcile_request(
    rpc: &mut ResidenceRpc,
    vault: &Vault,
    request: AuthorityEntryHash,
    home: EntityId,
) -> std::result::Result<WorkFate, TransportError> {
    let Some(attempt) = vault.unresolved_bundle_attempt(request).map_err(storage)? else {
        return Ok(WorkFate::Open);
    };
    if attempt.home != Some(home) {
        return Ok(WorkFate::Open);
    }
    let expected = WorkAddress::of(&attempt);
    match status_by_id(rpc, &expected).await? {
        WorkRead::Found(status) => {
            settle_or_hold(vault, AttemptKey::Request(request), attempt, status)
        }
        WorkRead::Unknown => Ok(WorkFate::Uncertain),
        WorkRead::Missing => match status_by_request(rpc, request).await? {
            RequestRead::Unknown => Ok(WorkFate::Uncertain),
            RequestRead::Read { receipt, work } => {
                if let Some(receipt) = receipt {
                    return reconcile_receipt(attempt, receipt);
                }
                // Another execution known pending for the request holds the
                // resend: this install does not pile its own begin on.
                if let Some(work) = work
                    && work_state_of(&work)? == WorkState::Pending
                {
                    return Ok(WorkFate::Uncertain);
                }
                resend(vault, rpc, AttemptKey::Request(request), attempt).await
            }
        },
    }
}

/// Reconciles this install's saved automatic attempt for the route
/// `address`: the same fates as [`reconcile_request`], addressed by the
/// caller-known work id. The route keys continuity, so proof flapping
/// between unknown and known never orphans the attempt.
pub(super) async fn reconcile_auto(
    rpc: &mut ResidenceRpc,
    vault: &Vault,
    address: [u8; 32],
) -> std::result::Result<WorkFate, TransportError> {
    let Some(attempt) = vault.unresolved_auto_attempt(address).map_err(storage)? else {
        return Ok(WorkFate::Open);
    };
    let expected = WorkAddress::of(&attempt);
    match status_by_id(rpc, &expected).await? {
        WorkRead::Found(status) => {
            settle_or_hold(vault, AttemptKey::Auto(address), attempt, status)
        }
        WorkRead::Unknown => Ok(WorkFate::Uncertain),
        WorkRead::Missing => resend(vault, rpc, AttemptKey::Auto(address), attempt).await,
    }
}
