//! FIX 6424 part 3 (2b, Engine 10-20 21:0x rulings 1 and 5, CALLS `FIX 6424
//! channel-identity request nonce` and `FIX 6424 lifecycle retry token`): an
//! owner's approve-once press on one channel-identity lifecycle request
//! (provision, bind, rotate, release, route inbound) approves exactly that
//! request.
//!
//! Every lifecycle landing carries a request ref, its nonce, minted before
//! its first ask. A lifecycle door call takes the caller's own `request_ref`
//! (a true retry of exactly that request), else one its host's invocation
//! fixes for that input (the same invocation of the same request is the same
//! call), else a fresh one. Every other landing (a vault shape's provision,
//! bind or release, the native-mail pack, an embedding caller) names no ref,
//! so it gets a fresh one: it is a call of its own, and a caller that keeps
//! the result's `request_ref` retries exactly it through
//! `Vault::apply_channel_identity_lifecycle_request`. Its Gate input pins
//! [`ApprovalTarget::ChannelIdentityLifecycle`]: the verb, the identity, the
//! typed intent's parameters (fulfillment mode, the digest of a provision's
//! requested identity, a release's quarantine bound) and that nonce, never an
//! address a provider assigns later. The digest a hold names is the Gate's
//! own composer over that input; the result carries it as `approval_digest`,
//! beside `request_ref`, and [`channel_identity_lifecycle_approve_once_digest`]
//! composes it for a request.
//!
//! The request is kept by its ref BEFORE its ask, in one writer that reads
//! the ref and inserts it only when no row stands there, so two calls of one
//! ref share one identity: who asked, the verb, the identity it was given (a
//! provision's minted id, a delegated bind's row) and when that identity was
//! requested, and the digest of the caller's door input or of the request a
//! caller built. A retry naming the ref reuses that identity, so its
//! requested identity and its digest are the same, and a delegated bind is
//! never provisioned twice. Once the Gate allows it, its receipt, exactly as
//! the apply returned it (the identity's body and the door's view of its
//! facts as that apply committed them), is kept in the apply's own
//! transaction, and a retry answers it and applies nothing again. Only that
//! one ref is read: no earlier request is walked. A row that does not read or
//! decode leaves the call on today's path, a call of its own under a fresh
//! ref; a keep that does not commit is logged and the call goes on unkept.
//!
//! A kept receipt holds the identity's facts (an address among them), so it
//! goes with them: the identity's erase (`clear_assignment_for_delete`) or
//! retirement (`apply_channel_identity_body`) drops every request naming it,
//! and the actor's erase every request it made (this table's actor scrub).

use serde::{Deserialize, Serialize};

use super::{
    ChannelIdentityLifecycleIntent, ChannelIdentityLifecycleRequest, ChannelIdentityLifecycleResult,
};
use crate::Vault;
use crate::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityShape, ChannelIdentityState,
    channel_identity_facts_in_txn, decode_channel_identity_body, encode_channel_identity_body,
};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::gate::{ApprovalTarget, ChannelIdentityLifecycleFacts, ExternalEffectGateInput};
use crate::runtime_hooks::InvocationId;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

/// The derivation domain of a request ref its host's invocation fixes.
const LIFECYCLE_REQUEST_REF_DOMAIN: &[u8] = b"oneiron:channel-identity-lifecycle-request-ref:v1";
/// The BLAKE3 domain of a lifecycle door input's digest.
const LIFECYCLE_INPUT_DOMAIN: &[u8] = b"oneiron.channel_identity.lifecycle.input.v1";
/// The BLAKE3 domain of a built lifecycle request's digest.
const LIFECYCLE_REQUEST_DOMAIN: &[u8] = b"oneiron.channel_identity.lifecycle.request.v1";

/// Each lifecycle request, by its ref: see the module docs.
const REQUESTS: SideTable<EntityId, KeptLifecycleRequest, Named> =
    SideTable::new(&side_table::CHANNEL_IDENTITY_LIFECYCLE_REQUEST);

/// The Gate input of one lifecycle `request` over `snapshot` (the requested
/// identity of a provision, else the live row): pinned to its request when
/// `request_ref` names one, else exactly the input it was before FIX 6424.
pub(super) fn lifecycle_gate_input(
    request: &ChannelIdentityLifecycleRequest,
    snapshot: &ChannelIdentity,
    request_ref: Option<EntityId>,
) -> ExternalEffectGateInput {
    let identity_id = request.intent.identity_id();
    let mut provenance = request.actor.provenance(identity_id);
    provenance.approval_target = request_ref
        .and_then(|request_ref| lifecycle_facts(&request.intent, request_ref))
        .map(ApprovalTarget::ChannelIdentityLifecycle);
    ExternalEffectGateInput {
        actor: request.actor.gate_actor(),
        provenance,
        verb: request.intent.verb().as_str().to_owned(),
        channel: snapshot.channel().to_owned(),
        channel_identity_ref: Some(identity_id),
        counterparty: None,
        brief_ref: None,
        send_ref: None,
        standing_grant_ref: None,
        scoped_mcp_call: None,
        counterparty_first_touch: None,
        counterparty_opted_out: false,
        counterparty_opt_out_receipt_reason: None,
        has_opted_in: request.gate.has_opted_in,
        has_permission: request.gate.has_permission,
        policy_risk: request.gate.policy_risk.to_gate(),
        send_autonomy: None,
    }
}

/// A typed intent's parameters the pin binds: the fulfillment mode, the
/// digest of a provision's requested identity, a release's quarantine
/// bound. `None` when a provision's requested identity does not encode: that
/// call pins nothing and keeps the digest it had before FIX 6424 (its
/// identity is refused once it applies).
type IntentParameters = (Option<&'static str>, Option<[u8; 32]>, Option<u64>);

fn intent_parameters(intent: &ChannelIdentityLifecycleIntent) -> Option<IntentParameters> {
    Some(match intent {
        ChannelIdentityLifecycleIntent::Provision(provision) => {
            let body = encode_channel_identity_body(&provision.identity).ok()?;
            (
                Some(provision.fulfillment_mode.as_str()),
                Some(*blake3::hash(&body).as_bytes()),
                None,
            )
        }
        ChannelIdentityLifecycleIntent::Bind(bind) => {
            (Some(bind.fulfillment_mode.as_str()), None, None)
        }
        ChannelIdentityLifecycleIntent::Release(release) => {
            (None, None, Some(release.quarantine_until))
        }
        ChannelIdentityLifecycleIntent::Rotate(_)
        | ChannelIdentityLifecycleIntent::RouteInbound(_) => (None, None, None),
    })
}

/// The facts `intent`, as request `request_ref`, pins.
fn lifecycle_facts(
    intent: &ChannelIdentityLifecycleIntent,
    request_ref: EntityId,
) -> Option<ChannelIdentityLifecycleFacts> {
    let (fulfillment_mode, specification_digest, quarantine_until) = intent_parameters(intent)?;
    Some(ChannelIdentityLifecycleFacts {
        verb: intent.verb().as_str(),
        identity_id: intent.identity_id(),
        fulfillment_mode,
        specification_digest,
        quarantine_until,
        request_ref,
    })
}

/// FIX 6424 part 3: the approve-once digest (64 lower-hex) an owner's press
/// on one channel-identity lifecycle `request`, as request `request_ref`,
/// names, by the Gate's own composer over the input its gate reads (the
/// requested identity of a provision, else the identity's live row). `None`
/// when the identity is not there to read. A held result carries the same
/// digest as `approval_digest`.
///
/// # Errors
/// A storage error reading the identity.
pub fn channel_identity_lifecycle_approve_once_digest(
    vault: &Vault,
    request: &ChannelIdentityLifecycleRequest,
    request_ref: EntityId,
) -> Result<Option<String>> {
    let snapshot = match &request.intent {
        ChannelIdentityLifecycleIntent::Provision(intent) => intent.identity.clone(),
        intent => match vault.get_channel_identity(&intent.identity_id())? {
            Some(row) => row,
            None => return Ok(None),
        },
    };
    Ok(ApprovalTarget::held_digest(&lifecycle_gate_input(
        request,
        &snapshot,
        Some(request_ref),
    )))
}

fn frame(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

/// The digest of `request` as a caller built it, its nonce aside: its actor,
/// verb, identity and typed parameters. `None` when it pins nothing.
fn lifecycle_request_digest(request: &ChannelIdentityLifecycleRequest) -> Option<String> {
    let (mode, specification, quarantine) = intent_parameters(&request.intent)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(LIFECYCLE_REQUEST_DOMAIN);
    frame(&mut hasher, &request.actor.actor_class);
    frame(
        &mut hasher,
        request.actor.actor_ref.as_deref().unwrap_or_default(),
    );
    frame(
        &mut hasher,
        &request
            .actor
            .actor_entity_ref
            .map(|actor| actor.to_hex())
            .unwrap_or_default(),
    );
    frame(&mut hasher, request.intent.verb().as_str());
    frame(&mut hasher, &request.intent.identity_id().to_hex());
    frame(&mut hasher, mode.unwrap_or_default());
    frame(
        &mut hasher,
        &specification
            .map(|digest| bytes_to_hex_lower(&digest))
            .unwrap_or_default(),
    );
    frame(
        &mut hasher,
        &quarantine
            .map(|until| until.to_string())
            .unwrap_or_default(),
    );
    Some(bytes_to_hex_lower(hasher.finalize().as_bytes()))
}

/// The digest of a lifecycle door's `input` for `verb`: the caller's input
/// with no request ref, serialized.
pub(crate) fn lifecycle_input_digest<T: Serialize>(verb: &str, input: &T) -> [u8; 32] {
    let mut value = serde_json::to_value(input).unwrap_or_default();
    if let Some(fields) = value.as_object_mut() {
        fields.remove("request_ref");
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(LIFECYCLE_INPUT_DOMAIN);
    frame(&mut hasher, verb);
    hasher.update(&serde_json::to_vec(&value).unwrap_or_default());
    *hasher.finalize().as_bytes()
}

/// One lifecycle request as kept by its ref: see the module docs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeptLifecycleRequest {
    actor: Option<EntityId>,
    verb: String,
    identity_id: EntityId,
    /// When its identity was requested: a provision's requested identity
    /// is rebuilt with it.
    requested_at: u64,
    /// The door input's digest, lower hex, for a request a lifecycle door
    /// made.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    input_digest: Option<String>,
    /// The built request's digest, lower hex, for any other.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request_digest: Option<String>,
    /// The receipt the request answered once it applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completion: Option<RecordedLifecycle>,
}

/// The receipt a completed lifecycle request answered, as its apply
/// returned it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedLifecycle {
    receipt_id: String,
    gate_receipt_id: Option<String>,
    outcome: String,
    reason_codes: Vec<String>,
    owner_visible_state: String,
    /// The identity's body as the apply left it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity: Option<Vec<u8>>,
    outbound_closed: bool,
    identity_retiring: bool,
    /// The identity's facts as that apply committed them: the lifecycle
    /// door's view of the identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    view: Option<RecordedIdentityView>,
}

/// An identity as a lifecycle door's receipt shows it, as the apply that
/// completed the request committed it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordedIdentityView {
    pub(crate) channel: String,
    pub(crate) address_or_handle: String,
    pub(crate) shape: ChannelIdentityShape,
    pub(crate) binding: ChannelIdentityBinding,
    pub(crate) delegated: bool,
    pub(crate) state: ChannelIdentityState,
    pub(crate) pending_fulfillment: Option<String>,
    pub(crate) state_changed_at: u64,
    pub(crate) quarantine_until: Option<u64>,
    pub(crate) outbound_eligible: bool,
    pub(crate) occupies_assignment_key: bool,
}

/// What one lifecycle apply came to.
pub(crate) enum LifecycleApplied {
    /// The Gate decided it here.
    Applied(ChannelIdentityLifecycleResult),
    /// Its request had completed: the receipt it answered then, and the
    /// door's view of the identity as that apply committed it.
    Replayed(ChannelIdentityLifecycleResult, Option<RecordedIdentityView>),
}

impl LifecycleApplied {
    pub(super) fn into_result(self) -> ChannelIdentityLifecycleResult {
        match self {
            Self::Applied(result) | Self::Replayed(result, _) => result,
        }
    }
}

/// One lifecycle door call, as its request stood before its ask.
#[derive(Debug, Clone)]
pub(crate) struct LifecycleCall {
    /// The request's ref, its nonce.
    pub(crate) request_ref: EntityId,
    pub(crate) state: LifecycleCallState,
}

/// Where a lifecycle door call's request stands.
#[derive(Debug, Clone)]
pub(crate) enum LifecycleCallState {
    /// To be gated: the identity it was given and when that identity was
    /// requested (this call's, or the ones its kept request holds).
    Ready {
        identity_id: EntityId,
        requested_at: u64,
    },
    /// It applied: its identity, and the receipt it answered, which a retry
    /// answers again.
    Completed {
        identity_id: EntityId,
        result: Box<ChannelIdentityLifecycleResult>,
        view: Option<RecordedIdentityView>,
    },
    /// The ref names another request (another actor, verb or input).
    Conflict,
}

/// A request kept under one ref, as one writer found it.
enum Kept {
    Ready(KeptLifecycleRequest),
    Completed(KeptLifecycleRequest),
    Conflict,
    Unreadable,
}

impl KeptLifecycleRequest {
    /// The receipt a completed request answered, for a retry of it.
    fn replay(self, request_ref: EntityId) -> Option<LifecycleApplied> {
        let done = self.completion?;
        let result = ChannelIdentityLifecycleResult {
            receipt_id: done.receipt_id,
            gate_receipt_id: done.gate_receipt_id,
            outcome: done.outcome,
            reason_codes: done.reason_codes,
            owner_visible_state: done.owner_visible_state,
            identity: done
                .identity
                .and_then(|body| decode_channel_identity_body(&body).ok()),
            outbound_closed: done.outbound_closed,
            identity_retiring: done.identity_retiring,
            approval_digest: None,
            request_ref: Some(request_ref),
            paced_until: None,
        };
        Some(LifecycleApplied::Replayed(result, done.view))
    }
}

impl Vault {
    /// Keeps a request under `request_ref` before its ask (CALLS `FIX 6424
    /// lifecycle retry token`), in one writer: the row standing there when
    /// it is this request (`matches`), else `new_row` inserted. A row that
    /// does not read or decode is `Unreadable`; a writer that does not commit
    /// is logged and the call goes on with `new_row`, unkept.
    fn keep_lifecycle_request(
        &self,
        request_ref: EntityId,
        matches: impl Fn(&KeptLifecycleRequest) -> bool,
        new_row: impl Fn() -> Result<KeptLifecycleRequest>,
    ) -> Result<Kept> {
        let kept = self.try_with_write_txn(|wtxn| -> Result<Kept> {
            Ok(match REQUESTS.get(&self.store, wtxn, &request_ref) {
                Ok(Some(row)) if !matches(&row) => Kept::Conflict,
                Ok(Some(row)) if row.completion.is_some() => Kept::Completed(row),
                Ok(Some(row)) => Kept::Ready(row),
                Ok(None) => {
                    let row = new_row()?;
                    REQUESTS.put(&self.store, wtxn, &request_ref, &row)?;
                    Kept::Ready(row)
                }
                Err(_) => Kept::Unreadable,
            })
        });
        match kept {
            Ok(kept) => Ok(kept),
            Err(error) => {
                tracing::warn!(
                    request_ref = %request_ref.to_hex(),
                    %error,
                    "a channel-identity lifecycle request was not kept before its ask; the call \
                     goes on unkept"
                );
                Ok(Kept::Ready(new_row()?))
            }
        }
    }

    /// Resolves one lifecycle door call by `actor` before its ask: the
    /// request `supplied` names, else the one `invocation` fixes for this
    /// actor, verb and input, else a fresh one, kept with the identity
    /// `mint` gives a new request. A row that does not read or decode under
    /// that ref leaves the call on today's path, a request of its own under a
    /// fresh ref.
    ///
    /// # Errors
    /// `mint`'s own failure.
    pub(crate) fn begin_channel_identity_lifecycle(
        &self,
        actor: EntityId,
        verb: &'static str,
        supplied: Option<EntityId>,
        invocation: Option<InvocationId>,
        input_digest: [u8; 32],
        mint: impl Fn() -> Result<(EntityId, u64)>,
    ) -> Result<LifecycleCall> {
        let input_digest = bytes_to_hex_lower(&input_digest);
        let named = supplied.or_else(|| {
            let invocation = invocation?;
            EntityId::derive(
                LIFECYCLE_REQUEST_REF_DOMAIN,
                &[
                    actor.as_bytes(),
                    verb.as_bytes(),
                    &invocation.0,
                    input_digest.as_bytes(),
                ],
            )
            .ok()
        });
        let matches = |row: &KeptLifecycleRequest| {
            row.actor == Some(actor)
                && row.verb == verb
                && row.input_digest.as_deref() == Some(input_digest.as_str())
        };
        let new_row = || -> Result<KeptLifecycleRequest> {
            let (identity_id, requested_at) = mint()?;
            Ok(KeptLifecycleRequest {
                actor: Some(actor),
                verb: verb.to_owned(),
                identity_id,
                requested_at,
                input_digest: Some(input_digest.clone()),
                request_digest: None,
                completion: None,
            })
        };
        let mut request_ref = named.unwrap_or_else(EntityId::now);
        let mut kept = self.keep_lifecycle_request(request_ref, &matches, &new_row)?;
        if matches!(kept, Kept::Unreadable) {
            request_ref = EntityId::now();
            kept = match self.keep_lifecycle_request(request_ref, &matches, &new_row)? {
                Kept::Unreadable => Kept::Ready(new_row()?),
                kept => kept,
            };
        }
        let state = match kept {
            Kept::Ready(row) => LifecycleCallState::Ready {
                identity_id: row.identity_id,
                requested_at: row.requested_at,
            },
            Kept::Completed(row) => {
                let identity_id = row.identity_id;
                match row.replay(request_ref) {
                    Some(LifecycleApplied::Replayed(result, view)) => {
                        LifecycleCallState::Completed {
                            identity_id,
                            result: Box::new(result),
                            view,
                        }
                    }
                    _ => LifecycleCallState::Conflict,
                }
            }
            Kept::Conflict | Kept::Unreadable => LifecycleCallState::Conflict,
        };
        Ok(LifecycleCall { request_ref, state })
    }

    /// FIX 6424 part 3: applies `request` as the request `request_ref` names,
    /// kept by that ref before its ask: a retry of a request that completed
    /// answers its recorded receipt and applies nothing again. `None` gives
    /// it a fresh ref, a call of its own. A request that pins nothing (a
    /// provision whose requested identity does not encode) applies as
    /// before FIX 6424.
    pub(super) fn apply_channel_identity_lifecycle_kept(
        &self,
        request: ChannelIdentityLifecycleRequest,
        request_ref: Option<EntityId>,
    ) -> Result<LifecycleApplied> {
        let Some(request_digest) = lifecycle_request_digest(&request) else {
            return self.apply_channel_identity_lifecycle_gated(request, None);
        };
        let actor = request.actor.actor_entity_ref;
        let verb = request.intent.verb().as_str();
        let identity_id = request.intent.identity_id();
        let requested_at = match &request.intent {
            ChannelIdentityLifecycleIntent::Provision(intent) => intent.identity.state_changed_at(),
            _ => request.requested_at,
        };
        let matches = |row: &KeptLifecycleRequest| {
            row.actor == actor
                && row.verb == verb
                && row.identity_id == identity_id
                && row.request_digest.as_deref() == Some(request_digest.as_str())
        };
        let new_row = || -> Result<KeptLifecycleRequest> {
            Ok(KeptLifecycleRequest {
                actor,
                verb: verb.to_owned(),
                identity_id,
                requested_at,
                input_digest: None,
                request_digest: Some(request_digest.clone()),
                completion: None,
            })
        };
        let mut request_ref = request_ref.unwrap_or_else(EntityId::now);
        let kept = match self.keep_lifecycle_request(request_ref, &matches, &new_row)? {
            // Today's path: a call of its own, under a fresh ref.
            Kept::Unreadable => {
                request_ref = EntityId::now();
                self.keep_lifecycle_request(request_ref, &matches, &new_row)?
            }
            kept => kept,
        };
        match kept {
            Kept::Completed(row) => row.replay(request_ref).ok_or(Error::InvariantViolation(
                "a completed channel identity lifecycle request kept no receipt",
            )),
            Kept::Conflict => Err(Error::InvalidConfig(
                "request_ref names another channel identity lifecycle request".to_owned(),
            )),
            Kept::Ready(_) | Kept::Unreadable => {
                self.apply_channel_identity_lifecycle_gated(request, Some(request_ref))
            }
        }
    }
}

/// The receipt the request `request_ref` answered, when it completed for
/// `identity_id` before this apply's writer: another call of the same ref
/// got there first. A row that does not read or decode answers `None`.
pub(super) fn recorded_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    request_ref: EntityId,
    identity_id: EntityId,
) -> Option<LifecycleApplied> {
    REQUESTS
        .get(store, txn, &request_ref)
        .ok()
        .flatten()
        .filter(|row| row.identity_id == identity_id)?
        .replay(request_ref)
}

/// Keeps the receipt `result` the request `request_ref` answered for
/// `identity_id`, in the apply's own writer, beside the identity's body and
/// the door's view of its facts as this writer leaves them. A request no row
/// keeps (unkept, or dropped as its identity retired in this writer) keeps
/// nothing.
///
/// # Errors
/// A storage failure of the keep, which fails the apply with it, as the
/// apply's own receipt append does.
pub(super) fn record_completion_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    request_ref: EntityId,
    identity_id: EntityId,
    result: &ChannelIdentityLifecycleResult,
) -> Result<()> {
    let Some(mut row) = REQUESTS.get(store, wtxn, &request_ref).ok().flatten() else {
        return Ok(());
    };
    if row.completion.is_some() || row.identity_id != identity_id {
        return Ok(());
    }
    let view = result.identity.as_ref().and_then(|identity| {
        let facts = channel_identity_facts_in_txn(store, &*wtxn, &row.identity_id)
            .ok()
            .flatten()?;
        Some(RecordedIdentityView {
            outbound_eligible: identity.may_send() && facts.state == ChannelIdentityState::Active,
            occupies_assignment_key: identity.occupies_assignment_key(),
            delegated: identity.is_delegated(),
            channel: facts.channel,
            address_or_handle: facts.address_or_handle,
            shape: facts.shape,
            binding: facts.binding,
            state: facts.state,
            pending_fulfillment: facts.pending_fulfillment,
            state_changed_at: facts.state_changed_at,
            quarantine_until: facts.quarantine_until,
        })
    });
    row.completion = Some(RecordedLifecycle {
        receipt_id: result.receipt_id.clone(),
        gate_receipt_id: result.gate_receipt_id.clone(),
        outcome: result.outcome.clone(),
        reason_codes: result.reason_codes.clone(),
        owner_visible_state: result.owner_visible_state.clone(),
        identity: result
            .identity
            .as_ref()
            .and_then(|identity| encode_channel_identity_body(identity).ok()),
        outbound_closed: result.outbound_closed,
        identity_retiring: result.identity_retiring,
        view,
    });
    REQUESTS.put(store, wtxn, &request_ref, &row)
}

/// Drops every kept request `keep` refuses (and every row that does not
/// decode, which nothing reads back), in `wtxn`. A key that is not a ref is
/// passed over: no reader reaches it.
fn drop_requests_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    keep: impl Fn(&KeptLifecycleRequest) -> bool,
) -> Result<()> {
    let mut dropped = Vec::new();
    for row in REQUESTS.iter_raw_from(store, wtxn, &[])? {
        let (key, value) = row?;
        let Some(request_ref) = <[u8; 16]>::try_from(key.as_slice())
            .ok()
            .and_then(|key| EntityId::from_bytes(key).ok())
        else {
            continue;
        };
        if !REQUESTS.decode_value(&value).is_ok_and(|row| keep(&row)) {
            dropped.push(request_ref);
        }
    }
    for request_ref in dropped {
        REQUESTS.delete(store, wtxn, &request_ref)?;
    }
    Ok(())
}

/// FIX 6424 part 3: the erase of channel identity `id` drops every request
/// kept for it, receipts and their facts with them, in the erase's writer.
///
/// # Errors
/// A storage failure.
pub(crate) fn drop_lifecycle_requests_of_identity_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    drop_requests_in_txn(store, wtxn, |row| row.identity_id != *id)
}

/// FIX 6424 part 3: a write that leaves channel identity `id` retired
/// (released, quarantined, tombstoned) drops every request kept for it, in
/// that writer. Any other write keeps them.
///
/// # Errors
/// A storage failure.
pub(crate) fn retire_lifecycle_requests_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    identity: &ChannelIdentity,
) -> Result<()> {
    if !matches!(
        identity.state(),
        ChannelIdentityState::Released
            | ChannelIdentityState::Quarantine
            | ChannelIdentityState::Tombstone
    ) {
        return Ok(());
    }
    drop_lifecycle_requests_of_identity_in_txn(store, wtxn, id)
}

/// FIX 6424 part 3: this table's actor scrub (FIX 3520): an erase of
/// `actor` drops every request it made, in the erase's writer.
///
/// # Errors
/// A storage failure.
pub(crate) fn erase_lifecycle_request_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    drop_requests_in_txn(&vault.store, wtxn, |row| row.actor != Some(*actor))
}
