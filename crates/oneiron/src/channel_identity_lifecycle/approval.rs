//! FIX 6424 part 3 (2b, Engine 10-20 21:0x rulings 1 and 5, CALLS `FIX 6424
//! channel-identity request nonce` and `FIX 6424 lifecycle retry token`): an
//! owner's approve-once press on one channel-identity lifecycle request
//! (provision, bind, rotate, release, route inbound) approves exactly that
//! request.
//!
//! A request carries a `request_ref`, its nonce, minted before its first ask:
//! the caller's own when it names one (a true retry of exactly that request),
//! else one its host's invocation fixes (the same invocation of the same
//! request is the same call), else a fresh one for this call. Its Gate input
//! pins [`ApprovalTarget::ChannelIdentityLifecycle`]: the verb, the identity,
//! the typed intent's parameters (fulfillment mode, the digest of a
//! provision's requested identity, a release's quarantine bound) and that
//! nonce, never an address a provider assigns later. The digest a hold names
//! is the Gate's own composer over that input; its receipt carries it as
//! `approval_digest`, beside `request_ref`, and
//! [`channel_identity_lifecycle_approve_once_digest`] composes it for a
//! request.
//!
//! The request is kept by its ref once its Gate decision committed, in a
//! writer of its own ([`keep_press_after_admission`]): who asked, the verb,
//! the digest of the caller's input, the identity it was given (a
//! provision's minted id, a delegated bind's provisioned row) and when its
//! identity was requested, the digest its hold named, and, once the Gate
//! allowed it and it applied, the receipt it answered. Ids and digests only:
//! no address, specification or credential. A retry naming the ref, with the
//! same input, reuses that identity, so its requested identity and its
//! digest are the same, and a delegated bind is never provisioned twice; a
//! completed request answers its recorded receipt and applies nothing again.
//! Only that one ref is read: no earlier request is walked, and a row that
//! does not read or decode leaves the call on today's path (a new request
//! under that ref). A lifecycle intent applies in the Gate's own writer, so
//! it keeps no Pending row and no spent press: the recorded receipt is its
//! retry's answer.
//!
//! A landing with no request identity (`Vault::apply_channel_identity_lifecycle_intent`:
//! a vault shape's provision, bind or release, the native-mail pack) pins
//! nothing and composes the digest it composed before (CALLS `FIX 6424
//! lifecycle landings with no request identity`).

use serde::{Deserialize, Serialize};

use super::{
    ChannelIdentityLifecycleIntent, ChannelIdentityLifecycleRequest,
    ChannelIdentityLifecycleResult, LIFECYCLE_DENIED, LIFECYCLE_HELD,
};
use crate::Vault;
use crate::channel_identity::{ChannelIdentity, encode_channel_identity_body};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;
use crate::gate::{ApprovalTarget, ChannelIdentityLifecycleFacts, ExternalEffectGateInput};
use crate::outbound_intent_ledger::keep_press_after_admission;
use crate::runtime_hooks::InvocationId;
use crate::side_table::{self, Named, SideTable};

/// The derivation domain of a request ref its host's invocation fixes.
const LIFECYCLE_REQUEST_REF_DOMAIN: &[u8] = b"oneiron:channel-identity-lifecycle-request-ref:v1";

/// The BLAKE3 domain of a lifecycle door input's digest.
const LIFECYCLE_INPUT_DOMAIN: &[u8] = b"oneiron.channel_identity.lifecycle.input.v1";

/// Each lifecycle request, by its ref: see the module docs.
const REQUESTS: SideTable<EntityId, RetainedLifecycleRequest, Named> =
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

/// The facts `intent`, as request `request_ref`, pins. `None` when a
/// provision's requested identity does not encode: that call keeps the
/// digest it had before FIX 6424 (its identity is refused once it applies).
fn lifecycle_facts(
    intent: &ChannelIdentityLifecycleIntent,
    request_ref: EntityId,
) -> Option<ChannelIdentityLifecycleFacts> {
    let mut facts = ChannelIdentityLifecycleFacts {
        verb: intent.verb().as_str(),
        identity_id: intent.identity_id(),
        fulfillment_mode: None,
        specification_digest: None,
        quarantine_until: None,
        request_ref,
    };
    match intent {
        ChannelIdentityLifecycleIntent::Provision(provision) => {
            let body = encode_channel_identity_body(&provision.identity).ok()?;
            facts.fulfillment_mode = Some(provision.fulfillment_mode.as_str());
            facts.specification_digest = Some(*blake3::hash(&body).as_bytes());
        }
        ChannelIdentityLifecycleIntent::Bind(bind) => {
            facts.fulfillment_mode = Some(bind.fulfillment_mode.as_str());
        }
        ChannelIdentityLifecycleIntent::Release(release) => {
            facts.quarantine_until = Some(release.quarantine_until);
        }
        ChannelIdentityLifecycleIntent::Rotate(_)
        | ChannelIdentityLifecycleIntent::RouteInbound(_) => {}
    }
    Some(facts)
}

/// FIX 6424 part 3: the approve-once digest (64 lower-hex) an owner's press
/// on one channel-identity lifecycle `request`, as request `request_ref`,
/// names, by the Gate's own composer over the input its gate reads (the
/// requested identity of a provision, else the identity's live row). `None`
/// when the identity is not there to read. A held receipt carries the same
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

/// One lifecycle request as kept by its ref: see the module docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedLifecycleRequest {
    actor: EntityId,
    verb: String,
    /// BLAKE3 of the caller's door input with no request ref, lower hex.
    input_digest: String,
    identity_id: EntityId,
    /// When its identity was requested: a provision's requested identity
    /// is rebuilt with it.
    requested_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    approval_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completion: Option<RecordedLifecycle>,
}

/// The receipt a completed lifecycle request answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedLifecycle {
    receipt_ref: String,
    gate_receipt_ref: Option<String>,
    outcome: String,
    reason_codes: Vec<String>,
    owner_visible_state: String,
    outbound_closed: bool,
    identity_retiring: bool,
}

/// One lifecycle door call, as its request was resolved before its ask.
#[derive(Debug, Clone)]
pub(crate) struct LifecycleCall {
    /// The request's ref, its nonce.
    pub(crate) request_ref: EntityId,
    actor: EntityId,
    verb: &'static str,
    input_digest: String,
    pub(crate) state: LifecycleCallState,
}

/// Where a lifecycle door call's request stands.
#[derive(Debug, Clone)]
pub(crate) enum LifecycleCallState {
    /// No request is kept under its ref: a new request.
    New,
    /// A request kept under its ref, not yet applied: its retry reuses the
    /// identity it was given and when that identity was requested.
    Retained {
        identity_id: EntityId,
        requested_at: u64,
    },
    /// A request that applied: its identity and its recorded receipt,
    /// which a retry answers.
    Completed {
        identity_id: EntityId,
        result: Box<ChannelIdentityLifecycleResult>,
    },
    /// The ref names another request (another actor, verb or input).
    Conflict,
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
    hasher.update(&(verb.len() as u64).to_le_bytes());
    hasher.update(verb.as_bytes());
    hasher.update(&serde_json::to_vec(&value).unwrap_or_default());
    *hasher.finalize().as_bytes()
}

impl Vault {
    /// Resolves one lifecycle door call by `actor` before its ask (CALLS
    /// `FIX 6424 lifecycle retry token`): the request `supplied` names, else
    /// the one `invocation` fixes for this actor, verb and input, else a
    /// fresh one. Reads only that request's own row; a row that does not
    /// read or decode is a new request under that ref.
    pub(crate) fn channel_identity_lifecycle_call(
        &self,
        actor: EntityId,
        verb: &'static str,
        supplied: Option<EntityId>,
        invocation: Option<InvocationId>,
        input_digest: [u8; 32],
    ) -> LifecycleCall {
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
        let request_ref = named.unwrap_or_else(EntityId::now);
        let retained = named.and_then(|request_ref| self.retained_lifecycle_request(request_ref));
        let state = match retained {
            None => LifecycleCallState::New,
            Some(row)
                if row.actor != actor || row.verb != verb || row.input_digest != input_digest =>
            {
                LifecycleCallState::Conflict
            }
            Some(row) => match row.completion {
                Some(done) => LifecycleCallState::Completed {
                    identity_id: row.identity_id,
                    result: Box::new(ChannelIdentityLifecycleResult {
                        receipt_id: done.receipt_ref,
                        gate_receipt_id: done.gate_receipt_ref,
                        outcome: done.outcome,
                        reason_codes: done.reason_codes,
                        owner_visible_state: done.owner_visible_state,
                        identity: self.get_channel_identity(&row.identity_id).ok().flatten(),
                        outbound_closed: done.outbound_closed,
                        identity_retiring: done.identity_retiring,
                        approval_digest: None,
                        request_ref: Some(request_ref),
                    }),
                },
                None => LifecycleCallState::Retained {
                    identity_id: row.identity_id,
                    requested_at: row.requested_at,
                },
            },
        };
        LifecycleCall {
            request_ref,
            actor,
            verb,
            input_digest,
            state,
        }
    }

    /// The request kept under `request_ref`; `None` for none, or a row that
    /// does not read or decode (logged): that call stays on today's path.
    fn retained_lifecycle_request(
        &self,
        request_ref: EntityId,
    ) -> Option<RetainedLifecycleRequest> {
        let read = self
            .store
            .env
            .read_txn()
            .map_err(crate::error::Error::from)
            .and_then(|txn| REQUESTS.get(&self.store, &txn, &request_ref));
        match read {
            Ok(row) => row,
            Err(error) => {
                tracing::warn!(
                    request_ref = %request_ref.to_hex(),
                    %error,
                    "a kept channel-identity lifecycle request did not read; the call is a new \
                     request"
                );
                None
            }
        }
    }

    /// Keeps `call`'s request, given identity `identity_id` requested at
    /// `requested_at`, once its Gate decision committed with `result`: the
    /// digest its hold named, and its receipt once it applied. A request
    /// already kept keeps its identity and the first receipt it answered. A
    /// write that fails is logged and the call stands
    /// (`KEPT_PRESS_WRITE_FAILURE_CONTINUES`): its retry is then a new
    /// request.
    ///
    /// # Errors
    /// The write's own failure, only when that constant is `false`.
    pub(crate) fn keep_channel_identity_lifecycle_request(
        &self,
        call: &LifecycleCall,
        identity_id: EntityId,
        requested_at: u64,
        result: &ChannelIdentityLifecycleResult,
    ) -> Result<()> {
        let applied = result.outcome != LIFECYCLE_HELD && result.outcome != LIFECYCLE_DENIED;
        let completion = applied.then(|| RecordedLifecycle {
            receipt_ref: result.receipt_id.clone(),
            gate_receipt_ref: result.gate_receipt_id.clone(),
            outcome: result.outcome.clone(),
            reason_codes: result.reason_codes.clone(),
            owner_visible_state: result.owner_visible_state.clone(),
            outbound_closed: result.outbound_closed,
            identity_retiring: result.identity_retiring,
        });
        let subject = call.request_ref.to_hex();
        keep_press_after_admission(self, &subject, |wtxn| {
            let row = match REQUESTS
                .get(&self.store, wtxn, &call.request_ref)
                .ok()
                .flatten()
            {
                Some(mut row) => {
                    if row.actor != call.actor
                        || row.verb != call.verb
                        || row.input_digest != call.input_digest
                    {
                        return Ok(());
                    }
                    row.approval_digest = result.approval_digest.clone().or(row.approval_digest);
                    row.completion = row.completion.or(completion);
                    row
                }
                None => RetainedLifecycleRequest {
                    actor: call.actor,
                    verb: call.verb.to_owned(),
                    input_digest: call.input_digest.clone(),
                    identity_id,
                    requested_at,
                    approval_digest: result.approval_digest.clone(),
                    completion,
                },
            };
            REQUESTS.put(&self.store, wtxn, &call.request_ref, &row)
        })
    }
}
