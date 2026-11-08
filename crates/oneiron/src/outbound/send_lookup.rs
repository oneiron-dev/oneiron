//! The engine send id and the provider lookup of a send that may have gone
//! out (FIX 4747; canon ARCH-0023b, pending outbound send: "Uncertain: check
//! by an engine-stamped id on every outbound send through the connector").
//! Entry: `EngineSendId`, `SentLookup`.
//!
//! One logical send has one engine send id, the same on every machine: it
//! derives from the connector-send TASK's logical send ref, which the TASK
//! carries synced, never from a device-local ledger key. Where a provider
//! keeps an id of the sender's own on the wire (native mail's Message-ID,
//! LINE's retry key), a TASK's send carries one derived from it, so any
//! machine can ask the provider whether that send went: a sink's
//! [`super::OutboundExecutionSink::lookup_sent`]. Gmail keeps the Message-ID
//! its frozen plan mints. Slack and Telegram keep no such id, and their
//! lookup cannot tell.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::capability::OutboundVerbContract;
use super::connector_task::{
    ConnectorSendTaskOutcome, SEND_EXECUTOR_LEASE_FIRST_GENERATION, TakenSendExecutorLease,
};
use super::intent::OutboundIntent;
use crate::entity_id::EntityId;

/// The one engine send id of a logical send (FIX 4747): 64 lower-hex
/// characters, the same on every machine that reads its TASK.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EngineSendId(String);

impl EngineSendId {
    /// The id of the logical send `logical_send_ref` names.
    pub(crate) fn derive(logical_send_ref: &str) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron.outbound.engine_send_id.v1");
        hasher.update(&(logical_send_ref.len() as u64).to_le_bytes());
        hasher.update(logical_send_ref.as_bytes());
        Self(crate::entity_id::bytes_to_hex_lower(
            hasher.finalize().as_bytes(),
        ))
    }

    /// The id as its 64 lower-hex characters.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The engine send id of a connector-send TASK's logical send. Engine call
/// (CALLS, FIX 4747): it derives from the TASK's logical send ref (its actor
/// and idempotency key, or the TASK itself when it names none), which every
/// machine reads off the synced TASK, so a handed-over send looks up the
/// same id the first machine put on the wire.
pub(super) fn engine_send_id(task: &super::ConnectorSendTask) -> EngineSendId {
    EngineSendId::derive(&super::executor::connector_logical_send_intent_ref(task))
}

/// What a provider says of one engine send id (FIX 4747).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SentLookup {
    /// The provider kept the send: it went, under `provider_ref`.
    Sent { provider_ref: String },
    /// The provider answered and has no such send: it did not go. A proven
    /// non-delivery.
    NotSent,
    /// The provider would drop a resend under the same id for now (LINE's
    /// retry key, inside its window): the resend may go, but nothing is
    /// proven, so the send stays uncertain and every later resend asks
    /// again (review #6555).
    DedupedResend,
    /// Nobody can tell: the provider keeps no id of ours, or its answer did
    /// not come.
    CannotTell,
}

/// What a lookup may read of the send it looks up: its frozen intent, its
/// verb and the sender identity the dispatch resolved. Never its body.
pub struct SentLookupTarget<'a> {
    /// The sink-facing scheduled ref the send's plan is keyed by.
    pub intent_ref: &'a str,
    pub intent: &'a OutboundIntent,
    pub verb_contract: &'static OutboundVerbContract,
    pub channel_identity_ref: Option<EntityId>,
    /// When the send was approved (Unix seconds): the earliest any executor
    /// could have sent it. `None` when the caller does not know.
    pub send_approved_at: Option<u64>,
}

/// The bound on one provider lookup's request. Engine call (CALLS, FIX
/// 4747): a lookup is one bounded read, and a provider that does not answer
/// in time cannot tell.
pub const SENT_LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);

/// The receipt field naming what a send's lookup found: [`SENT_LOOKUP_SENT`],
/// [`SENT_LOOKUP_NOT_SENT`] or [`SENT_LOOKUP_CANNOT_TELL`] (FIX 4747).
pub(crate) const SENT_LOOKUP_FIELD: &str = "sent_lookup";
/// The provider kept the send.
pub(crate) const SENT_LOOKUP_SENT: &str = "sent";
/// The provider has no such send.
pub(crate) const SENT_LOOKUP_NOT_SENT: &str = "not_sent";
/// Nobody can tell.
pub(crate) const SENT_LOOKUP_CANNOT_TELL: &str = "cannot_tell";
/// The provider drops a resend under the same id for now; nothing is proven.
pub(crate) const SENT_LOOKUP_DEDUPED_RESEND: &str = "deduped_resend";
/// The execution's `retry_state` when nobody can tell: nothing was sent now.
pub(crate) const SENT_LOOKUP_CANNOT_TELL_REASON: &str = "sent_lookup_cannot_tell";

/// Whether a send under `taken` first looks itself up: an earlier executor
/// may have sent it. Engine call (CALLS, FIX 4747): a TASK taken at a lease
/// generation above the first whose send no lookup or owner's resend has
/// cleared at this generation yet. An older Failed outcome proves nothing
/// about a later executor's send, so it does not skip the lookup (review
/// #6574); a TASK whose outcome permits no send never reaches here.
pub(super) fn earlier_executor_may_have_sent(taken: &TakenSendExecutorLease) -> bool {
    taken.lease.generation > SEND_EXECUTOR_LEASE_FIRST_GENERATION
        && taken.lookup_cleared_generation != Some(taken.lease.generation)
}

/// Whether `outcome` is the owner's word that the send is not to be resent
/// (FIX 4747).
pub(super) const fn owner_declined_resend(outcome: Option<ConnectorSendTaskOutcome>) -> bool {
    matches!(outcome, Some(ConnectorSendTaskOutcome::OwnerDeclinedResend))
}

/// How long a send that came back ambiguous waits before its lookup, in
/// seconds. Engine call (CALLS, FIX 4747): the lookup runs on the attempt
/// after this one, so a provider whose sent mail is searchable only a
/// moment after it accepts a message shows it.
pub(super) const UNCERTAIN_SEND_LOOKUP_DELAY_SECS: u64 = 60;

/// How often a send held for the owner's answer re-reads its TASK, in
/// seconds. Engine call (CALLS, FIX 4747): the answer may come from any
/// machine, and the TASK's executor picks it up within this.
pub(super) const UNCERTAIN_SEND_ANSWER_POLL_SECS: u64 = 300;

/// The queue reason of a send that waits for a lookup.
pub(super) const UNCERTAIN_SEND_LOOKUP_DUE_REASON: &str = "uncertain_send_lookup_due";

/// The queue reason of a send that waits for the owner's answer.
pub(super) const UNCERTAIN_SEND_AWAITS_OWNER_REASON: &str = "uncertain_send_awaits_owner";
