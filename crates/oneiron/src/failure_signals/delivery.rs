//! Delivery of the failure-signal exports to the deployment's publisher
//! (OF-380). One batch carries the tier-1 counts and the sealed code-fix
//! records; it leaves as an ordinary outbound effect on the
//! `failure_signals/send` capability, through the dispatch pipeline and its
//! recorded receipt. What the batch held is acked only once it was
//! delivered, so a failed send loses nothing. A batch the Gate holds for the
//! owner is staged before it leaves and sent again as it was on the passes
//! after it, so his one press releases the batch he saw (FIX 6679, `held`).
//!
//! Consent is the owner's "Help improve Oneiron" switch
//! ([`FailureSignalConfig::exports`](crate::config::failure_signals::FailureSignalConfig::exports)):
//! on by default hosted with opt-out, off by default self-host with opt-in.
//! While it holds, the vault keeps one standing channel grant for the sender's
//! own derived principal, so the gate admits a batch without a per-send ask;
//! once it stops, the grant is revoked and nothing is sent. Owner feedback's
//! per-send approval is never involved.
//!
//! The engine names no publisher. The host supplies the destination and the
//! transport that carries the bytes.

use std::cell::Cell;

use serde::{Deserialize, Serialize};

use super::Tier1FailureCount;
use super::code_fix::CodeFixExport;
use super::held::{BatchSend, HeldBatch};
use crate::entity_id::EntityId;
use crate::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchError,
    OutboundDispatchGate, OutboundDispatchOutcome, OutboundDispatchRequest,
    OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink, OutboundIntent,
    OutboundIntentDraft, OutboundIntentTrigger, connector_actor_id,
};
use crate::outbound_grant::{
    StandingOutboundGrant, StandingOutboundGrantScope, StandingOutboundGrantStatus,
    encode_standing_outbound_grant_body, standing_outbound_grant_ids_for_principal,
    standing_outbound_grant_in_txn,
};
use crate::{Result, Vault};

/// The outbound channel a batch leaves on.
pub const FAILURE_SIGNALS_CHANNEL: &str = "failure_signals";
/// Its one verb.
pub const FAILURE_SIGNALS_SEND_VERB: &str = "send";
pub const FAILURE_SIGNAL_BATCH_VERSION: u16 = 1;

/// Origin recorded on the participation grant. The mint is the
/// deployment's participation, not an ask escalator.
const PARTICIPATION_COMPONENT: &str = "failure_signals.participation";
const PARTICIPATION_ACTION: &str = "export";

/// What one delivery carries, as the publisher receives it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureSignalBatch {
    pub version: u16,
    /// Random; derived from nothing in the vault.
    pub batch_id: String,
    /// Whether the deployment lets the publisher train on these. Export
    /// never grants it.
    pub training_permitted: bool,
    pub counts: Vec<Tier1FailureCount>,
    pub code_fix: Vec<CodeFixExport>,
}

/// What the host transport is handed once the pipeline admits a batch.
pub struct FailureSignalTransportRequest<'a> {
    /// The ordinary outbound execution request, unmodified.
    pub execution: &'a OutboundExecutionRequest<'a>,
    /// The batch, as JSON.
    pub body: &'a [u8],
    /// Lowercase hex BLAKE3 of `body`.
    pub digest: &'a str,
}

/// The host's carrier for a batch.
pub trait FailureSignalTransport {
    /// Delivers the batch and reports an ordinary execution outcome. A send
    /// that may have landed says so with
    /// [`OutboundExecutionOutcome::with_possible_delivery`].
    fn send_failure_signals(
        &mut self,
        request: &FailureSignalTransportRequest<'_>,
    ) -> OutboundExecutionOutcome;
}

/// What one delivery pass did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureSignalDelivery {
    /// This deployment does not export, or there was nothing to send.
    Idle,
    /// Delivered and acked.
    Delivered { counts: usize, records: usize },
    /// The pipeline did not deliver it. Nothing was acked, except counts
    /// that may have landed (an ambiguous send), which are not sent twice.
    NotDelivered {
        outcome: OutboundDispatchOutcome,
        /// While the Gate holds this batch for the owner, the approve-once
        /// digest his one-time press must name to release it, 64 lower-hex
        /// (FIX 6424), copied from the dispatch result. It pins this batch,
        /// which the next pass sends again as it was until it is released or
        /// retired (FIX 6679). `None` otherwise.
        approval_digest: Option<String>,
    },
}

struct BatchSink<'a, T: ?Sized> {
    transport: &'a mut T,
    vault: &'a Vault,
    held: &'a HeldBatch,
    /// The approve-once digest the owner's answer to a carried batch names.
    approval_digest: Option<&'a str>,
    /// Set once a check before the wire finds the batch may no longer
    /// leave (FIX 6679): no wire started.
    retired: Cell<bool>,
}

impl<T: FailureSignalTransport + ?Sized> OutboundExecutionSink for BatchSink<'_, T> {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        // FIX 6679: an erase, a world turned private or the owner's denial
        // since the pass read the batch keeps it off the wire.
        match self
            .vault
            .failure_signal_batch_may_leave(self.held, self.approval_digest)
        {
            Ok(true) => {}
            Ok(false) => {
                self.retired.set(true);
                return OutboundExecutionOutcome::failed("failure_signals_batch_retired");
            }
            Err(_) => return OutboundExecutionOutcome::failed("failure_signals_batch_unread"),
        }
        let digest = self.held.digest.as_str();
        self.transport
            .send_failure_signals(&FailureSignalTransportRequest {
                execution: request,
                body: self.held.body.as_bytes(),
                digest,
            })
            .with_receipt_field("failure_signals_batch_digest", digest)
    }

    /// The same check under the writer that would record the send's gate
    /// decision (FIX 6404): a batch that may no longer leave records none,
    /// and no owner press is spent on it.
    fn admit_in(&self, txn: &heed::RoTxn<'_>) -> Result<()> {
        if self
            .held
            .may_still_leave_in(self.vault, txn, self.approval_digest)?
        {
            return Ok(());
        }
        self.retired.set(true);
        Err(crate::Error::InvalidConfig(
            "failure signal batch may no longer leave".into(),
        ))
    }
}

/// The dispatch request one send of `held` carries: the same intent, refs,
/// actor and gate on every pass, so a carried batch's frozen ledger bytes
/// and approve-once digest are its first send's (FIX 6679).
pub(super) fn batch_request(
    sender: EntityId,
    held: &HeldBatch,
    now: u64,
) -> OutboundDispatchRequest {
    let send_ref = held.send_ref();
    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new(
            sender.to_hex(),
            FAILURE_SIGNALS_SEND_VERB,
            FAILURE_SIGNALS_CHANNEL,
            held.endpoint.as_str(),
        )
        .content_ref(held.content_ref())
        .idempotency_key(send_ref.clone()),
        OutboundIntentTrigger::agent_immediate(send_ref.clone()),
    );
    let mut request = OutboundDispatchRequest::new(
        send_ref.clone(),
        send_ref.clone(),
        intent,
        // An engine-owned send, like a scoped tool call's: first-party
        // is the class whose ceiling is Auto, and the grant still
        // decides what it may send.
        OutboundDispatchActor {
            actor_class: "first_party".to_owned(),
            actor_ref: Some(sender.to_hex()),
            actor_entity_ref: Some(sender),
        },
        OutboundDispatchGate::allow_when_policy_grants(),
        now,
        OutboundDeliveryWindowDecision::DeliverNow,
    );
    request.ledger_identity_ref = Some(send_ref);
    request
}

impl Vault {
    /// Sends one batch to `target`, the publisher's exact endpoint: every
    /// tier-1 count since the last delivery and up to `max_records` sealed
    /// code-fix records. A batch the Gate held for the owner is sent again
    /// exactly as it was, under its own refs, until it is settled or retired;
    /// counts and records that came since wait for the batch after it (FIX
    /// 6679). `now` is seconds since the epoch.
    pub fn deliver_failure_signals(
        &self,
        target: &str,
        max_records: usize,
        now: u64,
        transport: &mut dyn FailureSignalTransport,
    ) -> std::result::Result<FailureSignalDelivery, OutboundDispatchError> {
        let _pass = self.store.diagnostics.failure_signals.lock_delivery();
        let config = self.config.failure_signals;
        let sender = connector_actor_id(FAILURE_SIGNALS_CHANNEL)?;
        if !config.exports() {
            self.keep_failure_signal_participation(sender, false, now)?;
            // Drops whatever still waits: it may not leave now.
            self.retire_failure_signal_batch(false)?;
            self.pending_code_fix_records(0)?;
            return Ok(FailureSignalDelivery::Idle);
        }
        let send = if let Some(send) = self.carried_failure_signal_batch(target, sender, now)? {
            self.keep_failure_signal_participation(sender, true, now)?;
            send
        } else {
            let counts = self.export_tier1_failure_counts()?;
            let code_fix = self.pending_code_fix_rows(max_records)?;
            if counts.is_empty() && code_fix.is_empty() {
                return Ok(FailureSignalDelivery::Idle);
            }
            self.keep_failure_signal_participation(sender, true, now)?;
            let floor = self.store.clock.ulid()?;
            let training = config.permits_training();
            let held = HeldBatch::mint(target, training, counts, code_fix, floor, now)?;
            // Staged before it leaves, so a hold the owner sees keeps its batch.
            self.stage_failure_signal_batch(&held)?;
            let request = batch_request(sender, &held, now);
            BatchSend {
                held,
                request,
                approval_digest: None,
            }
        };
        let BatchSend {
            held,
            request,
            approval_digest,
        } = send;
        let mut sink = BatchSink {
            transport,
            vault: self,
            held: &held,
            approval_digest: approval_digest.as_deref(),
            retired: Cell::new(false),
        };
        let dispatched = self.dispatch_outbound_intent_recorded(request, &mut sink);
        let retired = sink.retired.get();
        if retired {
            // Nothing left: it goes with no ack (FIX 6679).
            self.retire_failure_signal_batch(true)?;
        }
        let result = dispatched?;
        let outcome = result.outcome;
        match outcome {
            OutboundDispatchOutcome::DeliveredToChannel => {
                self.settle_failure_signal_batch(&held, true)?;
                Ok(FailureSignalDelivery::Delivered {
                    counts: held.counts.len(),
                    records: held.code_fix.len(),
                })
            }
            // A record resent carries its own id, so the publisher keeps
            // one; a count resent would count twice.
            OutboundDispatchOutcome::Ambiguous => {
                self.settle_failure_signal_batch(&held, false)?;
                Ok(FailureSignalDelivery::NotDelivered {
                    outcome,
                    approval_digest: result.approval_digest,
                })
            }
            _ => {
                if !retired {
                    match self.next_failure_signal_stage(&held, &result)? {
                        Some(stage) => self.keep_failure_signal_batch(&held, stage)?,
                        None => self.retire_failure_signal_batch(false)?,
                    }
                }
                Ok(FailureSignalDelivery::NotDelivered {
                    outcome,
                    approval_digest: result.approval_digest,
                })
            }
        }
    }

    /// Keeps the participation grant in step with the owner's switch, with
    /// no transport and no destination (FIX 1884): a deployment that stopped
    /// exporting has its grant revoked even when no sender runs, and one
    /// that exports holds one grant under the current policy. Nothing is
    /// sent, and a stopped deployment drops the batch it carried (FIX 6679).
    /// `now` is seconds since the epoch.
    ///
    /// # Errors
    ///
    /// Storage and policy errors.
    pub fn reconcile_failure_signal_participation(&self, now: u64) -> Result<()> {
        let sender = connector_actor_id(FAILURE_SIGNALS_CHANNEL)?;
        let on = self.config.failure_signals.exports();
        let _pass = self.store.diagnostics.failure_signals.lock_delivery();
        self.keep_failure_signal_participation(sender, on, now)?;
        if on {
            return Ok(());
        }
        self.retire_failure_signal_batch(false)
    }

    /// Keeps the participation grant in step with `on`: one active grant
    /// under the current policy while it holds, none once it stops. A grant
    /// a policy change left behind is revoked and minted afresh.
    fn keep_failure_signal_participation(
        &self,
        sender: EntityId,
        on: bool,
        now: u64,
    ) -> Result<()> {
        let principal = sender.to_hex();
        self.with_write_txn_grouped(|txn| {
            let floor =
                crate::gate::resolve_policy_manifest(&self.store, txn)?.read_frontier_hash()?;
            let mut current = false;
            let mut stale = Vec::new();
            for id in standing_outbound_grant_ids_for_principal(&self.store, txn, &principal)? {
                let Some(grant) = standing_outbound_grant_in_txn(&self.store, txn, &id)? else {
                    continue;
                };
                if grant.origin_component_id != PARTICIPATION_COMPONENT
                    || grant.status != StandingOutboundGrantStatus::Active
                {
                    continue;
                }
                if on && !current && grant.is_active_under_policy(&floor) {
                    current = true;
                } else {
                    stale.push((id, grant));
                }
            }
            for (id, grant) in stale {
                let data = encode_standing_outbound_grant_body(&grant.revoked(now)?)?;
                self.apply_standing_outbound_grant_body(txn, &id, now, data)?;
            }
            if on && !current {
                let grant = StandingOutboundGrant {
                    authority_scope: crate::federation::scope_codec::effect_preset(),
                    principal_ref: principal.clone(),
                    origin_component_id: PARTICIPATION_COMPONENT.to_owned(),
                    origin_action_id: PARTICIPATION_ACTION.to_owned(),
                    origin_receipt_ref: None,
                    scope: StandingOutboundGrantScope::Channel {
                        channel: FAILURE_SIGNALS_CHANNEL.to_owned(),
                    },
                    status: StandingOutboundGrantStatus::Active,
                    created_at: now,
                    revoked_at: None,
                    last_used_at: None,
                    binding_diff_handle: participation_binding_handle(&principal),
                    read_frontier_hash: floor,
                };
                grant.validate()?;
                let data = encode_standing_outbound_grant_body(&grant)?;
                self.apply_standing_outbound_grant_body(txn, &EntityId::now(), now, data)?;
            }
            Ok(())
        })
    }
}

/// Content address of the participation decision behind the grant, under
/// its own domain tag so it can never be replayed as another grant's.
fn participation_binding_handle(principal: &str) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    for part in [
        b"oneiron.gate.standing_outbound_grant.failure_signals.v1".as_slice(),
        principal.as_bytes(),
        PARTICIPATION_COMPONENT.as_bytes(),
    ] {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    hasher.finalize().as_bytes().to_vec()
}
