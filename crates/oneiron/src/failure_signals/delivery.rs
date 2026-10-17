//! Delivery of the failure-signal exports to the deployment's publisher
//! (OF-380). One batch carries the tier-1 counts and the sealed code-fix
//! records; it leaves as an ordinary outbound effect on the
//! `failure_signals/send` capability, through the dispatch pipeline and its
//! recorded receipt. What the batch held is acked only once it was
//! delivered, so a failed send loses nothing.
//!
//! Consent is the deployment's participation
//! ([`FailureSignalConfig::exports`](crate::config::failure_signals::FailureSignalConfig::exports)):
//! the managed terms, or the self-host owner's opt-in. While it holds, the
//! vault keeps one standing channel grant for the sender's own derived
//! principal, so the gate admits a batch without a per-send ask; once it
//! stops, the grant is revoked and nothing is sent. Owner feedback's
//! per-send approval is never involved.
//!
//! The engine names no publisher. The host supplies the destination and the
//! transport that carries the bytes.

use serde::{Deserialize, Serialize};

use super::Tier1FailureCount;
use super::code_fix::CodeFixExport;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
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
    NotDelivered { outcome: OutboundDispatchOutcome },
}

struct BatchSink<'a, T: ?Sized> {
    transport: &'a mut T,
    body: &'a [u8],
    digest: &'a str,
}

impl<T: FailureSignalTransport + ?Sized> OutboundExecutionSink for BatchSink<'_, T> {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.transport
            .send_failure_signals(&FailureSignalTransportRequest {
                execution: request,
                body: self.body,
                digest: self.digest,
            })
            .with_receipt_field("failure_signals_batch_digest", self.digest)
    }
}

impl Vault {
    /// Sends one batch to `target`, the publisher's exact endpoint: every
    /// tier-1 count since the last delivery and up to `max_records` sealed
    /// code-fix records. `now` is seconds since the epoch.
    pub fn deliver_failure_signals(
        &self,
        target: &str,
        max_records: usize,
        now: u64,
        transport: &mut dyn FailureSignalTransport,
    ) -> std::result::Result<FailureSignalDelivery, OutboundDispatchError> {
        let config = self.config.failure_signals;
        let sender = connector_actor_id(FAILURE_SIGNALS_CHANNEL)?;
        if !config.exports() {
            self.keep_failure_signal_participation(sender, false, now)?;
            // Drops whatever still waits: it may not leave now.
            self.pending_code_fix_records(0)?;
            return Ok(FailureSignalDelivery::Idle);
        }
        let counts = self.export_tier1_failure_counts()?;
        let code_fix = self.pending_code_fix_records(max_records)?;
        if counts.is_empty() && code_fix.is_empty() {
            return Ok(FailureSignalDelivery::Idle);
        }
        self.keep_failure_signal_participation(sender, true, now)?;

        let mut id = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut id);
        let batch = FailureSignalBatch {
            version: FAILURE_SIGNAL_BATCH_VERSION,
            batch_id: bytes_to_hex_lower(&id),
            training_permitted: config.permits_training(),
            counts,
            code_fix,
        };
        let body = serde_json::to_vec(&batch)
            .map_err(|_| crate::Error::InvariantViolation("failure signal batch encode"))?;
        let digest = blake3::hash(&body).to_hex().to_string();
        let send_ref = format!("failure_signals:batch:{}", batch.batch_id);
        let intent = OutboundIntent::from_trigger(
            OutboundIntentDraft::new(
                sender.to_hex(),
                FAILURE_SIGNALS_SEND_VERB,
                FAILURE_SIGNALS_CHANNEL,
                target,
            )
            .content_ref(format!("failure_signals:digest:{digest}"))
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
        let mut sink = BatchSink {
            transport,
            body: &body,
            digest: &digest,
        };
        let outcome = self
            .dispatch_outbound_intent_recorded(request, &mut sink)?
            .outcome;
        let ids = batch
            .code_fix
            .iter()
            .map(CodeFixExport::id)
            .collect::<Vec<_>>();
        match outcome {
            OutboundDispatchOutcome::DeliveredToChannel => {
                self.ack_tier1_failure_counts(&batch.counts)?;
                self.ack_code_fix_records(&ids)?;
                Ok(FailureSignalDelivery::Delivered {
                    counts: batch.counts.len(),
                    records: ids.len(),
                })
            }
            // A record resent carries its own id, so the publisher keeps
            // one; a count resent would count twice.
            OutboundDispatchOutcome::Ambiguous => {
                self.ack_tier1_failure_counts(&batch.counts)?;
                Ok(FailureSignalDelivery::NotDelivered { outcome })
            }
            _ => Ok(FailureSignalDelivery::NotDelivered { outcome }),
        }
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
