//! Durable e-sign transition intents cross OF-327 before edge handoff.
use super::{
    SealedItem,
    ledger::{events_in, hash, state_in},
    model::invalid,
};
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome,
    CompleteAttempt, EnqueueAttempt, FailAttempt, RetryAttempt,
};
use crate::outbound::{
    OutboundDispatchError, OutboundDispatchOutcome, OutboundDispatchRequest,
    OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink,
};
use crate::receipt::{DispatchObservationKey, append_dispatch_observation_in_txn};
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ESIGN_NOTICE_ATTEMPT_KIND: &str = "esign.notice";
/// Frozen transition intent, staged with its triggering claim. The cloud edge
/// receives the sealed artifact refs only after the email send gate allows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EsignNotice {
    pub document: String,
    pub recipient: String,
    pub email: String,
    pub transition: String,
    pub dispatch_ref: Option<String>,
    pub sealed_items: Vec<SealedItem>,
    pub principal: Option<String>,
    pub event_ref: Option<String>,
    pub generation: Option<String>,
}
fn decode(attempt: &AttemptRecord) -> Result<EsignNotice> {
    if attempt.kind != ESIGN_NOTICE_ATTEMPT_KIND {
        return Err(invalid("not an esign notice"));
    }
    let notice: EsignNotice =
        serde_json::from_slice(&attempt.payload).map_err(|_| invalid("notice schema"))?;
    if notice.dispatch_ref.is_some()
        || notice.principal.as_deref().is_none_or(str::is_empty)
        || notice.event_ref.as_deref().is_none_or(str::is_empty)
    {
        return Err(invalid("notice origin missing"));
    }
    Ok(notice)
}
struct NoticeSink<'a> {
    vault: &'a Vault,
    attempt: &'a AttemptRecord,
    notice: &'a EsignNotice,
    now: u64,
    /// The caller's credential scope, judged again in the snapshot that
    /// queues the delivery (FIX 6220, `notice_scope`).
    in_scope: &'a dyn Fn(&heed::RoTxn<'_>) -> Result<()>,
}
impl OutboundExecutionSink for NoticeSink<'_> {
    fn execute(&mut self, _request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        let result = self.vault.with_write_txn_grouped(|txn| {
            let queue = AttemptQueue::new(self.vault);
            let current = queue
                .get_in_write_txn(txn, self.attempt.id)?
                .ok_or_else(|| invalid("notice attempt missing"))?;
            if current.kind != ESIGN_NOTICE_ATTEMPT_KIND
                || current.payload != self.attempt.payload
                || current.state != AttemptState::Leased
                || current.lease_owner != self.attempt.lease_owner
                || current.attempt_count != self.attempt.attempt_count
            {
                return Err(invalid("notice lease changed"));
            }
            (self.in_scope)(txn)?;
            let document = EntityId::from_hex(&self.notice.document)?;
            let state = state_in(self.vault, txn, document)?;
            if state
                .document
                .recipients
                .iter()
                .all(|r| r.id != self.notice.recipient || r.email != self.notice.email)
            {
                return Err(invalid("notice recipient changed"));
            }
            let rows = events_in(self.vault, txn, document)?;
            if !rows.iter().any(|row| {
                hash(row).is_ok_and(|h| {
                    Some(crate::entity_id::bytes_to_hex_lower(&h)) == self.notice.event_ref
                })
            }) {
                return Err(invalid("notice event missing"));
            }
            if let Some(generation) = &self.notice.generation {
                let manifest = super::seal::CANONICAL
                    .get_bytes(&self.vault.store, txn, &document)?
                    .ok_or_else(|| invalid("notice seal missing"))?;
                let sealed: super::SealedDocument =
                    serde_json::from_slice(&manifest).map_err(|_| invalid("notice seal schema"))?;
                if &sealed.attempt_ref != generation
                    || (self.notice.transition == "completed"
                        && self.notice.sealed_items != sealed.items)
                {
                    return Err(invalid("superseded sealed notice"));
                }
            }
            crate::ports::JobQueue::port_job_enqueue(
                self.vault,
                txn,
                EnqueueAttempt {
                    kind: "esign.delivery".into(),
                    payload: self.attempt.payload.clone(),
                    dedupe_key: self.attempt.dedupe_key.clone(),
                    run_id: None,
                    now: self.now,
                },
            )?;
            Ok(())
        });
        match result {
            Ok(()) => OutboundExecutionOutcome::delivered_to_channel(format!(
                "esign-notice:{}",
                self.notice.document
            ))
            .with_receipt_field("delivery_health", "enqueued"),
            Err(_) => OutboundExecutionOutcome::failed("esign_notice_binding_or_lease_changed"),
        }
    }
}
impl Vault {
    /// Claim the next staged transition; a denied or held send never produces
    /// `esign.delivery`. The caller supplies a live OF-327 actor and grant.
    pub fn claim_esign_notice(
        &self,
        lease_owner: &str,
        now: u64,
    ) -> Result<Option<(AttemptRecord, EsignNotice)>> {
        match AttemptQueue::new(self).claim_kind(
            ESIGN_NOTICE_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: lease_owner.into(),
                now,
            },
        )? {
            ClaimOutcome::Empty => Ok(None),
            ClaimOutcome::Claimed(attempt) => {
                let notice = decode(&attempt)?;
                Ok(Some((attempt, notice)))
            }
        }
    }
    /// Authorize one frozen transition through the email OF-327 gate. A stable
    /// logical-send key survives lease retries; the request receipt id is per try.
    pub fn dispatch_esign_notice(
        &self,
        attempt: &AttemptRecord,
        request: OutboundDispatchRequest,
    ) -> std::result::Result<crate::outbound::OutboundDispatchResult, OutboundDispatchError> {
        self.dispatch_esign_notice_in_scope(attempt, request, &|_| Ok(()))
    }

    /// [`Self::dispatch_esign_notice`] for a caller whose credential scope
    /// `in_scope` judges again in the snapshot that queues the delivery
    /// (FIX 6220): one it no longer admits there is a failed send.
    pub(super) fn dispatch_esign_notice_in_scope(
        &self,
        attempt: &AttemptRecord,
        mut request: OutboundDispatchRequest,
        in_scope: &dyn Fn(&heed::RoTxn<'_>) -> Result<()>,
    ) -> std::result::Result<crate::outbound::OutboundDispatchResult, OutboundDispatchError> {
        let notice = decode(attempt)?;
        let principal = notice
            .principal
            .as_deref()
            .ok_or_else(|| invalid("notice principal"))?;
        let event_ref = notice
            .event_ref
            .as_deref()
            .ok_or_else(|| invalid("notice event"))?;
        if attempt.state != AttemptState::Leased
            || attempt.lease_owner.is_none()
            || request.intent.channel != "email"
            || request.intent.verb != "send"
            || request.intent.target != notice.email
            || request.intent.actor != principal
            || request.actor.actor_ref.as_deref() != Some(principal)
            || request.intent.on_behalf_of.is_some()
            || request.intent.intent_source != "record_transition"
            || request.intent.trigger_ref != event_ref
        {
            return Err(invalid("notice dispatch binding mismatch").into());
        }
        let logical_ref = attempt
            .dedupe_key
            .as_deref()
            .ok_or_else(|| invalid("notice key"))?;
        request.intent_ref = format!("esign-notice:{logical_ref}");
        request.ledger_identity_ref = Some(request.intent_ref.clone());
        request.intent.idempotency_key = Some(request.intent_ref.clone());
        request.intent.dedupe_key = Some(request.intent_ref.clone());
        request.intent.content_ref = Some(format!(
            "esign-notice-sha256:{}",
            crate::entity_id::bytes_to_hex_lower(&Sha256::digest(&attempt.payload))
        ));
        let actor = EntityId::from_hex(principal)?;
        if request.actor.actor_entity_ref != Some(actor) {
            return Err(invalid("notice actor entity mismatch").into());
        }
        let actor_class = match request.actor.actor_class.as_str() {
            "human" => crate::edge::EdgeActorClass::Human,
            "agent" => crate::edge::EdgeActorClass::Agent,
            "system" => crate::edge::EdgeActorClass::System,
            _ => return Err(invalid("notice actor class").into()),
        };
        let key = DispatchObservationKey {
            attempt_id: attempt.id,
            attempt_count: attempt.attempt_count,
        };
        let now = request.occurred_at;
        let preflight = || {
            // The domain seal generation is checked only for a NEW crossing;
            // OF-327 owns and validates completed-result replay first.
            if let Some(generation) = &notice.generation {
                let current = self
                    .sealed_esign_document(EntityId::from_hex(&notice.document)?)?
                    .ok_or_else(|| invalid("notice seal missing"))?;
                if &current.attempt_ref != generation {
                    AttemptQueue::new(self).fail(FailAttempt {
                        id: attempt.id,
                        lease_owner: attempt
                            .lease_owner
                            .clone()
                            .ok_or_else(|| invalid("notice lease owner"))?,
                        attempt_count: attempt.attempt_count,
                        reason: "superseded_seal".into(),
                        now,
                    })?;
                    return Err(invalid("superseded sealed notice").into());
                }
            }
            Ok(())
        };
        let recorded = self.dispatch_outbound_intent_with_recorded_observation(
            request,
            &mut NoticeSink {
                vault: self,
                attempt,
                notice: &notice,
                now,
                in_scope,
            },
            (actor, actor_class),
            key,
            preflight,
        )?;
        if recorded.replayed {
            return Ok(recorded.result);
        }
        let result = recorded.result;
        let identity = recorded.identity;
        self.with_write_txn_grouped(|txn| {
            let queue = AttemptQueue::new(self);
            let lease_owner = attempt
                .lease_owner
                .clone()
                .ok_or_else(|| invalid("notice lease owner"))?;
            match result.outcome {
                OutboundDispatchOutcome::DeliveredToChannel => {
                    queue.complete_in_txn(
                        txn,
                        CompleteAttempt {
                            id: attempt.id,
                            lease_owner,
                            attempt_count: attempt.attempt_count,
                            now,
                        },
                    )?;
                }
                OutboundDispatchOutcome::Suppressed | OutboundDispatchOutcome::LetGo => {
                    queue.fail_in_txn(
                        txn,
                        FailAttempt {
                            id: attempt.id,
                            lease_owner,
                            attempt_count: attempt.attempt_count,
                            reason: "notice_denied".into(),
                            now,
                        },
                    )?;
                }
                _ => {
                    queue.retry_in_txn(
                        txn,
                        RetryAttempt {
                            id: attempt.id,
                            lease_owner,
                            attempt_count: attempt.attempt_count,
                            backoff_until: now.saturating_add(60),
                            last_error: Some("notice_not_dispatched".into()),
                            now,
                        },
                    )?;
                }
            }
            append_dispatch_observation_in_txn(self, txn, key, identity, &result)?;
            Ok(result)
        })
        .map_err(Into::into)
    }
}

/// How long a door claim of a notice stays leased before the same
/// principal's next `vault.esign.notices.dispatch` on its document takes it
/// back: the e-sign delivery outbox's no-ack lease, reused. A host restart
/// requeues it sooner, with every lease a stopped process held.
pub(super) const NOTICE_LEASE_SECS: u64 = 300;

/// The lease-owner prefix of every door claim made for `principal`. A call
/// leases as this prefix and its own nonce, so no call releases another's
/// live lease.
pub(super) fn notice_lease_prefix(principal: EntityId) -> String {
    format!("esign-notice:{}:", principal.to_hex())
}

/// Where a scoped claim found one staged notice.
pub(super) enum ScopedNotice {
    /// Leased to this call: its try's lease is stamped.
    Claimed(Box<AttemptRecord>, EsignNotice),
    /// Staged but not due: a retry's backoff, or a queue hold.
    NotDue(EsignNotice),
    /// Leased by another call of the same principal's that still holds it.
    InFlight(EsignNotice),
    /// Settled, or no longer this principal's, since it was listed.
    Gone,
}

/// The notice `row` stages when it is `document`'s and recorded for
/// `principal`; any other row is `None`.
fn scoped(row: &AttemptRecord, document: EntityId, principal: EntityId) -> Option<EsignNotice> {
    let notice = decode(row).ok()?;
    let principal_matches = notice
        .principal
        .as_deref()
        .and_then(|recorded| EntityId::from_hex(recorded).ok())
        == Some(principal);
    let document_matches = EntityId::from_hex(&notice.document).is_ok_and(|d| d == document);
    (principal_matches && document_matches).then_some(notice)
}

/// `document`'s unsettled staged notices recorded for `principal`, in queue
/// order. A read only: each row is read again under the writer that claims
/// or recovers it.
pub(super) fn principal_notices(
    vault: &Vault,
    document: EntityId,
    principal: EntityId,
) -> Result<Vec<AttemptRecord>> {
    Ok(AttemptQueue::new(vault)
        .list_kind_bounded(ESIGN_NOTICE_ATTEMPT_KIND, usize::MAX)?
        .into_iter()
        .filter(|row| !row.state.is_terminal() && scoped(row, document, principal).is_some())
        .collect())
}

/// Returns one of `principal`'s door claims on `document` that a failed call
/// left leased to the queue as the same try, once its lease ran
/// [`NOTICE_LEASE_SECS`] on the recorded clock: `true` when it did. A live
/// claim, and a claim of any other principal, document or worker, stays.
pub(super) fn recover_notice_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: AttemptId,
    document: EntityId,
    principal: EntityId,
) -> Result<bool> {
    let queue = AttemptQueue::new(vault);
    let Some(row) = queue.get_in_write_txn(txn, id)? else {
        return Ok(false);
    };
    let prefix = notice_lease_prefix(principal);
    let Some(owner) = row
        .lease_owner
        .clone()
        .filter(|owner| owner.starts_with(&prefix))
    else {
        return Ok(false);
    };
    if row.state != AttemptState::Leased || scoped(&row, document, principal).is_none() {
        return Ok(false);
    }
    let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    if now.saturating_sub(row.updated_at) < NOTICE_LEASE_SECS {
        return Ok(false);
    }
    queue.release_lease_in_txn(txn, id, &owner, now)
}

/// Leases one of `document`'s staged notices recorded for `principal` to
/// `lease_owner` through the queue's own point-claim (readiness, placement,
/// holds and lease admission), after reading the row and its binding again
/// under this writer.
pub(super) fn claim_notice_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: AttemptId,
    document: EntityId,
    principal: EntityId,
    lease_owner: &str,
) -> Result<ScopedNotice> {
    let queue = AttemptQueue::new(vault);
    let Some(row) = queue.get_in_write_txn(txn, id)? else {
        return Ok(ScopedNotice::Gone);
    };
    let Some(notice) = scoped(&row, document, principal) else {
        return Ok(ScopedNotice::Gone);
    };
    match row.state {
        AttemptState::Queued | AttemptState::Scheduled => {}
        AttemptState::Leased | AttemptState::Landing => {
            return Ok(ScopedNotice::InFlight(notice));
        }
        AttemptState::Paused => return Ok(ScopedNotice::NotDue(notice)),
        AttemptState::Completed
        | AttemptState::Failed
        | AttemptState::Cancelled
        | AttemptState::Abandoned => return Ok(ScopedNotice::Gone),
    }
    let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    match queue.claim_id_in_txn(
        txn,
        id,
        ClaimAttempt {
            lease_owner: lease_owner.into(),
            now,
        },
    )? {
        ClaimOutcome::Claimed(attempt) => Ok(ScopedNotice::Claimed(Box::new(attempt), notice)),
        ClaimOutcome::Empty => Ok(ScopedNotice::NotDue(notice)),
    }
}
