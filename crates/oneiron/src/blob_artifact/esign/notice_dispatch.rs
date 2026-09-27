//! Durable e-sign transition intents cross OF-327 before edge handoff.
use super::{
    SealedItem,
    ledger::{events_in, hash, state_in},
    model::invalid,
};
use crate::attempt_queue::{
    AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome, CompleteAttempt,
    EnqueueAttempt, FailAttempt, RetryAttempt,
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
}
impl OutboundExecutionSink for NoticeSink<'_> {
    fn execute(&mut self, _request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        let result = self.vault.with_write_txn(|txn| {
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
            queue.enqueue_in_txn(
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
        mut request: OutboundDispatchRequest,
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
        self.with_write_txn(|txn| {
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
            append_dispatch_observation_in_txn(&self.store, txn, key, identity, &result)?;
            Ok(result)
        })
        .map_err(Into::into)
    }
}
