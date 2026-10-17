//! A trusted-contact notice crosses the OF-327 outbound rails like any other
//! engine-staged send: staged with the transition that fired it, claimed by
//! the host's worker, and sent through the ordinary dispatch with the host's
//! transport. The contact's live consent is read again at each of those steps,
//! the last one under the lock a revocation takes, so a send never starts
//! after a revocation has returned.
//!
//! The notice is a fact, not a message: it carries no text. The host renders
//! its own fixed check-in wording for it, the same every time.

use std::sync::{PoisonError, RwLockReadGuard, RwLockWriteGuard};

use serde::{Deserialize, Serialize};

use super::trusted_contact::{RELATIONS, TrustedContact, invalid};
use crate::attempt_queue::{
    AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome, CompleteAttempt,
    EnqueueAttempt, EnqueueOutcome, FailAttempt, RetryAttempt,
};
use crate::edge::EdgeActorClass;
use crate::outbound::{
    OutboundDispatchActor, OutboundDispatchError, OutboundDispatchOutcome, OutboundDispatchRequest,
    OutboundDispatchResult, OutboundExecutionOutcome, OutboundExecutionRequest,
    OutboundExecutionSink, OutboundIntent, OutboundIntentDraft, OutboundIntentTrigger,
};
use crate::receipt::{DispatchObservationKey, append_dispatch_observation_in_txn};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

pub const TRUSTED_CONTACT_NOTICE_ATTEMPT_KIND: &str = "trusted_contact.notice";

/// The content a notice's send carries: the fact of concern, which the
/// host's adapter renders as its fixed check-in line.
pub const TRUSTED_CONTACT_NOTICE_CONTENT_REF: &str = "trusted-contact-notice:fact_of_concern";

/// Every notice the engine staged, by its fire ref. Only the staging door
/// writes it, so a notice queued any other way is no notice.
const FIRES: SideTable<EntityId, TrustedContactNotice, Named> =
    SideTable::new(&side_table::TRUSTED_CONTACT_FIRE);

/// Orders a send's last consent read and its transport against revocation
/// and re-naming on this vault: a revocation waits for a send already under
/// way, and no send starts once it has returned.
pub(super) fn consent_change_guard(vault: &Vault) -> RwLockWriteGuard<'_, ()> {
    vault
        .trusted_contact_send_order
        .write()
        .unwrap_or_else(PoisonError::into_inner)
}

fn send_guard(vault: &Vault) -> RwLockReadGuard<'_, ()> {
    vault
        .trusted_contact_send_order
        .read()
        .unwrap_or_else(PoisonError::into_inner)
}

/// Everything the host needs to send one notice, and nothing from the turn,
/// the verdict, the policy row or its tier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedContactNotice {
    /// The send's own ref: one per fire, so a later crisis is a new send and
    /// never the replay of an old one.
    pub fire: String,
    pub person: String,
    pub contact: String,
    pub version: u64,
    pub sender: String,
    pub channel: String,
    pub verb: String,
    pub target: String,
}

/// Stages one notice from `relation` in the transaction that fired it. While
/// one waits for this naming, another collapses into it; a notice for an
/// earlier naming never stands in for it.
pub(super) fn stage_notice_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    relation: &TrustedContact,
    fire: EntityId,
    now: u64,
) -> Result<()> {
    let notice = TrustedContactNotice {
        fire: fire.to_hex(),
        person: relation.person.to_hex(),
        contact: relation.contact.to_hex(),
        version: relation.version,
        sender: relation.reach.sender.to_hex(),
        channel: relation.reach.channel.clone(),
        verb: relation.reach.verb.clone(),
        target: relation.reach.target.clone(),
    };
    let payload = serde_json::to_vec(&notice).map_err(|_| invalid("notice encoding"))?;
    let staged = crate::ports::JobQueue::port_job_enqueue(
        vault,
        wtxn,
        EnqueueAttempt {
            kind: TRUSTED_CONTACT_NOTICE_ATTEMPT_KIND.into(),
            payload,
            dedupe_key: Some(format!(
                "trusted-contact:{}:{}:{}",
                notice.person, notice.contact, notice.version
            )),
            run_id: None,
            now,
        },
    )?;
    if let EnqueueOutcome::Enqueued(_) = staged {
        FIRES.put(&vault.store, wtxn, &fire, &notice)?;
    }
    Ok(())
}

fn decode(attempt: &AttemptRecord) -> Result<TrustedContactNotice> {
    if attempt.kind != TRUSTED_CONTACT_NOTICE_ATTEMPT_KIND {
        return Err(invalid("not a trusted-contact notice"));
    }
    serde_json::from_slice(&attempt.payload).map_err(|_| invalid("notice schema"))
}

impl Vault {
    /// Whether `notice` is one the engine staged, from a relation that still
    /// stands as it was then: the same naming, reach and sender, both sides'
    /// consent, the contact an adult, neither revoked.
    fn trusted_contact_notice_is_live(&self, notice: &TrustedContactNotice) -> Result<bool> {
        let fire = EntityId::from_hex(&notice.fire)?;
        let key = (
            EntityId::from_hex(&notice.person)?,
            EntityId::from_hex(&notice.contact)?,
        );
        let rtxn = self.store.env.read_txn()?;
        if FIRES.get(&self.store, &rtxn, &fire)?.as_ref() != Some(notice) {
            return Ok(false);
        }
        Ok(RELATIONS
            .get(&self.store, &rtxn, &key)?
            .is_some_and(|relation| {
                relation.is_live()
                    && relation.version == notice.version
                    && relation.reach.sender.to_hex() == notice.sender
                    && relation.reach.channel == notice.channel
                    && relation.reach.verb == notice.verb
                    && relation.reach.target == notice.target
            }))
    }

    /// The stored attempt, when it is still the one `attempt` names, leased
    /// as it was.
    fn leased_trusted_contact_notice(&self, attempt: &AttemptRecord) -> Result<AttemptRecord> {
        AttemptQueue::new(self)
            .get(attempt.id)?
            .filter(|stored| {
                stored.kind == TRUSTED_CONTACT_NOTICE_ATTEMPT_KIND
                    && stored.payload == attempt.payload
                    && stored.state == AttemptState::Leased
                    && stored.lease_owner.is_some()
                    && stored.lease_owner == attempt.lease_owner
                    && stored.attempt_count == attempt.attempt_count
            })
            .ok_or_else(|| invalid("notice lease changed"))
    }

    fn fail_trusted_contact_notice(
        &self,
        attempt: &AttemptRecord,
        reason: &str,
        now: u64,
    ) -> Result<()> {
        AttemptQueue::new(self).fail(FailAttempt {
            id: attempt.id,
            lease_owner: attempt
                .lease_owner
                .clone()
                .ok_or_else(|| invalid("notice lease owner"))?,
            attempt_count: attempt.attempt_count,
            reason: reason.into(),
            now,
        })?;
        Ok(())
    }

    /// Claims the next staged notice that is still live. One the engine did
    /// not stage, or whose contact has withdrawn, is failed here, unseen by
    /// the host.
    pub fn claim_trusted_contact_notice(
        &self,
        lease_owner: &str,
        now: u64,
    ) -> Result<Option<(AttemptRecord, TrustedContactNotice)>> {
        loop {
            let claimed = AttemptQueue::new(self).claim_kind(
                TRUSTED_CONTACT_NOTICE_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: lease_owner.into(),
                    now,
                },
            )?;
            let ClaimOutcome::Claimed(attempt) = claimed else {
                return Ok(None);
            };
            match decode(&attempt) {
                Ok(notice) if self.trusted_contact_notice_is_live(&notice)? => {
                    return Ok(Some((attempt, notice)));
                }
                _ => self.fail_trusted_contact_notice(&attempt, "consent_not_live", now)?,
            }
        }
    }

    /// Sends one claimed notice through the OF-327 dispatch, from its sender
    /// to its target, with `sink` as the transport. The host's request must
    /// carry the notice's binding; only its receipt id, gate answer, clock,
    /// delivery window, sending identity and actor class are kept, and the
    /// request sent is built from the stored notice, so nothing else the
    /// host attached reaches the contact. The contact's consent is read again
    /// before the gate and again just before `sink` runs.
    pub fn dispatch_trusted_contact_notice<S: OutboundExecutionSink>(
        &self,
        attempt: &AttemptRecord,
        request: OutboundDispatchRequest,
        sink: &mut S,
    ) -> std::result::Result<OutboundDispatchResult, OutboundDispatchError> {
        let attempt = self.leased_trusted_contact_notice(attempt)?;
        let attempt = &attempt;
        let notice = decode(attempt)?;
        let sender = EntityId::from_hex(&notice.sender)?;
        if request.intent.channel != notice.channel
            || request.intent.verb != notice.verb
            || request.intent.target != notice.target
            || request.intent.actor != notice.sender
            || request.actor.actor_ref.as_deref() != Some(notice.sender.as_str())
            || request.actor.actor_entity_ref != Some(sender)
            || request.intent.on_behalf_of.is_some()
            || request.intent.intent_source != "record_transition"
            || request.intent.trigger_ref != notice.fire
        {
            return Err(invalid("notice dispatch binding mismatch").into());
        }
        let actor_class = match request.actor.actor_class.as_str() {
            "human" => EdgeActorClass::Human,
            "agent" => EdgeActorClass::Agent,
            "system" => EdgeActorClass::System,
            _ => return Err(invalid("notice actor class").into()),
        };
        let intent_ref = format!("trusted-contact-notice:{}", notice.fire);
        let mut outgoing = OutboundDispatchRequest::new(
            request.receipt_id,
            intent_ref.clone(),
            OutboundIntent::from_trigger(
                OutboundIntentDraft {
                    actor: notice.sender.clone(),
                    on_behalf_of: None,
                    verb: notice.verb.clone(),
                    channel: notice.channel.clone(),
                    target: notice.target.clone(),
                    content_ref: Some(TRUSTED_CONTACT_NOTICE_CONTENT_REF.to_owned()),
                    idempotency_key: Some(intent_ref.clone()),
                    dedupe_key: Some(intent_ref.clone()),
                    mention: None,
                },
                OutboundIntentTrigger::record_transition(notice.fire.clone()),
            ),
            OutboundDispatchActor {
                actor_class: request.actor.actor_class,
                actor_ref: Some(notice.sender.clone()),
                actor_entity_ref: Some(sender),
            },
            request.gate,
            request.occurred_at,
            request.window_decision,
        );
        outgoing.ledger_identity_ref = Some(intent_ref);
        outgoing.channel_identity_ref = request.channel_identity_ref;
        let key = DispatchObservationKey {
            attempt_id: attempt.id,
            attempt_count: attempt.attempt_count,
        };
        let now = outgoing.occurred_at;
        let preflight = || {
            if !self.trusted_contact_notice_is_live(&notice)? {
                self.fail_trusted_contact_notice(attempt, "consent_not_live", now)?;
                return Err(invalid("the trusted contact's consent is not live").into());
            }
            Ok(())
        };
        let recorded = self.dispatch_outbound_intent_with_recorded_observation(
            outgoing,
            &mut LiveConsentSink {
                vault: self,
                attempt,
                notice: &notice,
                transport: sink,
            },
            (sender, actor_class),
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
            append_dispatch_observation_in_txn(&self.store, txn, key, identity, &result)?;
            Ok(result)
        })
        .map_err(Into::into)
    }
}

/// The host's transport, behind one last read of the contact's consent and
/// of the notice's lease, held under the vault's send order until the
/// transport returns.
struct LiveConsentSink<'a, S> {
    vault: &'a Vault,
    attempt: &'a AttemptRecord,
    notice: &'a TrustedContactNotice,
    transport: &'a mut S,
}

impl<S: OutboundExecutionSink> OutboundExecutionSink for LiveConsentSink<'_, S> {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        let _order = send_guard(self.vault);
        let live = self
            .vault
            .leased_trusted_contact_notice(self.attempt)
            .and_then(|_| self.vault.trusted_contact_notice_is_live(self.notice));
        match live {
            Ok(true) => self.transport.execute(request),
            Ok(false) | Err(_) => {
                OutboundExecutionOutcome::failed("trusted_contact_consent_not_live")
            }
        }
    }
}
