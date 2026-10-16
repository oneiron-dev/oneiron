//! A trusted-contact notice crosses the OF-327 outbound rails like any other
//! engine-staged send: staged with the transition that fired it, claimed by
//! the host's worker, and sent through the ordinary dispatch with the host's
//! transport. The contact's live consent is read again at each of those steps,
//! the last one just before the transport runs.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::trusted_contact::{RELATIONS, TrustedContact, invalid};
use crate::attempt_queue::{
    AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome, CompleteAttempt,
    EnqueueAttempt, FailAttempt, RetryAttempt,
};
use crate::edge::EdgeActorClass;
use crate::outbound::{
    OutboundDispatchError, OutboundDispatchOutcome, OutboundDispatchRequest,
    OutboundDispatchResult, OutboundExecutionOutcome, OutboundExecutionRequest,
    OutboundExecutionSink,
};
use crate::receipt::{DispatchObservationKey, append_dispatch_observation_in_txn};
use crate::{EntityId, Result, Vault};

pub const TRUSTED_CONTACT_NOTICE_ATTEMPT_KIND: &str = "trusted_contact.notice";

/// Everything the host needs to send one notice, and nothing from the turn,
/// the verdict, the policy row or its tier: `text` is the notice the person
/// wrote when they named the contact.
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
    pub text: String,
}

/// Stages one notice from `relation` in the transaction that fired it. While
/// one is waiting for the relation, another collapses into it.
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
        text: relation.notice.clone(),
    };
    let payload = serde_json::to_vec(&notice).map_err(|_| invalid("notice encoding"))?;
    crate::ports::JobQueue::port_job_enqueue(
        vault,
        wtxn,
        EnqueueAttempt {
            kind: TRUSTED_CONTACT_NOTICE_ATTEMPT_KIND.into(),
            payload,
            dedupe_key: Some(format!(
                "trusted-contact:{}:{}",
                notice.person, notice.contact
            )),
            run_id: None,
            now,
        },
    )?;
    Ok(())
}

fn decode(attempt: &AttemptRecord) -> Result<TrustedContactNotice> {
    if attempt.kind != TRUSTED_CONTACT_NOTICE_ATTEMPT_KIND {
        return Err(invalid("not a trusted-contact notice"));
    }
    serde_json::from_slice(&attempt.payload).map_err(|_| invalid("notice schema"))
}

impl Vault {
    /// Whether the relation `notice` was staged from still stands at the same
    /// version: both sides' consent, the contact an adult, neither revoked.
    /// The version pins the reach, the sender and the text.
    fn trusted_contact_notice_is_live(&self, notice: &TrustedContactNotice) -> Result<bool> {
        let key = (
            EntityId::from_hex(&notice.person)?,
            EntityId::from_hex(&notice.contact)?,
        );
        let rtxn = self.store.env.read_txn()?;
        Ok(RELATIONS
            .get(&self.store, &rtxn, &key)?
            .is_some_and(|relation| relation.is_live() && relation.version == notice.version))
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

    /// Claims the next staged notice whose relation is still live. A notice
    /// whose contact has withdrawn is failed here, unseen by the host.
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
            let notice = decode(&attempt)?;
            if self.trusted_contact_notice_is_live(&notice)? {
                return Ok(Some((attempt, notice)));
            }
            self.fail_trusted_contact_notice(&attempt, "consent_not_live", now)?;
        }
    }

    /// Sends one claimed notice through the OF-327 dispatch, from its sender
    /// to its target, with `sink` as the transport. The request must carry
    /// exactly the notice's binding. The contact's consent is read again
    /// before the gate and again just before `sink` runs.
    pub fn dispatch_trusted_contact_notice<S: OutboundExecutionSink>(
        &self,
        attempt: &AttemptRecord,
        mut request: OutboundDispatchRequest,
        sink: &mut S,
    ) -> std::result::Result<OutboundDispatchResult, OutboundDispatchError> {
        let notice = decode(attempt)?;
        let sender = EntityId::from_hex(&notice.sender)?;
        if attempt.state != AttemptState::Leased
            || attempt.lease_owner.is_none()
            || request.intent.channel != notice.channel
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
        request.intent_ref = format!("trusted-contact-notice:{}", notice.fire);
        request.ledger_identity_ref = Some(request.intent_ref.clone());
        request.intent.idempotency_key = Some(request.intent_ref.clone());
        request.intent.dedupe_key = Some(request.intent_ref.clone());
        request.intent.content_ref = Some(format!(
            "trusted-contact-notice-sha256:{}",
            crate::entity_id::bytes_to_hex_lower(&Sha256::digest(notice.text.as_bytes()))
        ));
        let actor_class = match request.actor.actor_class.as_str() {
            "human" => EdgeActorClass::Human,
            "agent" => EdgeActorClass::Agent,
            "system" => EdgeActorClass::System,
            _ => return Err(invalid("notice actor class").into()),
        };
        let key = DispatchObservationKey {
            attempt_id: attempt.id,
            attempt_count: attempt.attempt_count,
        };
        let now = request.occurred_at;
        let preflight = || {
            if !self.trusted_contact_notice_is_live(&notice)? {
                self.fail_trusted_contact_notice(attempt, "consent_not_live", now)?;
                return Err(invalid("the trusted contact's consent is not live").into());
            }
            Ok(())
        };
        let recorded = self.dispatch_outbound_intent_with_recorded_observation(
            request,
            &mut LiveConsentSink {
                vault: self,
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

/// The host's transport, behind one last read of the contact's consent: a
/// revocation that committed while the send waited for the gate stops it here.
struct LiveConsentSink<'a, S> {
    vault: &'a Vault,
    notice: &'a TrustedContactNotice,
    transport: &'a mut S,
}

impl<S: OutboundExecutionSink> OutboundExecutionSink for LiveConsentSink<'_, S> {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        match self.vault.trusted_contact_notice_is_live(self.notice) {
            Ok(true) => self.transport.execute(request),
            Ok(false) | Err(_) => {
                OutboundExecutionOutcome::failed("trusted_contact_consent_not_live")
            }
        }
    }
}
