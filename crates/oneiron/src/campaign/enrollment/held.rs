//! Campaign enrollment held loop: observe Gate holds, ask the owner once, press to redrive.

use super::approval::{RETAINED, RetainedKey, RetainedRequest, decode_request};
use super::outbound_leg::{CampaignApprovalSnapshot, campaign_approval_snapshot_in_txn};
use super::runner::decode_enrollment_attempt_payload;
use super::storage::CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND;
use crate::Vault;
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, EnqueueAttempt, EnqueueOutcome,
};
use crate::consent::{AuthenticatedOwner, ConsentReceipt};
use crate::entity_id::EntityId;
use crate::gate::{CampaignLegFacts, GateReasonCode};
use crate::llm::decision::{AskTo, HumanDecisionRequest};
use crate::model_decision::{
    AnswerContract, DecisionClass, DecisionQuestion, DecisionRung, HumanAskReason, ProviderPin,
};
use crate::outbound_chokepoint::OutboundEffectResult;
use crate::outbound_intent_ledger::IntentLedgerError;

const HELD_CALL_REF_DOMAIN: &[u8] = b"oneiron.campaign.enrollment.held.call_ref.v1";
const HELD_QUESTION_DOMAIN: &[u8] = b"oneiron.campaign.enrollment.held.question.v1";
const APPROVED_DEDUPE_DOMAIN: &[u8] = b"oneiron.campaign.enrollment.approved.v1";

#[derive(Debug, Clone)]
pub(super) struct PreparedHeldRequest {
    pub(super) key: RetainedKey,
    pub(super) owner_actor: EntityId,
    pub(super) envelope_hash: [u8; 32],
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HeldEnrollmentCall {
    pub(super) owner_actor: EntityId,
    pub(super) frozen_event_ref: EntityId,
    pub(super) attempt_ref: AttemptId,
    pub(super) payload: Vec<u8>,
    pub(super) task_ref: Option<String>,
    pub(super) run_id: Option<String>,
    pub(super) dedupe_actor_ref: Option<String>,
    pub(super) envelope_hash: [u8; 32],
    pub(super) approval_digest: String,
    pub(super) approval_actor: Option<EntityId>,
    pub(super) held_at_ms: u64,
    pub(super) gate_reason_codes: Vec<String>,
    pub(super) gate_receipt_reasons: Vec<String>,
    pub(super) owner_ask_seq: Option<u64>,
    pub(super) approved_redrive: Option<AttemptId>,
}

impl HeldEnrollmentCall {
    pub(super) fn references_actor(&self, actor: &EntityId) -> bool {
        self.owner_actor == *actor
            || self.frozen_event_ref == *actor
            || self.attempt_ref.as_bytes() == actor.as_bytes()
            || self
                .approved_redrive
                .as_ref()
                .is_some_and(|id| id.as_bytes() == actor.as_bytes())
            || decode_enrollment_attempt_payload(&self.payload).is_ok_and(|payload| {
                payload.membership_event_ref == *actor
                    || payload.campaign_program_ref == *actor
                    || payload.program_step_ref == *actor
            })
    }
}

fn held_call_ref(key: &RetainedKey) -> std::result::Result<EntityId, IntentLedgerError> {
    let seq = key.1.to_be_bytes();
    EntityId::derive(HELD_CALL_REF_DOMAIN, &[&key.0[..], &seq[..], &key.2[..]])
        .map_err(|_| IntentLedgerError::InvalidRecord("campaign held call ref"))
}

fn held_question_id(
    call_ref: &EntityId,
    approval_digest: &str,
) -> std::result::Result<EntityId, IntentLedgerError> {
    EntityId::derive(
        HELD_QUESTION_DOMAIN,
        &[&call_ref.as_bytes()[..], approval_digest.as_bytes()],
    )
    .map_err(|_| IntentLedgerError::InvalidRecord("campaign held question"))
}

fn approved_dedupe_key(call_ref: &EntityId, reviewed: &str, decision_id: [u8; 16]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(APPROVED_DEDUPE_DOMAIN);
    hasher.update(call_ref.as_bytes());
    hasher.update(&(reviewed.len() as u64).to_be_bytes());
    hasher.update(reviewed.as_bytes());
    hasher.update(&decision_id);
    let hash = hasher.finalize();
    format!(
        "campaign.enrollment.approved.v1:{}",
        crate::entity_id::bytes_to_hex_lower(hash.as_bytes())
    )
}

fn hold_erased_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &RetainedKey,
    request: &RetainedRequest,
    snapshot: &CampaignApprovalSnapshot,
    payload: &super::runner::CampaignEnrollmentAttemptPayload,
    attempt_ref: &AttemptId,
) -> std::result::Result<bool, IntentLedgerError> {
    let (facts, first_event_ref) = decode_request(key, request)
        .ok_or(IntentLedgerError::InvalidRecord("campaign held request"))?;
    let consequence_id = AttemptId::from_bytes(&key.0)
        .map_err(|_| IntentLedgerError::InvalidRecord("campaign held key"))?;
    if crate::outbound_intent_ledger::call_row_erased_in_txn(vault, txn, consequence_id, key.1)? {
        return Ok(true);
    }
    let attempt_id = EntityId::from_bytes(*attempt_ref.as_bytes())?;
    for id in [
        facts.query_ref,
        facts.campaign_ref,
        facts.entity_ref,
        facts.program_ref,
        facts.step_ref,
        first_event_ref,
        snapshot.sender_ref,
        snapshot.owner_actor,
        snapshot.event_ref,
        payload.membership_event_ref,
        attempt_id,
    ] {
        if vault.local_hard_delete_marker_exists_in_txn(txn, &id)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn queue_held_owner_ask_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &RetainedKey,
    facts: &CampaignLegFacts,
    held: &HeldEnrollmentCall,
) -> std::result::Result<u64, IntentLedgerError> {
    let call_ref = held_call_ref(key)?;
    let question_id = held_question_id(&call_ref, held.approval_digest.as_str())?;
    let evidence = vec![
        facts.query_ref,
        facts.campaign_ref,
        facts.entity_ref,
        facts.program_ref,
        facts.step_ref,
        held.frozen_event_ref,
    ];
    // ARCH-0059 #copy-review: a copy-review hold states the campaign's
    // review mode and the judge's reason class, so the owner sees what holds it.
    let copy_review = if held
        .gate_reason_codes
        .iter()
        .any(|code| code == GateReasonCode::PendingCampaignCopyReview.as_str())
    {
        super::copy_review::copy_review_ask_state_in_txn(
            &vault.store,
            txn,
            facts.campaign_ref,
            facts.payload_digest,
        )?
    } else {
        None
    };
    let state = serde_json::json!({
        "call_ref": crate::entity_id::bytes_to_hex_lower(call_ref.as_bytes()),
        "consequence": crate::entity_id::bytes_to_hex_lower(&key.0),
        "call_seq": key.1,
        "query_ref": facts.query_ref.to_hex(),
        "campaign_ref": facts.campaign_ref.to_hex(),
        "member_ref": facts.entity_ref.to_hex(),
        "program_ref": facts.program_ref.to_hex(),
        "step_ref": facts.step_ref.to_hex(),
        "owner_actor": held.owner_actor.to_hex(),
        "frozen_event_ref": held.frozen_event_ref.to_hex(),
        "attempt_ref": crate::entity_id::bytes_to_hex_lower(held.attempt_ref.as_bytes()),
        "approval_digest": &held.approval_digest,
        "approval_actor": held.approval_actor.as_ref().map(|actor| actor.to_hex()),
        "envelope_hash": crate::entity_id::bytes_to_hex_lower(&held.envelope_hash),
        "gate_reason_codes": &held.gate_reason_codes,
        "gate_receipt_reasons": &held.gate_receipt_reasons,
        "copy_review": copy_review,
    });
    let text = serde_json::to_string(&state)
        .map_err(|_| IntentLedgerError::InvalidRecord("campaign held ask"))?;
    let request = HumanDecisionRequest {
        question: DecisionQuestion {
            id: question_id,
            version: 1,
            text,
            class: DecisionClass::Judgment,
            contract: AnswerContract::Noul,
            accept_type: false,
        },
        principal: held.owner_actor,
        evidence,
        reason: HumanAskReason::OwnerSelected,
        prior: None,
        prior_provider: None,
        queue_pin: ProviderPin {
            rung: DecisionRung::Human,
            model: "campaign.enrollment.held".to_owned(),
            version: "v1".to_owned(),
        },
        to: AskTo::owner(),
        correlation: Some(call_ref),
    };
    Ok(vault.queue_decision_ask_in_txn(txn, &request, Some(&state))?)
}

pub(super) fn observe_outbound_result(
    vault: &Vault,
    attempt: &AttemptRecord,
    prepared: &PreparedHeldRequest,
    result: &OutboundEffectResult,
    now_ms: u64,
) {
    let outcome: std::result::Result<(), IntentLedgerError> = vault.try_with_write_txn(|txn| {
        let existing: Option<RetainedRequest> = RETAINED.get(&vault.store, txn, &prepared.key)?;
        let Some(existing) = existing else {
            return Ok(());
        };
        let Some((facts, _)) = decode_request(&prepared.key, &existing) else {
            return Ok(());
        };
        if let Some(approval_digest) = result.approval_digest.as_ref() {
            let payload = decode_enrollment_attempt_payload(&attempt.payload)?;
            let snapshot: Option<CampaignApprovalSnapshot> =
                campaign_approval_snapshot_in_txn(vault, txn, &payload)?;
            let Some(snapshot) = snapshot else {
                return Err(IntentLedgerError::InvalidRecord("campaign held snapshot"));
            };
            if snapshot.key != prepared.key
                || snapshot.owner_actor != prepared.owner_actor
                || snapshot.approval_digest.to_hex().as_str() != approval_digest.as_str()
            {
                return Err(IntentLedgerError::InvalidRecord("campaign held mismatch"));
            }
            if snapshot.intent_id.is_none() && snapshot.envelope_hash != prepared.envelope_hash {
                return Err(IntentLedgerError::InvalidRecord("campaign held envelope"));
            }
            if hold_erased_in_txn(
                vault,
                txn,
                &prepared.key,
                &existing,
                &snapshot,
                &payload,
                &attempt.id,
            )? {
                return Ok(());
            }
            let reason_codes = result.gate_reason_codes.clone();
            let receipt_reasons = result.gate_receipt_reasons.clone();
            if let Some(old) = existing.held.as_ref() {
                if old.approval_digest.as_str() == approval_digest.as_str()
                    && old.envelope_hash == snapshot.envelope_hash
                    && old.owner_actor == snapshot.owner_actor
                    && old.frozen_event_ref == snapshot.event_ref
                {
                    let mut merged = (*old).clone();
                    merged.gate_reason_codes = reason_codes;
                    merged.gate_receipt_reasons = receipt_reasons;
                    if merged.approved_redrive.is_none() && merged.owner_ask_seq.is_none() {
                        let seq = queue_held_owner_ask_in_txn(
                            vault,
                            txn,
                            &prepared.key,
                            &facts,
                            &merged,
                        )?;
                        merged.owner_ask_seq = Some(seq);
                    }
                    RETAINED.put(
                        &vault.store,
                        txn,
                        &prepared.key,
                        &RetainedRequest {
                            original_request: existing.original_request.clone(),
                            held: Some(merged),
                        },
                    )?;
                    return Ok(());
                }
                let _ = withdraw_owner_ask_in_txn(vault, txn, Some(old));
            }
            let mut fresh = HeldEnrollmentCall {
                owner_actor: snapshot.owner_actor,
                frozen_event_ref: snapshot.event_ref,
                attempt_ref: attempt.id.clone(),
                payload: attempt.payload.clone(),
                task_ref: attempt.task_ref.clone(),
                run_id: attempt.run_id.clone(),
                dedupe_actor_ref: attempt.dedupe_actor_ref.clone(),
                envelope_hash: snapshot.envelope_hash,
                approval_digest: approval_digest.to_string(),
                approval_actor: result.approval_actor.clone(),
                held_at_ms: now_ms,
                gate_reason_codes: reason_codes,
                gate_receipt_reasons: receipt_reasons,
                owner_ask_seq: None,
                approved_redrive: None,
            };
            let seq = queue_held_owner_ask_in_txn(vault, txn, &prepared.key, &facts, &fresh)?;
            fresh.owner_ask_seq = Some(seq);
            RETAINED.put(
                &vault.store,
                txn,
                &prepared.key,
                &RetainedRequest {
                    original_request: existing.original_request.clone(),
                    held: Some(fresh),
                },
            )?;
            Ok(())
        } else if result.paced_until.is_some() {
            Ok(())
        } else {
            if let Some(old) = existing.held.as_ref() {
                let _ = withdraw_owner_ask_in_txn(vault, txn, Some(old));
                RETAINED.put(
                    &vault.store,
                    txn,
                    &prepared.key,
                    &RetainedRequest {
                        original_request: existing.original_request.clone(),
                        held: None,
                    },
                )?;
            }
            Ok(())
        }
    });
    if let Err(error) = outcome {
        tracing::warn!(
            reason = "campaign_enrollment_held_observe",
            %error,
            "a campaign enrollment held observation failed; the dispatch is unchanged"
        );
    }
}

pub(super) fn withdraw_owner_ask_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    held: Option<&HeldEnrollmentCall>,
) -> Option<u64> {
    let held = held?;
    let seq = held.owner_ask_seq?;
    match vault.withdraw_decision_ask_in_txn(txn, seq) {
        Ok(true) => {
            crate::batch::queue_decision_answer(vault, txn, seq);
            Some(seq)
        }
        Ok(false) => None,
        Err(error) => {
            tracing::warn!(
                reason = "campaign_enrollment_held_withdraw",
                seq,
                %error,
                "a campaign enrollment held ask was not withdrawn"
            );
            None
        }
    }
}

#[doc(hidden)]
pub use oneiron_verb_wire::campaign::enrollment::held::CampaignEnrollmentHeldCall;

impl Vault {
    /// Lists retained observations under a live native owner proof.
    pub fn campaign_enrollment_held_calls(
        &self,
        owner: &AuthenticatedOwner,
    ) -> std::result::Result<Vec<CampaignEnrollmentHeldCall>, IntentLedgerError> {
        let txn = self
            .store
            .env
            .read_txn()
            .map_err(crate::error::Error::from)?;
        owner.revalidate_in_txn(self, &txn)?;
        let rows = RETAINED.scan(&self.store, &txn)?;
        let mut out = Vec::new();
        for (key, request) in rows {
            let Some(held) = request.held.as_ref() else {
                continue;
            };
            let Some((facts, _)) = decode_request(&key, &request) else {
                continue;
            };
            let Ok(call_ref) = held_call_ref(&key) else {
                continue;
            };
            let Ok(consequence_ref) = EntityId::from_bytes(key.0) else {
                continue;
            };
            out.push(CampaignEnrollmentHeldCall {
                call_ref,
                consequence_ref,
                call_seq: key.1,
                campaign_ref: facts.campaign_ref,
                program_ref: facts.program_ref,
                step_ref: facts.step_ref,
                member_ref: facts.entity_ref,
                owner_actor: held.owner_actor.clone(),
                frozen_event_ref: held.frozen_event_ref.clone(),
                attempt_ref: crate::entity_id::bytes_to_hex_lower(held.attempt_ref.as_bytes()),
                approval_digest: held.approval_digest.clone(),
                approval_actor: held.approval_actor.clone(),
                envelope_hash: crate::entity_id::bytes_to_hex_lower(&held.envelope_hash),
                held_at_ms: held.held_at_ms,
                owner_ask_seq: held.owner_ask_seq,
                approved_redrive: held
                    .approved_redrive
                    .as_ref()
                    .map(|id| crate::entity_id::bytes_to_hex_lower(id.as_bytes())),
            });
        }
        Ok(out)
    }

    /// Approves the exact reviewed request and queues its original typed work atomically.
    pub fn approve_campaign_enrollment_once(
        &self,
        owner: &AuthenticatedOwner,
        call_ref: &EntityId,
        reviewed_digest: &str,
    ) -> std::result::Result<ConsentReceipt, IntentLedgerError> {
        let receipt = self.try_with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let rows = RETAINED.scan(&self.store, txn)?;
            let mut found: Option<(RetainedKey, RetainedRequest)> = None;
            for (key, request) in rows {
                let Some(held) = request.held.as_ref() else {
                    continue;
                };
                if held.approved_redrive.is_some() {
                    continue;
                }
                let Ok(computed) = held_call_ref(&key) else {
                    continue;
                };
                if computed != *call_ref {
                    continue;
                }
                if held.approval_digest.as_str() != reviewed_digest {
                    return Err(IntentLedgerError::InvalidInput("campaign held digest"));
                }
                found = Some((key, request));
                break;
            }
            let Some((key, mut request)) = found else {
                return Err(IntentLedgerError::InvalidInput("campaign held call"));
            };
            let Some(mut held) = request.held.take() else {
                return Err(IntentLedgerError::InvalidInput("campaign held call"));
            };
            let payload = decode_enrollment_attempt_payload(&held.payload)?;
            let snapshot: Option<CampaignApprovalSnapshot> =
                campaign_approval_snapshot_in_txn(self, txn, &payload)?;
            let Some(snapshot) = snapshot else {
                return Err(IntentLedgerError::InvalidRecord("campaign held snapshot"));
            };
            if key != snapshot.key
                || held.owner_actor != snapshot.owner_actor
                || held.frozen_event_ref != snapshot.event_ref
                || held.envelope_hash != snapshot.envelope_hash
                || held.approval_digest.as_str() != snapshot.approval_digest.to_hex().as_str()
            {
                return Err(IntentLedgerError::InvalidRecord("campaign held mismatch"));
            }
            if hold_erased_in_txn(
                self,
                txn,
                &key,
                &request,
                &snapshot,
                &payload,
                &held.attempt_ref,
            )? {
                return Err(IntentLedgerError::InvalidRecord("campaign held erased"));
            }
            let receipt = self.approve_once_in_txn(txn, owner, snapshot.approval_digest)?;
            let ConsentReceipt::Approved { decision_id, .. } = &receipt else {
                return Err(IntentLedgerError::InvalidRecord("campaign held receipt"));
            };
            let dedupe_key =
                approved_dedupe_key(call_ref, reviewed_digest, (*decision_id).as_bytes());
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let input = EnqueueAttempt {
                kind: CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND.to_owned(),
                payload: held.payload.clone(),
                dedupe_key: Some(dedupe_key),
                run_id: held.run_id.clone(),
                now,
            };
            let outcome = AttemptQueue::new(self).enqueue_with_task_ref_and_dedupe_actor_in_txn(
                txn,
                input,
                held.task_ref.clone(),
                held.dedupe_actor_ref.as_deref(),
            )?;
            let record = match outcome {
                EnqueueOutcome::Enqueued(record) => record,
                EnqueueOutcome::Existing(record) => {
                    if record.state.is_terminal() {
                        return Err(IntentLedgerError::InvalidRecord("campaign held redrive"));
                    }
                    record
                }
            };
            held.approved_redrive = Some(record.id.clone());
            let _ = withdraw_owner_ask_in_txn(self, txn, Some(&held));
            request.held = Some(held);
            RETAINED.put(&self.store, txn, &key, &request)?;
            Ok(receipt)
        })?;
        self.store.notify_attempt_observers();
        Ok(receipt)
    }

    /// Repairs only holds that have never acquired an owner-ask sequence.
    pub fn repair_campaign_enrollment_owner_asks(
        &self,
    ) -> std::result::Result<usize, IntentLedgerError> {
        self.try_with_write_txn(|txn| {
            let rows = RETAINED.scan(&self.store, txn)?;
            let mut repaired = 0;
            for (key, mut request) in rows {
                let Some(held) = request.held.clone() else {
                    continue;
                };
                if held.approved_redrive.is_some() || held.owner_ask_seq.is_some() {
                    continue;
                }
                let Some((facts, _)) = decode_request(&key, &request) else {
                    tracing::warn!(
                        reason = "campaign_enrollment_held_repair_decode",
                        "a campaign held row did not decode; it keeps no ask"
                    );
                    continue;
                };
                let payload = match decode_enrollment_attempt_payload(&held.payload) {
                    Ok(payload) => payload,
                    Err(error) => {
                        tracing::warn!(
                            reason = "campaign_enrollment_held_repair_payload",
                            %error,
                            "a campaign held payload did not decode; it keeps no ask"
                        );
                        continue;
                    }
                };
                let snapshot: Option<CampaignApprovalSnapshot> =
                    match campaign_approval_snapshot_in_txn(self, txn, &payload) {
                        Ok(snapshot) => snapshot,
                        Err(error) => {
                            tracing::warn!(
                                reason = "campaign_enrollment_held_repair_snapshot",
                                %error,
                                "a campaign held snapshot did not read; it keeps no ask"
                            );
                            continue;
                        }
                    };
                let Some(snapshot) = snapshot else {
                    tracing::warn!(
                        reason = "campaign_enrollment_held_repair_snapshot",
                        "a campaign held snapshot is missing; it keeps no ask"
                    );
                    continue;
                };
                if key != snapshot.key
                    || held.owner_actor != snapshot.owner_actor
                    || held.frozen_event_ref != snapshot.event_ref
                    || held.envelope_hash != snapshot.envelope_hash
                    || held.approval_digest.as_str() != snapshot.approval_digest.to_hex().as_str()
                {
                    tracing::warn!(
                        reason = "campaign_enrollment_held_repair_mismatch",
                        "a campaign held row does not match its snapshot; it keeps no ask"
                    );
                    continue;
                }
                match hold_erased_in_txn(
                    self,
                    txn,
                    &key,
                    &request,
                    &snapshot,
                    &payload,
                    &held.attempt_ref,
                ) {
                    Ok(false) => {}
                    Ok(true) => continue,
                    Err(error) => {
                        tracing::warn!(%error, "a campaign held erase fence did not read");
                        continue;
                    }
                }
                let seq = queue_held_owner_ask_in_txn(self, txn, &key, &facts, &held)?;
                let mut repaired_held = held;
                repaired_held.owner_ask_seq = Some(seq);
                request.held = Some(repaired_held);
                RETAINED.put(&self.store, txn, &key, &request)?;
                repaired += 1;
            }
            Ok(repaired)
        })
    }
}

/// Retires the auxiliary ask when this observed outward leg owes no call.
pub(super) fn observe_nothing_owed(
    vault: &Vault,
    event: &super::detection::CampaignEnrollmentEvent,
    step: &super::program::CampaignProgramStep,
) {
    let retired = vault.try_with_write_txn(|txn| -> std::result::Result<(), IntentLedgerError> {
        for (key, mut request) in RETAINED.scan(&vault.store, txn)? {
            let Some((facts, _)) = decode_request(&key, &request) else {
                continue;
            };
            if request.held.is_none()
                || facts.query_ref != event.query_ref
                || facts.campaign_ref != event.campaign_ref
                || facts.entity_ref != event.entity_ref
                || facts.epoch != event.epoch
                || facts.program_ref != step.program_ref
                || facts.step_ref != step.step_ref
            {
                continue;
            }
            let _ = withdraw_owner_ask_in_txn(vault, txn, request.held.as_ref());
            request.held = None;
            RETAINED.put(&vault.store, txn, &key, &request)?;
        }
        Ok(())
    });
    if let Err(error) = retired {
        tracing::warn!(%error, "campaign enrollment held asks were not retired");
    }
}
