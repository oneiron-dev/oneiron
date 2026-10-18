//! Caller-bound campaign actions. Membership uses the ordinary claim gate;
//! earned stages and suppression delegate to their existing projector writers.

use std::sync::atomic::Ordering;
use crate::batch::{ApplyOpsGateMode, BatchOp};
use crate::campaign::claims::{
    CampaignMemberChannel, CampaignMemberState, CampaignMemberValue, EvidenceBasis,
    normalize_campaign_pack_token,
};
use crate::campaign::stage::{ExternalStageEvidenceHook, StageEvidence, StageProjectResult};
use crate::campaign::surface::*;
use crate::claim::{ClaimApprovalStatus, ClaimReadStatus, ClaimSource};
use crate::consent::AuthenticatedOwner;
use crate::temporal::TimeRange;
use crate::{EntityId, Error};
use super::{Memory, MemoryError, MemoryResult, MEMORY_CODE_FORBIDDEN};

impl Memory<'_> {
    /// `vault.campaign.enroll`: evidence-backed manual intake, with no send,
    /// fabricated saved-query event, machine epoch or pipeline stage.
    pub fn campaign_enroll(&self, input: &CampaignEnrollRequest) -> MemoryResult<CampaignEnrollmentReceipt> {
        self.verified_actor_class()?;
        let campaign = entity(&input.campaign_ref)?;
        let person = entity(&input.person_ref)?;
        let evidence = entities(&input.evidence_refs)?;
        let channels = input.channels.iter().map(|row| Ok(CampaignMemberChannel {
            channel: normalize_campaign_pack_token(&row.channel),
            basis_evidence: entity(&row.basis_evidence)?,
            sender_ref: entity(&row.sender_ref)?,
        })).collect::<MemoryResult<Vec<_>>>()?;
        let refs: Vec<_> = [campaign, person].into_iter().chain(evidence.iter().copied())
            .chain(channels.iter().flat_map(|row| [row.basis_evidence, row.sender_ref])).collect();
        crate::gate::record_references::admit_row_references(self, "vault.campaign.enroll", input,
            &["/campaign_ref", "/person_ref", "/evidence_refs/*", "/channels/*/basis_evidence", "/channels/*/sender_ref"])?;
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let now = self.vault.store.clock.now_recorded_at();
        let id = self.vault.store.clock.entity_id()?;
        let value = CampaignMemberValue { campaign, state: CampaignMemberState::Enrolled, channels, derivation: None };
        let source = if self.actor_class == crate::EdgeActorClass::Human { ClaimSource::UserStated } else { ClaimSource::Observed };
        let approval = self.with_actor_content_write_txn(|content| {
            require_readable(&lane, content.read(), &refs)?;
            let candidate = crate::campaign::enrollment::manual_enrollment_candidate_in_txn(
                self.vault, content.read(), self.actor, person, &value, &evidence)?;
            let mut envelope = self.claim_envelope(source, "vault.campaign.enroll", ClaimApprovalStatus::Auto)?;
            self.sign_machine_claim_in_txn(content.read(), id, &candidate, &mut envelope)?;
            let owner_authored = self.owner_authored_write_in_txn(content.read())?;
            content.apply_claim_ops(vec![BatchOp::ClaimCandidate {
                id, candidate: Box::new(candidate), envelope,
                occurred: TimeRange { start: now, end: now }, learned_at: now,
                internal_lexical_query_hint: false,
            }], self.vault.text_index_trusted.load(Ordering::Acquire),
                ApplyOpsGateMode::new(true, true).with_owner_authored(owner_authored))?;
            Ok(self.vault.get_claim_in_txn(content.read(), &id)?.ok_or(Error::EntityNotFound)?.approval.as_str().to_owned())
        })?;
        Ok(CampaignEnrollmentReceipt {
            membership_claim_ref: id.to_hex(), person_ref: person.to_hex(), campaign_ref: campaign.to_hex(),
            state: CampaignEnrollmentState::Enrolled,
            channels: value.channels.iter().map(|row| CampaignMemberChannelSpec {
                channel: row.channel.clone(), basis_evidence: row.basis_evidence.to_hex(), sender_ref: row.sender_ref.to_hex(),
            }).collect(), approval,
            provenance: CampaignActionProvenance { actor_ref: self.actor.to_hex(), evidence_refs: evidence.iter().map(EntityId::to_hex).collect(), recorded_at: now },
            receipt_ref: self.latest_decision_ref_for(&id)?.unwrap_or_else(|| format!("claim:{}", id.to_hex())),
        })
    }

    /// Embedded invocation: machine evidence needs no owner proof; attestation
    /// explicitly requires the embedded owner's constructor-owned handle.
    pub fn campaign_stage_evidence(&self, input: &CampaignStageEvidenceRequest) -> MemoryResult<CampaignStageEvidenceReceipt> {
        match input.evidence.basis {
            EvidenceBasis::Machine => self.campaign_stage_evidence_as(None, input),
            EvidenceBasis::OwnerAttested => {
                let owner = self.embedded_owner("vault.campaign.stage.evidence")?;
                self.campaign_stage_evidence_as(Some(&owner), input)
            }
        }
    }

    /// Served invocation: the host supplies the actual request's owner proof
    /// only for an owner attestation. No caller payload can supply this proof.
    pub fn campaign_stage_evidence_as(&self, owner: Option<&AuthenticatedOwner>, input: &CampaignStageEvidenceRequest) -> MemoryResult<CampaignStageEvidenceReceipt> {
        self.verified_actor_class()?;
        let campaign = entity(&input.campaign_ref)?;
        let person = entity(&input.person_ref)?;
        let evidence = entities(&input.evidence.evidence_refs)?;
        let refs: Vec<_> = [campaign, person].into_iter().chain(evidence.iter().copied()).collect();
        crate::gate::record_references::admit_row_references(self, "vault.campaign.stage.evidence", input,
            &["/campaign_ref", "/person_ref", "/evidence/evidence_refs/*"])?;
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let source = match input.evidence.basis { EvidenceBasis::Machine => ClaimSource::Observed, EvidenceBasis::OwnerAttested => ClaimSource::UserStated };
        let envelope = self.claim_envelope(source, "vault.campaign.stage.evidence", ClaimApprovalStatus::Approved)?;
        let hook = ExternalStageEvidenceHook {
            party_ref: person, campaign_ref: campaign, target_stage: input.target_stage.clone(),
            evidence: StageEvidence { class: input.evidence.class, basis: input.evidence.basis, evidence_refs: evidence.clone(), recorded_at: input.evidence.recorded_at },
        };
        self.with_verified_actor_write_txn(|txn| {
            require_readable(&lane, txn, &refs)?;
            require_campaign_person(self, txn, campaign, person, true)?;
            if input.evidence.basis == EvidenceBasis::OwnerAttested {
                let owner = owner.ok_or_else(|| MemoryError::new(MEMORY_CODE_FORBIDDEN,
                    "owner-attested stage evidence requires the owner's proof", &[]))?;
                if owner.revalidate_in_txn(self.vault, txn)? != self.actor || self.actor_class != crate::EdgeActorClass::Human {
                    return Err(MemoryError::new(MEMORY_CODE_FORBIDDEN, "stage attestation must act as the authenticated owner", &[]));
                }
            }
            let now = self.vault.store.clock.now_recorded_at();
            if input.evidence.recorded_at > now {
                return Err(MemoryError::bad_request("stage evidence cannot be recorded in the future"));
            }
            let projected = crate::campaign::stage::apply_external_stage_evidence_in_txn(self.vault, txn, &input.ladder, &hook, input.mode, Some(&envelope))?;
            let (outcome, claim) = match projected {
                StageProjectResult::Advanced { new_claim_ref } => (CampaignStageEvidenceOutcome::Advanced, Some(new_claim_ref)),
                StageProjectResult::Proposed { proposed_claim_ref } => (CampaignStageEvidenceOutcome::Proposed, Some(proposed_claim_ref)),
                StageProjectResult::NoChange => (CampaignStageEvidenceOutcome::NoChange, None),
                StageProjectResult::Routed(_) => return Err(MemoryError::bad_request("external evidence cannot route membership")),
            };
            Ok(CampaignStageEvidenceReceipt {
                person_ref: person.to_hex(), campaign_ref: campaign.to_hex(), outcome,
                stage_claim_ref: claim.map(|id| id.to_hex()),
                stage: claim.map(|_| input.target_stage.clone()),
                evidence: claim.map(|_| input.evidence.clone()),
                provenance: claim.map(|_| CampaignActionProvenance { actor_ref: self.actor.to_hex(), evidence_refs: evidence.iter().map(EntityId::to_hex).collect(), recorded_at: input.evidence.recorded_at }),
                receipt_ref: claim.map(|id| format!("claim:{}", id.to_hex())),
            })
        })
    }

    /// `vault.campaign.unsubscribe`: writes the enforcement claim and all
    /// suppressed member heads atomically through CA-05, before it returns.
    pub fn campaign_unsubscribe(&self, input: &CampaignUnsubscribeRequest) -> MemoryResult<CampaignUnsubscribeReceipt> {
        self.verified_actor_class()?;
        let campaign = entity(&input.campaign_ref)?;
        let person = entity(&input.person_ref)?;
        let evidence = entity(&input.evidence_ref)?;
        let channel = normalize_campaign_pack_token(&input.channel);
        crate::gate::record_references::admit_row_references(self, "vault.campaign.unsubscribe", input,
            &["/campaign_ref", "/person_ref", "/evidence_ref"])?;
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        self.with_verified_actor_write_txn(|txn| {
            require_readable(&lane, txn, &[campaign, person, evidence])?;
            // An archived campaign still must honor an unsubscribe.
            require_campaign_person(self, txn, campaign, person, false)?;
            let receipt = crate::campaign::send_hygiene::apply_suppression_in_txn(self.vault, txn,
                crate::campaign::send_hygiene::SuppressionCause::Unsubscribe,
                &crate::campaign::send_hygiene::SuppressionInput {
                    person_ref: person, campaign_ref: Some(campaign), channel: channel.clone(), sender_ref: None,
                    evidence_ref: evidence, occurred_at: self.vault.store.clock.now_recorded_at(),
                })?;
            Ok(CampaignUnsubscribeReceipt {
                campaign_ref: campaign.to_hex(), person_ref: person.to_hex(), channel: channel.clone(), evidence_ref: evidence.to_hex(),
                suppression_claim_ref: receipt.do_not_contact_claim_ref.to_hex(),
                member_claim_refs: receipt.member_claim_refs.iter().map(EntityId::to_hex).collect(),
                receipt_ref: format!("claim:{}", receipt.do_not_contact_claim_ref.to_hex()),
            })
        })
    }
}

fn entity(reference: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(reference).map_err(|_| MemoryError::bad_request("campaign references must be 32-character hex entity ids"))
}

fn entities(references: &[String]) -> MemoryResult<Vec<EntityId>> {
    references.iter().map(|reference| entity(reference)).collect()
}

fn require_readable(lane: &crate::claim::ScopedRead<'_>, txn: &heed::RoTxn<'_>, refs: &[EntityId]) -> MemoryResult<()> {
    if lane.entities_readable_in_txn(txn, refs)?.iter().any(|readable| !readable) {
        return Err(Error::EntityNotFound.into());
    }
    Ok(())
}

fn require_campaign_person(memory: &Memory<'_>, txn: &heed::RoTxn<'_>, campaign: EntityId, person: EntityId, active: bool) -> MemoryResult<()> {
    let record = owned_campaign_in_txn(memory.vault, txn, memory.actor, campaign, campaign_type_byte(memory.vault)?)?;
    if active && record.definition.lifecycle != CampaignLifecycle::Active {
        return Err(MemoryError::bad_request("an archived campaign cannot advance stages"));
    }
    if memory.vault.get_entity_type_in_txn(txn, &person)? != Some(crate::registry::ENTITY_TYPE_PERSON) {
        return Err(MemoryError::bad_request("campaign actions require a PERSON"));
    }
    Ok(())
}
