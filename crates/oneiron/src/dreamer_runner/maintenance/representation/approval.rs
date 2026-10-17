//! Content-bound owner review, live revalidation, and the existing OF-327 adapter.
//! A plan the Dreamer saved at once (OF-023) is armed by the owner's own
//! send-review receipt; a plan the Gate held, by their bundle approval.
use super::super::applied::{self, MaintenanceTarget};
use super::context::validate_packet;
use super::proposal::{StoredProposal, read_proposal};
use super::{CONTENT_PREFIX, Packet, RepresentationCitation, invalid};
use crate::compaction::output::OutputRef;
use crate::consent::AuthenticatedOwner;
use crate::memory::{
    Memory, MemoryError, MemoryResult, OutboundDraftInput, OutboundIntentReceipt,
    OutboundScheduleContext,
};
use crate::outbound::{
    OutboundDispatchRequest, OutboundIntent, OutboundIntentDraft, OutboundIntentTrigger,
};
use crate::run_tree::GateConsentBundleAction;
use crate::side_table::{self, LegacyJson, SideTable};
use crate::store::{GateDecisionId, GateDecisionRecord};
use crate::{ClaimApprovalStatus, EdgeActorClass, EntityId, Result, Vault, WriteActor};
use serde::{Deserialize, Serialize};

/// Owner approval/decline record for a representation proposal review.
const APPROVAL: SideTable<EntityId, ApprovalRecord, LegacyJson> =
    SideTable::new(&side_table::DREAMER_REPRESENTATION_APPROVAL);
/// The Gate receipt the owner's approval of a saved plan leaves: their
/// review of its exact content and sources, and their word to send it.
const SEND_REVIEW_KIND: &str = "dreamer_representation_send_review";
const SEND_REVIEW_REASON: &str = "gate.dreamer.representation_send_reviewed";

/// Immutable review witness. A caller cannot replace the reviewed content,
/// source revisions, owner, or destination while retaining this witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepresentationReview {
    id: EntityId,
    record: StoredProposal,
    basis: ReviewBasis,
}
/// What one review stands on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReviewBasis {
    /// A held plan's one-member Gate bundle, which the owner resolves.
    Bundle([u8; 32]),
    /// A plan the Dreamer saved at once: the owner's approval adds their own
    /// send-review receipt.
    Saved,
}
impl RepresentationReview {
    pub const fn proposal_id(&self) -> EntityId {
        self.id
    }
    pub fn request(&self) -> &super::RepresentationRequest {
        &self.record.packet.request
    }
    pub const fn content(&self) -> OutputRef {
        self.record.packet.content
    }
    pub fn evidence(&self) -> &[RepresentationCitation] {
        &self.record.packet.evidence
    }
    pub fn voice(&self) -> &[RepresentationCitation] {
        &self.record.packet.voice
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalRecord {
    witness: OwnerWitness,
    revision: [u8; 32],
    #[serde(with = "crate::serialize::entity_ref")]
    owner: EntityId,
}
/// The owner's receipt an arm stands on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OwnerWitness {
    /// Their Gate bundle approval of a held plan.
    Bundle([u8; 32]),
    /// Their send-review receipt on a saved plan.
    SendReview(GateDecisionId),
}
/// An approved proposal, not a transport permission. OF-327 still evaluates
/// its ordinary Gate, consent, delivery window, budget, and replay contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedRepresentation {
    id: EntityId,
    record: StoredProposal,
    actor: EntityId,
    approval: ApprovalRecord,
}
impl ApprovedRepresentation {
    pub const fn proposal_id(&self) -> EntityId {
        self.id
    }
}
impl Vault {
    /// The review of one plan by exact content and source revisions: a plan
    /// the Dreamer saved and the owner has not reverted, or a held plan
    /// awaiting its one-member bundle.
    pub fn review_representation(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
    ) -> Result<RepresentationReview> {
        let (record, body) = read_proposal(self, id)?;
        require_recipient(self, owner, &record.packet)?;
        validate_packet(self, &record.packet)?;
        let basis = match body.approval {
            ClaimApprovalStatus::Auto if saved(self, *id)? => ReviewBasis::Saved,
            ClaimApprovalStatus::Proposed => {
                let bundle =
                    self.review_gate_consent_bundle(&self.dreamer_authority()?, &record.run)?;
                if bundle.members.len() != 1 || bundle.members[0].claim_id != *id {
                    return Err(invalid());
                }
                ReviewBasis::Bundle(bundle.bundle_id)
            }
            _ => return Err(invalid()),
        };
        Ok(RepresentationReview {
            id: *id,
            record,
            basis,
        })
    }
    /// The owner's approval of a reviewed plan, armed for OF-327. A saved
    /// plan is armed against the send-review receipt this approval records;
    /// a held one against the owner's bundle approval.
    pub fn approve_representation(
        &self,
        owner: &AuthenticatedOwner,
        review: &RepresentationReview,
        now: u64,
    ) -> Result<ApprovedRepresentation> {
        require_owner(self, owner, &review.record.packet)?;
        let (record, body) = read_proposal(self, &review.id)?;
        if record != review.record {
            return Err(invalid());
        }
        validate_packet(self, &record.packet)?;
        let ReviewBasis::Bundle(bundle_id) = review.basis else {
            self.arm_saved_plan(owner, review, now)?;
            return self.approved_representation(&review.id);
        };
        match body.approval {
            ClaimApprovalStatus::Proposed => {
                self.resolve_gate_consent_bundle(
                    owner,
                    bundle_id,
                    &record.run,
                    GateConsentBundleAction::Approve,
                    now,
                )?;
            }
            // A crash or post-commit VAD error can leave the Gate approved and
            // the local adapter unarmed. Only the SAME owner review can finish
            // it, and only with the real indexed bundle-member receipt below.
            ClaimApprovalStatus::Approved => {}
            _ => return Err(invalid()),
        }
        let (current, body) = read_proposal(self, &review.id)?;
        if current != record || body.approval != ClaimApprovalStatus::Approved {
            return Err(invalid());
        }
        validate_packet(self, &current.packet)?;
        self.with_write_txn_grouped(|txn| {
            let approval = ApprovalRecord {
                witness: OwnerWitness::Bundle(bundle_id),
                revision: record.revision,
                owner: crate::dreamer_runner::maintenance::validate_owner_in_txn(
                    self, &*txn, owner,
                )?,
            };
            require_owner_witness_in(self, txn, review.id, &approval)?;
            // The exact reviewed body must still be live at the local arm.
            let body = self
                .get_claim_in_txn(&*txn, &review.id)?
                .ok_or_else(invalid)?;
            if body.approval != ClaimApprovalStatus::Approved
                || super::proposal::review_revision(&body)? != approval.revision
            {
                return Err(invalid());
            }
            APPROVAL.put(&self.store, txn, &review.id, &approval)?;
            Ok(())
        })?;
        self.approved_representation(&review.id)
    }
    /// Decline closes a held plan's Gate bundle, and withdraws a saved plan
    /// through the owner's maintenance revert (it is retracted, with their
    /// receipt). It has no outbound call. Stale evidence does not prevent
    /// declining a still-current review body.
    pub fn decline_representation(
        &self,
        owner: &AuthenticatedOwner,
        review: &RepresentationReview,
        now: u64,
    ) -> Result<()> {
        require_owner(self, owner, &review.record.packet)?;
        let (record, body) = read_proposal(self, &review.id)?;
        if record != review.record {
            return Err(invalid());
        }
        let ReviewBasis::Bundle(bundle_id) = review.basis else {
            self.revert_dreamer_maintenance(owner, MaintenanceTarget::Finding(review.id), now)?;
            return Ok(());
        };
        if body.approval != ClaimApprovalStatus::Proposed {
            return Err(invalid());
        }
        self.resolve_gate_consent_bundle(
            owner,
            bundle_id,
            &record.run,
            GateConsentBundleAction::Decline,
            now,
        )?;
        Ok(())
    }
    /// Arms a saved plan in one write: the owner proof and the exact reviewed
    /// body are rechecked, the owner's send-review receipt is recorded and
    /// the arm stands on it. An arm the same owner already made at this
    /// revision is kept, so a retry records nothing twice.
    fn arm_saved_plan(
        &self,
        owner: &AuthenticatedOwner,
        review: &RepresentationReview,
        now: u64,
    ) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            let actor =
                crate::dreamer_runner::maintenance::validate_owner_in_txn(self, &*txn, owner)?;
            let body = self
                .get_claim_in_txn(&*txn, &review.id)?
                .ok_or_else(invalid)?;
            if body.approval != ClaimApprovalStatus::Auto
                || super::proposal::review_revision(&body)? != review.record.revision
                || !applied::standing_in_txn(self, &*txn, review.id)?
            {
                return Err(invalid());
            }
            if let Some(held) = APPROVAL.get(&self.store, &*txn, &review.id)?
                && held.owner == actor
                && held.revision == review.record.revision
                && require_owner_witness_in(self, txn, review.id, &held).is_ok()
            {
                return Ok(());
            }
            let mut receipt = applied::decision(
                WriteActor::new(actor, EdgeActorClass::Human),
                SEND_REVIEW_KIND,
                SEND_REVIEW_REASON,
                MaintenanceTarget::Finding(review.id),
                review.record.revision.to_vec(),
                now,
            );
            self.store
                .append_fresh_gate_decision_in_txn(txn, &mut receipt)?;
            let approval = ApprovalRecord {
                witness: OwnerWitness::SendReview(receipt.decision_id),
                revision: review.record.revision,
                owner: actor,
            };
            APPROVAL.put(&self.store, txn, &review.id, &approval)
        })
    }
    /// Reloads approved state, including evidence and voice revisions. An
    /// ordinary inbox approval alone cannot mint this adapter's owner arm,
    /// and the Dreamer's own save of a plan never stands in for the owner's
    /// send review.
    pub fn approved_representation(&self, id: &EntityId) -> Result<ApprovedRepresentation> {
        let (record, body) = read_proposal(self, id)?;
        validate_packet(self, &record.packet)?;
        let approval: ApprovalRecord = {
            let txn = self.store.env.read_txn()?;
            let approval = APPROVAL.get(&self.store, &txn, id)?.ok_or_else(invalid)?;
            require_owner_witness_in(self, &txn, *id, &approval)?;
            let armed = match approval.witness {
                OwnerWitness::Bundle(_) => body.approval == ClaimApprovalStatus::Approved,
                OwnerWitness::SendReview(_) => {
                    body.approval == ClaimApprovalStatus::Auto
                        && applied::standing_in_txn(self, &txn, *id)?
                }
            };
            if !armed {
                return Err(invalid());
            }
            approval
        };
        if approval.owner != record.packet.request.owner || approval.revision != record.revision {
            return Err(invalid());
        }
        Ok(ApprovedRepresentation {
            id: *id,
            record,
            actor: self.dreamer_authority()?.entity_ref(),
            approval,
        })
    }
    /// Connector content loader for this typed reference. A connector never
    /// resolves a bare mutable claim or substitutes today's generated text.
    pub fn read_representation_content(&self, reference: &str) -> Result<Vec<u8>> {
        let id = content_proposal_id(reference)?;
        let approved = self.approved_representation(&id)?;
        if reference != approved.record.packet.content_ref()? {
            return Err(invalid());
        }
        crate::compaction::output::restore_output(self, approved.record.packet.content)
    }
}
fn require_owner(vault: &Vault, owner: &AuthenticatedOwner, packet: &Packet) -> Result<()> {
    // Revalidate the supplied proof itself against this vault's store truth
    // and lifecycle: a handle minted before its PERSON became a merged/split
    // shell, or a proof another vault authenticated for the same PERSON id,
    // never reviews or arms here.
    let txn = vault.store.env.read_txn()?;
    if crate::dreamer_runner::maintenance::validate_owner_in_txn(vault, &txn, owner)?
        != packet.request.owner
    {
        return Err(invalid());
    }
    Ok(())
}
/// [`require_owner`] for reading the review addressed to the packet's
/// person, which approves and arms nothing: the person tier.
fn require_recipient(vault: &Vault, owner: &AuthenticatedOwner, packet: &Packet) -> Result<()> {
    let txn = vault.store.env.read_txn()?;
    if crate::dreamer_runner::maintenance::validate_person_in_txn(vault, &txn, owner)?
        != packet.request.owner
    {
        return Err(invalid());
    }
    Ok(())
}
/// Whether a saved plan's applied row still stands: the owner has not
/// reverted it.
fn saved(vault: &Vault, id: EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    applied::standing_in_txn(vault, &txn, id)
}
fn is_owner_witness(receipt: &GateDecisionRecord, approval: &ApprovalRecord) -> bool {
    if receipt.outcome != "approved" || receipt.redacted_at.is_some() {
        return false;
    }
    match approval.witness {
        OwnerWitness::Bundle(bundle_id) => {
            let bundle_ref = format!(
                "bundle:{}",
                crate::entity_id::bytes_to_hex_lower(&bundle_id)
            );
            receipt.grant_ref.as_deref() == Some(bundle_ref.as_str())
                && receipt
                    .reason_codes
                    .iter()
                    .any(|s| s == crate::gate::GATE_BUNDLE_REASON_APPROVED)
        }
        OwnerWitness::SendReview(decision) => {
            receipt.decision_id == decision
                && receipt.content_kind == SEND_REVIEW_KIND
                && receipt.actor_ref.as_deref() == Some(approval.owner.to_hex().as_str())
                && receipt.diff_handle == approval.revision
        }
    }
}
fn require_owner_witness_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    approval: &ApprovalRecord,
) -> Result<()> {
    let receipts = vault
        .store
        .gate_decisions_for_claim_in_txn(txn, id.as_bytes())?;
    if !receipts.iter().any(|r| is_owner_witness(r, approval)) {
        return Err(invalid());
    }
    Ok(())
}
/// Loading and scheduling an approved proposal re-prove the owner's bundle
/// or send-review receipt, so the retention sweep keeps it while the
/// approval exists.
pub(crate) fn representation_approval_is_live_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    receipt: &GateDecisionRecord,
) -> Result<bool> {
    let Some(claim) = receipt.claim_id else {
        return Ok(false);
    };
    if receipt.outcome != "approved" || receipt.redacted_at.is_some() {
        return Ok(false);
    }
    let Some(approval) = APPROVAL.get(&vault.store, txn, &EntityId::from_bytes(claim)?)? else {
        return Ok(false);
    };
    Ok(is_owner_witness(receipt, &approval))
}
fn content_proposal_id(reference: &str) -> Result<EntityId> {
    let suffix = reference.strip_prefix(CONTENT_PREFIX).ok_or_else(invalid)?;
    let (id, _) = suffix.split_once(':').ok_or_else(invalid)?;
    EntityId::from_hex(id).map_err(|_| invalid())
}
fn expected_intent(approved: &ApprovedRepresentation) -> Result<OutboundIntent> {
    let packet = &approved.record.packet;
    Ok(OutboundIntent::from_trigger(
        OutboundIntentDraft::new(
            approved.actor.to_hex(),
            packet.request.verb.clone(),
            packet.request.channel.clone(),
            packet.request.target.clone(),
        )
        .on_behalf_of(packet.request.owner.to_hex())
        .content_ref(packet.content_ref()?)
        .idempotency_key(format!("representation:{}", approved.id.to_hex())),
        OutboundIntentTrigger::gap_queue(packet.trigger_ref()?),
    ))
}
pub fn schedule_approved_representation(
    facade: &Memory<'_>,
    approved: ApprovedRepresentation,
    context: &OutboundScheduleContext,
    now: u64,
) -> MemoryResult<OutboundIntentReceipt> {
    let current = facade.vault().approved_representation(&approved.id)?;
    if current != approved
        || facade.actor() != approved.actor
        || facade.actor_class() != EdgeActorClass::System
    {
        return Err(MemoryError::from(invalid()));
    }
    let intent = expected_intent(&approved)?;
    facade.schedule_outbound_with_context(
        &OutboundDraftInput {
            verb: intent.verb,
            channel: intent.channel,
            target: intent.target,
            on_behalf_of: intent.on_behalf_of,
            content_ref: intent.content_ref,
            idempotency_key: intent.idempotency_key,
            dedupe_key: intent.dedupe_key,
            trigger: "gap_queue".into(),
            trigger_ref: intent.trigger_ref,
            job_ref: None,
            occurred_at: Some(now),
            mention: intent.mention,
        },
        context,
    )
}
/// Called by the existing dispatch spine BEFORE replay/gate/window/transport.
/// Thus source edits, retraction, or content substitution after scheduling also
/// refuse a retry. Other outbound intents retain their existing path unchanged.
pub(crate) fn validate_dispatch(vault: &Vault, request: &OutboundDispatchRequest) -> Result<()> {
    let tagged_content = request
        .intent
        .content_ref
        .as_deref()
        .is_some_and(|s| s.starts_with(CONTENT_PREFIX));
    if !tagged_content && !request.intent.trigger_ref.starts_with(CONTENT_PREFIX) {
        return Ok(());
    }
    let content = request.intent.content_ref.as_deref().ok_or_else(invalid)?;
    let id = content_proposal_id(content)?;
    let approved = vault.approved_representation(&id)?;
    if request.intent != expected_intent(&approved)?
        || request.actor.actor_entity_ref != Some(approved.actor)
        || request.actor.actor_ref.as_deref() != Some(approved.actor.to_hex().as_str())
        || request.actor.actor_class != "system"
    {
        return Err(invalid());
    }
    Ok(())
}
