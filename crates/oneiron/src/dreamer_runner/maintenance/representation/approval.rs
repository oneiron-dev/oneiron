//! Content-bound owner review, live revalidation, and the existing OF-327 adapter.
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
use crate::{ClaimApprovalStatus, EdgeActorClass, EntityId, Result, Vault};
use serde::{Deserialize, Serialize};

/// Owner approval/decline record for a representation proposal review.
const APPROVAL: SideTable<EntityId, ApprovalRecord, LegacyJson> =
    SideTable::new(&side_table::DREAMER_REPRESENTATION_APPROVAL);

/// Immutable review witness. A caller cannot replace the reviewed content,
/// source revisions, owner, or destination while retaining this witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepresentationReview {
    id: EntityId,
    record: StoredProposal,
    bundle_id: [u8; 32],
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
    bundle_id: [u8; 32],
    revision: [u8; 32],
    #[serde(with = "crate::serialize::entity_ref")]
    owner: EntityId,
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
    pub fn review_representation(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
    ) -> Result<RepresentationReview> {
        let (record, body) = read_proposal(self, id)?;
        require_owner(self, owner, &record.packet)?;
        validate_packet(self, &record.packet)?;
        if body.approval != ClaimApprovalStatus::Proposed {
            return Err(invalid());
        }
        let bundle = self.review_gate_consent_bundle(&self.dreamer_authority()?, &record.run)?;
        if bundle.members.len() != 1 || bundle.members[0].claim_id != *id {
            return Err(invalid());
        }
        Ok(RepresentationReview {
            id: *id,
            record,
            bundle_id: bundle.bundle_id,
        })
    }
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
        match body.approval {
            ClaimApprovalStatus::Proposed => {
                self.resolve_gate_consent_bundle(
                    owner,
                    review.bundle_id,
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
        let approval = ApprovalRecord {
            bundle_id: review.bundle_id,
            revision: record.revision,
            owner: owner.actor(),
        };
        self.with_write_txn(|txn| {
            require_owner_bundle_in(self, txn, review.id, &approval)?;
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
    /// Decline only closes the existing Gate bundle. It has no outbound call.
    /// Stale evidence does not prevent declining a still-current review body.
    pub fn decline_representation(
        &self,
        owner: &AuthenticatedOwner,
        review: &RepresentationReview,
        now: u64,
    ) -> Result<()> {
        require_owner(self, owner, &review.record.packet)?;
        let (record, body) = read_proposal(self, &review.id)?;
        if record != review.record || body.approval != ClaimApprovalStatus::Proposed {
            return Err(invalid());
        }
        self.resolve_gate_consent_bundle(
            owner,
            review.bundle_id,
            &record.run,
            GateConsentBundleAction::Decline,
            now,
        )?;
        Ok(())
    }
    /// Reloads approved state, including evidence and voice revisions. An
    /// ordinary inbox approval alone cannot mint this adapter's owner arm.
    pub fn approved_representation(&self, id: &EntityId) -> Result<ApprovedRepresentation> {
        let (record, body) = read_proposal(self, id)?;
        if body.approval != ClaimApprovalStatus::Approved {
            return Err(invalid());
        }
        validate_packet(self, &record.packet)?;
        let approval: ApprovalRecord = {
            let txn = self.store.env.read_txn()?;
            let approval = APPROVAL.get(&self.store, &txn, id)?.ok_or_else(invalid)?;
            require_owner_bundle_in(self, &txn, *id, &approval)?;
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
    if owner.actor() != packet.request.owner {
        return Err(invalid());
    }
    // Revalidate store truth and lifecycle instead of trusting an old handle
    // minted before its PERSON became a merged/split shell.
    vault.authenticate_owner(
        owner.actor(),
        owner.principal_ref(),
        true,
        owner.decision_id(),
    )?;
    Ok(())
}
fn require_owner_bundle_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    approval: &ApprovalRecord,
) -> Result<()> {
    let bundle_ref = format!(
        "bundle:{}",
        crate::entity_id::bytes_to_hex_lower(&approval.bundle_id)
    );
    let receipts = vault
        .store
        .gate_decisions_for_claim_in_txn(txn, id.as_bytes())?;
    if !receipts.iter().any(|r| {
        r.outcome == "approved"
            && r.grant_ref.as_deref() == Some(bundle_ref.as_str())
            && r.reason_codes
                .iter()
                .any(|s| s == crate::gate::GATE_BUNDLE_REASON_APPROVED)
            && r.redacted_at.is_none()
    }) {
        return Err(invalid());
    }
    Ok(())
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
        || facade.actor_class() != EdgeActorClass::Agent
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
        || request.actor.actor_class != "agent"
    {
        return Err(invalid());
    }
    Ok(())
}
