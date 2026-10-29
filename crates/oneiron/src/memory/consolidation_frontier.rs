//! Typed reference frontiers and the root's immutable evidence-accounting receipts.
use serde::{Deserialize, Serialize};

use crate::claim::ClaimSource;
use crate::dreamer_promotion::PromotionEvidenceReason;
use crate::memory::consolidation::ConsolidationMessageEvidence;

/// The canon's six-axis consolidation bucket. References are full entity ids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationRootBucket {
    pub subject: String,
    pub predicate_root: String,
    pub world: Option<String>,
    pub facet: Option<String>,
    pub relationship: Option<String>,
    pub project: String,
}

/// A child's reference, never child-authored bytes, hashes or trust labels.
/// Exactly one of claim_id and byte_range must be present.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationReference {
    pub source_id: String,
    pub claim_id: Option<String>,
    pub byte_range: Option<(usize, usize)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationRootInput {
    pub bucket: ConsolidationRootBucket,
    pub evidence: Vec<ConsolidationReference>,
}

/// Admit every reference before children finish, at one root-owned revision.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationPinRequest {
    pub buckets: Vec<ConsolidationRootInput>,
}

/// Judgements remain proposals. This door cannot settle a belief or choose
/// the writer's source, actor, approval, evidence taint or provenance.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationJudgement {
    pub predicate: String,
    pub value: serde_json::Value,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationChildFrontier {
    pub child_ref: String,
    pub bucket_hash: [u8; 32],
    pub judgement: ConsolidationJudgement,
    pub evidence: Vec<ConsolidationReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationFrontierRequest {
    pub root_ref: String,
    pub children: Vec<ConsolidationChildFrontier>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationAccountingRequest {
    pub root_ref: String,
}

/// A stored ancestor's classification at the root's pin, including the
/// edge.provenance claims on each derived_from edge the root followed.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationAncestor {
    pub source_ref: String,
    pub source_revision: [u8; 32],
    pub trust_class: ClaimSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationRootEvidence {
    pub reference: ConsolidationReference,
    pub source_revision: [u8; 32],
    pub content_hash: [u8; 32],
    pub trust_class: ClaimSource,
    pub corroborates: bool,
    pub refusal: Option<PromotionEvidenceReason>,
    pub ancestors: Vec<ConsolidationAncestor>,
    pub messages: Vec<ConsolidationMessageEvidence>,
}

/// The root keeps a digest, not another copy of child-authored prose.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationChildReceipt {
    pub child_ref: String,
    pub judgement_hash: [u8; 32],
    pub evidence: Vec<ConsolidationReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationBucketAccounting {
    pub bucket: ConsolidationRootBucket,
    pub bucket_hash: [u8; 32],
    pub pinned: Vec<ConsolidationRootEvidence>,
    pub children: Vec<ConsolidationChildReceipt>,
    pub independent: Vec<ConsolidationRootEvidence>,
    pub duplicates_collapsed: u32,
    pub excluded_references: u32,
    pub source_meet: ClaimSource,
}

/// revision is the committed LMDB revision the root read before pinning,
/// never a child-supplied cursor. Later reads return these original facts;
/// current read authority is still checked. No raw source text is copied.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationRootAccounting {
    pub root_ref: String,
    pub revision: u64,
    pub buckets: Vec<ConsolidationBucketAccounting>,
}

impl super::Memory<'_> {
    fn consolidation_root_owner_in_txn(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        txn: &heed::RoTxn<'_>,
    ) -> super::MemoryResult<crate::EntityId> {
        let actor = owner.revalidate_in_txn(self.vault, txn)?;
        if actor != self.actor || self.actor_class != crate::EdgeActorClass::Human {
            return Err(super::MemoryError::new(
                super::MEMORY_CODE_FORBIDDEN,
                "consolidation root acts through the owner's own credential",
                &["Present the owner's own verified, unattenuated credential."],
            ));
        }
        Ok(actor)
    }

    /// Pins every bucket and reference, however many (Rule 5, FIX 8698), in
    /// this operation's fair task-work turn, at one frozen revision.
    pub fn consolidation_pin_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        input: &ConsolidationPinRequest,
    ) -> super::MemoryResult<ConsolidationRootAccounting> {
        if !self.has_task_work_turn() {
            return self
                .task_work_memory()
                .consolidation_pin_as_owner(owner, input);
        }
        let read = self.read_lane(crate::claim::ClaimReadStatus::Recorded)?;
        let accounting = crate::dreamer_consolidation::root_evidence::pin_frozen(
            self.vault,
            &read,
            input,
            |txn| self.consolidation_root_owner_in_txn(owner, txn),
        )?;
        self.produced_from(crate::dreamer_consolidation::root_evidence::source_ids(
            &accounting,
        )?);
        Ok(accounting)
    }

    /// Lands every child and citation, however many (Rule 5, FIX 8698), in
    /// this operation's fair task-work turn, against the root's own pins.
    pub fn consolidation_frontier_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        input: &ConsolidationFrontierRequest,
    ) -> super::MemoryResult<ConsolidationRootAccounting> {
        if !self.has_task_work_turn() {
            return self
                .task_work_memory()
                .consolidation_frontier_as_owner(owner, input);
        }
        let read = self.read_lane(crate::claim::ClaimReadStatus::Recorded)?;
        let accounting = crate::dreamer_consolidation::root_evidence::frontier_frozen(
            self.vault,
            &read,
            input,
            |txn| self.consolidation_root_owner_in_txn(owner, txn),
        )?;
        self.produced_from(crate::dreamer_consolidation::root_evidence::source_ids(
            &accounting,
        )?);
        Ok(accounting)
    }

    pub fn consolidation_accounting_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        input: &ConsolidationAccountingRequest,
    ) -> super::MemoryResult<ConsolidationRootAccounting> {
        let read = self.read_lane(crate::claim::ClaimReadStatus::Recorded)?;
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let actor = self.consolidation_root_owner_in_txn(owner, &txn)?;
        let accounting = crate::dreamer_consolidation::root_evidence::accounting_in_txn(
            self.vault,
            &read,
            &txn,
            actor,
            &input.root_ref,
        )?;
        self.produced_from(crate::dreamer_consolidation::root_evidence::source_ids(
            &accounting,
        )?);
        Ok(accounting)
    }
}
