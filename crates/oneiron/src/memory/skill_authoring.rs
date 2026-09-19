//! Authored skill saves and forks over the existing skill lifecycle gate.

use super::authorship::*;
use super::{Memory, MemoryResult};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::error::Error;
use crate::skill::{SkillLifecycle, SkillRecord};
use crate::temporal::TimeRange;
use crate::{EntityId, WriteActor};
use rmpv::Value;
use serde::{Deserialize, Serialize};

const AUTHOR_KIND: &str = "memory_skill_author";
const AUTHOR_PROOF: &str = "memoryAuthorDecision";

/// The skill and its immutable birth-author receipt, not an activation grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillAuthoringReceipt {
    #[serde(with = "super::authorship::entity_serde")]
    pub skill_id: EntityId,
    #[serde(with = "super::authorship::entity_serde")]
    pub author: EntityId,
    pub author_receipt: String,
    pub version: String,
}

fn author_proof(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    record: &SkillRecord,
) -> Result<(EntityId, crate::store::GateDecisionId), Error> {
    let Value::Map(entries) = &record.provenance else {
        return Err(authority_denied("skill author proof is missing"));
    };
    let mut proofs = entries
        .iter()
        .filter(|(k, _)| k.as_str() == Some(AUTHOR_PROOF));
    let proof = proofs
        .next()
        .and_then(|(_, v)| v.as_str())
        .ok_or_else(|| authority_denied("skill author proof is missing; fork it"))?;
    if proofs.next().is_some() {
        return Err(authority_denied("ambiguous skill author proof"));
    }
    for receipt in vault
        .store
        .gate_decisions_for_claim_in_txn(txn, id.as_bytes())?
    {
        if receipt.content_kind == AUTHOR_KIND
            && receipt.decision_id.to_hex() == proof
            && receipt.redacted_at.is_none()
        {
            let author = receipt
                .actor_ref
                .as_deref()
                .and_then(|s| EntityId::from_hex(s).ok())
                .ok_or(Error::CorruptedIndex("skill author receipt"))?;
            return Ok((author, receipt.decision_id));
        }
    }
    Err(authority_denied(
        "skill author proof has no matching durable receipt",
    ))
}

impl Memory<'_> {
    /// Saves a candidate. The actor and provenance proof are derived, never
    /// taken from caller-supplied authorship flags. Editing admitted content
    /// requires a new candidate fork and the existing held-out admission gate.
    /// `expected_version` is mandatory on update and absent on creation.
    pub fn skill_save(
        &self,
        id: EntityId,
        proposed: &SkillRecord,
        expected_version: Option<&str>,
        now: u64,
    ) -> MemoryResult<SkillAuthoringReceipt> {
        self.with_verified_actor_write_txn(|txn| {
            let actor = WriteActor::new(self.actor, self.actor_class);
            verify_live_actor(self.vault, txn, actor)?;
            if self.vault.local_hard_delete_marker_exists_in_txn(txn, &id)? { return Err(super::hard_deleted_refusal(&id)); }
            let mut record = proposed.clone();
            let proof = if self.vault.get_raw_in(txn, &id)?.is_some() {
                let stored = self.vault.read_skill_record_in_txn(txn, &id)?;
                let (author, proof) = author_proof(self.vault, txn, id, &stored)?;
                require_authorship_in_txn(self.vault, txn, actor, id, Some(author), "memory.skill.edit")?;
                if expected_version != Some(stored.version.as_str()) { return Err(Error::ConcurrentWrite("skill version changed").into()); }
                if stored.lifecycle_status != SkillLifecycle::Candidate
                    || record.lifecycle_status != stored.lifecycle_status
                    || record.approval_status != stored.approval_status
                    || record.governance_tier != stored.governance_tier
                    || record.provenance != stored.provenance {
                    return Err(authority_denied("self-Grant changes candidate content, not admission, governance or attribution").into());
                }
                self.vault.put_skill_record_in_txn(txn, &id, &record, TimeRange { start: now, end: now }, now)?;
                (author, proof)
            } else {
                if expected_version.is_some() { return Err(Error::EntityNotFound.into()); }
                if record.forked_from.is_some() { return Err(authority_denied("fork lineage must be created by skill_fork").into()); }
                require_authorship_in_txn(self.vault, txn, actor, id, Some(self.actor), "memory.skill.create")?;
                self.birth_skill_in_txn(txn, id, &mut record, now)?
            };
            Ok(SkillAuthoringReceipt { skill_id: id, author: proof.0, author_receipt: format!("gate:{}", proof.1.to_hex()), version: record.version })
        })
    }

    /// Forks a stored skill in one transaction. Import ancestry remains
    /// visible. The fork is generated for agent/daemon callers, never relabeled
    /// human-authored merely because the native owner fork door does so.
    pub fn skill_fork(
        &self,
        parent: EntityId,
        id: EntityId,
        skill_id: &str,
        now: u64,
    ) -> MemoryResult<SkillAuthoringReceipt> {
        self.with_verified_actor_write_txn(|txn| {
            let actor = WriteActor::new(self.actor, self.actor_class);
            verify_live_actor(self.vault, txn, actor)?;
            require_authorship_in_txn(
                self.vault,
                txn,
                actor,
                parent,
                Some(self.actor),
                "memory.skill.fork",
            )?;
            if self
                .vault
                .local_hard_delete_marker_exists_in_txn(txn, &id)?
            {
                return Err(super::hard_deleted_refusal(&id));
            }
            if self.vault.get_raw_in(txn, &id)?.is_some() {
                return Err(Error::ConcurrentWrite("skill fork target already exists").into());
            }
            let stored = self.vault.read_skill_record_in_txn(txn, &parent)?;
            if stored.skill_id == skill_id {
                return Err(authority_denied("fork must use its own skill identity").into());
            }
            let mut record = SkillRecord::new(
                skill_id,
                stored.desc.clone(),
                "1",
                ClaimApprovalStatus::Proposed,
                SkillLifecycle::Candidate,
                ClaimSource::Generated,
                1.0,
                true,
                false,
                stored.dependencies,
                Value::Map(vec![
                    (Value::from("forkOfEntity"), Value::from(parent.to_hex())),
                    (Value::from("forkOfVersion"), Value::from(stored.version)),
                    (Value::from("upstreamProvenance"), stored.provenance),
                ]),
            );
            record.forked_from = Some(parent);
            let (author, proof) = self.birth_skill_in_txn(txn, id, &mut record, now)?;
            self.vault
                .batch_in()
                .edge(
                    &id,
                    EdgeKind::DerivedFrom,
                    &parent,
                    EdgeKind::DerivedFrom.default_weight().unwrap_or(0.2),
                )
                .apply(txn)?;
            Ok(SkillAuthoringReceipt {
                skill_id: id,
                author,
                author_receipt: format!("gate:{}", proof.to_hex()),
                version: record.version,
            })
        })
    }

    fn birth_skill_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        record: &mut SkillRecord,
        now: u64,
    ) -> MemoryResult<(EntityId, crate::store::GateDecisionId)> {
        let actor = WriteActor::new(self.actor, self.actor_class);
        record.source = if self.actor_class == EdgeActorClass::Human {
            ClaimSource::UserStated
        } else {
            ClaimSource::Generated
        };
        record.generated = self.actor_class != EdgeActorClass::Human;
        record.human_authored = !record.generated;
        record.lifecycle_status = SkillLifecycle::Candidate;
        record.approval_status = ClaimApprovalStatus::Proposed;
        record.governance_tier = None;
        let mut receipt = decision(
            actor,
            AUTHOR_KIND,
            "recorded",
            "gate.memory.skill_authored",
            Some(id),
            vec![1],
            now,
        );
        let Value::Map(entries) = &mut record.provenance else {
            return Err(authority_denied("skill provenance must be a map").into());
        };
        if entries
            .iter()
            .any(|(k, _)| k.as_str() == Some(AUTHOR_PROOF))
        {
            return Err(authority_denied("caller cannot supply a skill author proof").into());
        }
        entries.push((
            Value::from(AUTHOR_PROOF),
            Value::from(receipt.decision_id.to_hex()),
        ));
        let data = crate::skill::encode_skill_record(record)?;
        receipt.diff_handle = blake3::hash(&data).as_bytes().to_vec();
        self.vault.put_skill_record_in_txn(
            txn,
            &id,
            record,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )?;
        self.vault
            .store
            .append_gate_decision_in_txn(txn, &receipt)?;
        Ok((self.actor, receipt.decision_id))
    }
}
