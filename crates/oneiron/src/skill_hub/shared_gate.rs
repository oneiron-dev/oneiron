//! Useful-upstream and held-out merge gate for submitted shared-skill deltas.
use super::{HubPackage, SharedSkillDelta, package_codec::invalid};
use crate::{
    Vault,
    consent::{
        AuthenticatedOwner, ComposedEffect, ConsentReceipt, EffectDigest, EffectFacts, UndoFidelity,
    },
    entity_id::EntityId,
    error::Result,
    skill::{SkillLifecycle, SkillRecord},
    skill_optimize::{HeldOutReplayCase, HeldOutReplayScorer},
    temporal::TimeRange,
};

/// The typed question precedes replay. A host judges only the offered package
/// against this receiving base; this interface has no personal-vault read handle.
pub trait UsefulUpstreamJudge {
    fn useful_upstream(
        &self,
        base: &SkillRecord,
        candidate: &HubPackage,
        delta: &SharedSkillDelta,
    ) -> Result<bool>;
}
#[derive(Debug, Clone)]
pub struct SharedSkillMergeAsk {
    candidate: EntityId,
    binding: String,
    effect: EffectDigest,
}
impl SharedSkillMergeAsk {
    #[must_use]
    pub const fn effect_digest(&self) -> EffectDigest {
        self.effect
    }
    #[must_use]
    pub const fn candidate(&self) -> EntityId {
        self.candidate
    }
}
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedSkillMergeReceipt {
    pub receipt_id: String,
    pub delta: SharedSkillDelta,
    pub consent_digest: String,
    pub binding: String,
    pub useful_upstream: bool,
    pub before: Option<f32>,
    pub after: Option<f32>,
    pub held_out_digest: String,
    pub accepted: bool,
    pub at: u64,
}
#[derive(Debug, Clone, PartialEq)]
pub enum SharedSkillMergeDisposition {
    PendingConsent,
    Ruled(Box<SharedSkillMergeReceipt>),
}
struct MergeSnapshot {
    delta: SharedSkillDelta,
    base_id: EntityId,
    base: SkillRecord,
    record: SkillRecord,
    package: HubPackage,
    baseline: String,
    evidence: Vec<String>,
    binding: String,
}
impl Vault {
    pub fn prepare_shared_skill_merge(&self, candidate: EntityId) -> Result<SharedSkillMergeAsk> {
        let txn = self.store.env.read_txn()?;
        let snapshot = self.shared_merge_snapshot(&txn, &candidate)?;
        let effect = ComposedEffect::new(
            EffectFacts::new(format!("skill.merge:{}", snapshot.binding))?
                .with_undo_fidelity(UndoFidelity::None),
        )
        .digest();
        Ok(SharedSkillMergeAsk {
            candidate,
            binding: snapshot.binding,
            effect,
        })
    }
    pub fn approve_shared_skill_merge(
        &self,
        ask: &SharedSkillMergeAsk,
        owner: &AuthenticatedOwner,
    ) -> Result<ConsentReceipt> {
        self.with_write_txn(|txn| {
            self.check_merge_ask(txn, ask)?;
            self.approve_once_in_txn(txn, owner, ask.effect)
        })
    }
    /// The one merge door. A caller cannot submit a bool or a precomputed score.
    /// Both host callbacks run without a read or write transaction held. Binding
    /// and human consent are rechecked when activation + supersession commit together.
    pub fn merge_shared_skill_delta(
        &self,
        ask: &SharedSkillMergeAsk,
        useful: &dyn UsefulUpstreamJudge,
        scorer: &dyn HeldOutReplayScorer,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<SharedSkillMergeDisposition> {
        let snapshot = {
            let txn = self.store.env.read_txn()?;
            let snapshot = self.check_merge_ask(&txn, ask)?;
            if crate::consent::approve_once_authorization_in_txn(&self.store, &txn, &ask.effect)?
                .is_none()
            {
                return Ok(SharedSkillMergeDisposition::PendingConsent);
            }
            snapshot
        };
        let useful_upstream =
            useful.useful_upstream(&snapshot.base, &snapshot.package, &snapshot.delta)?;
        let (before, after) = if useful_upstream {
            replay(scorer, &snapshot)?
        } else {
            (None, None)
        };
        let accepted = matches!((before, after), (Some(before), Some(after)) if after > before);
        let receipt = SharedSkillMergeReceipt {
            receipt_id: EntityId::now().to_hex(),
            delta: snapshot.delta.clone(),
            consent_digest: ask.effect.to_hex(),
            binding: ask.binding.clone(),
            useful_upstream,
            before,
            after,
            held_out_digest: crate::skill_optimize::held_out_receipt_set_digest(&snapshot.evidence),
            accepted,
            at: learned_at,
        };
        self.with_write_txn(|txn| {
            self.check_merge_ask(txn, ask)?;
            let authorization =
                crate::consent::approve_once_authorization_in_txn(&self.store, txn, &ask.effect)?
                    .ok_or_else(|| invalid("human merge consent is missing"))?;
            if accepted {
                self.activate_scored_hub_record_in_txn(
                    txn,
                    &ask.candidate,
                    &snapshot.record,
                    occurred,
                    learned_at,
                )?;
                self.supersede_skill_record_in_txn(
                    txn,
                    &snapshot.base_id,
                    &ask.candidate,
                    occurred,
                    learned_at,
                )?;
            }
            crate::consent::spend_approve_once_in_txn(&self.store, txn, &authorization)?;
            let encoded_receipt =
                serde_json::to_vec(&receipt).map_err(|_| invalid("merge receipt encode failed"))?;
            let mut history_key = b"skill_hub/shared-merge-history/v1\0".to_vec();
            history_key.extend_from_slice(receipt.receipt_id.as_bytes());
            self.store
                .vault_meta
                .put(txn, &history_key, &encoded_receipt)?;
            self.store.vault_meta.put(
                txn,
                &merge_receipt_key(&ask.candidate),
                &serde_json::to_vec(&receipt)
                    .map_err(|_| invalid("merge receipt encode failed"))?,
            )?;
            Ok(SharedSkillMergeDisposition::Ruled(Box::new(receipt)))
        })
    }
    pub fn shared_skill_merge_receipt(
        &self,
        candidate: &EntityId,
    ) -> Result<Option<SharedSkillMergeReceipt>> {
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, &merge_receipt_key(candidate))?
            .map(|raw| serde_json::from_slice(&raw).map_err(|_| invalid("invalid merge receipt")))
            .transpose()
    }
    fn check_merge_ask(
        &self,
        txn: &heed::RoTxn<'_>,
        ask: &SharedSkillMergeAsk,
    ) -> Result<MergeSnapshot> {
        let snapshot = self.shared_merge_snapshot(txn, &ask.candidate)?;
        if snapshot.binding != ask.binding {
            return Err(invalid(
                "merge content, baseline, evidence or scan posture moved",
            ));
        }
        Ok(snapshot)
    }
    fn shared_merge_snapshot(
        &self,
        txn: &heed::RoTxn<'_>,
        candidate: &EntityId,
    ) -> Result<MergeSnapshot> {
        let delta = self
            .delta_in_txn(txn, candidate)?
            .ok_or_else(|| invalid("no submitted delta"))?;
        let base_id = EntityId::from_hex(&delta.base)?;
        let base = super::admission_view::read_skill(self, txn, &base_id)?;
        let record = super::admission_view::read_skill(self, txn, candidate)?;
        let package = self.stored_hub_package_in_txn(txn, candidate)?;
        if base.lifecycle_status != SkillLifecycle::Active
            || record.lifecycle_status != SkillLifecycle::Candidate
            || crate::skill_optimize::skill_body_binding_digest(&base)? != delta.base_binding
            || base
                .governance_tier
                .is_some_and(crate::skill::SkillGovernanceTier::is_protected)
            || record
                .governance_tier
                .is_some_and(crate::skill::SkillGovernanceTier::is_protected)
            || record.approval_status == crate::claim::ClaimApprovalStatus::Rejected
            || package.content_hash()?.to_hex() != delta.content_hash
            || record.content_hash != Some(package.content_hash()?)
            || record.skill_id != package.record.skill_id
            || record.version != package.record.version
            || record.desc != package.record.desc
            || record.skill_id != base.skill_id
            || record.version == base.version
        {
            return Err(invalid("shared delta no longer revises its admitted base"));
        }
        let baseline = self.hub_baseline_instructions(txn, &base_id, &base)?;
        let evidence = crate::skill_reliability::attributed_outcome_receipts(self, txn, &base_id)?
            .into_iter()
            .filter(|r| crate::skill_optimize::receipt_is_held_out(&base_id, r))
            .collect::<Vec<_>>();
        if evidence.is_empty() || evidence.len() > 4096 {
            return Err(invalid("no bounded held-out reserve for shared base"));
        }
        let scan = crate::skill_scan::scan_gate_for_activation_in_txn(
            &self.store,
            txn,
            package.content_hash()?,
        )?;
        let mut hash = blake3::Hasher::new_derive_key("oneiron.shared-skill.merge.v1");
        for part in [
            candidate.as_bytes().to_vec(),
            serde_json::to_vec(&delta).map_err(|_| invalid("delta encode failed"))?,
            crate::skill::encode_skill_record(&base)?,
            baseline.as_bytes().to_vec(),
            crate::skill::encode_skill_record(&record)?,
            super::encode_hub_package(&package)?,
            format!("{scan:?}").into_bytes(),
            crate::skill_optimize::held_out_receipt_set_digest(&evidence).into_bytes(),
        ] {
            hash.update(&(part.len() as u64).to_be_bytes());
            hash.update(&part);
        }
        Ok(MergeSnapshot {
            delta,
            base_id,
            base,
            record,
            package,
            baseline,
            evidence,
            binding: hash.finalize().to_hex().to_string(),
        })
    }
}
fn replay(
    scorer: &dyn HeldOutReplayScorer,
    snapshot: &MergeSnapshot,
) -> Result<(Option<f32>, Option<f32>)> {
    let instructions = snapshot
        .package
        .files
        .iter()
        .find(|f| f.path == "SKILL.md")
        .ok_or_else(|| invalid("delta has no instructions"))?;
    let instructions = std::str::from_utf8(&instructions.content)
        .map_err(|_| invalid("delta instructions are not UTF-8"))?;
    let evaluate = |version: &str, instructions: &str| -> Result<f32> {
        let value = scorer.score(&HeldOutReplayCase {
            skill: snapshot.base_id,
            skill_id: &snapshot.base.skill_id,
            version,
            instructions,
            held_out_receipts: &snapshot.evidence,
        })?;
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            return Err(invalid("invalid host held-out score"));
        }
        Ok(value)
    };
    Ok((
        Some(evaluate(&snapshot.base.version, &snapshot.baseline)?),
        Some(evaluate(&snapshot.record.version, instructions)?),
    ))
}
fn merge_receipt_key(id: &EntityId) -> Vec<u8> {
    let mut key = b"skill_hub/shared-merge-receipt/v1\0".to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}
