//! Useful-upstream and held-out merge gate for submitted shared-skill deltas.
use super::refinement_admission::{
    RefinementAdmissionProof, RefinementState, RefinementTarget, put_control, read_control,
};
use super::refinement_custody::RefinementReceipt;
use super::{HubPackage, SharedSkillDelta, package_codec::invalid};
use crate::{
    Vault,
    consent::{AuthenticatedOwner, ComposedEffect, ConsentReceipt, EffectDigest, EffectFacts},
    entity_id::EntityId,
    error::Result,
    llm::decision::{
        AnswerContract, DecisionAnswer, DecisionClass, DecisionQuestion, DecisionRung,
        TypedDecision,
    },
    skill::{SkillLifecycle, SkillRecord},
    skill_optimize::{HeldOutReplayCase, HeldOutReplayScorer},
    temporal::TimeRange,
};

/// The host's OF-493 answerer runs the configured typed question with a System One
/// seat first. It sees submitted bytes, never the branch vault. The gate checks
/// its typed receipt before any held-out replay or state change.
pub trait UsefulUpstreamJudge {
    fn decide(
        &self,
        question: &DecisionQuestion,
        resident: EntityId,
        base: &SkillRecord,
        candidate: &HubPackage,
        delta: &SharedSkillDelta,
    ) -> Result<TypedDecision>;
}
#[derive(Debug, Clone)]
pub struct SharedSkillMergeAsk {
    candidate: EntityId,
    binding: String,
    resident: EntityId,
    question: DecisionQuestion,
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
    pub resident: String,
    pub question: DecisionQuestion,
    pub decision: TypedDecision,
    pub before: Option<f32>,
    pub after: Option<f32>,
    pub held_out_digest: String,
    pub accepted: bool,
    pub judge_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub displaced_by_revision: Option<String>,
    pub at: u64,
}
#[derive(Debug, Clone, PartialEq)]
pub enum SharedSkillMergeDisposition {
    /// The delta widens the skill's permissions, and a widening answers the
    /// fit ladder's ask rung: the owner approves this exact effect once.
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
    pub fn prepare_shared_skill_merge(
        &self,
        candidate: EntityId,
        resident: EntityId,
        question: DecisionQuestion,
    ) -> Result<SharedSkillMergeAsk> {
        question.validate()?;
        crate::batch::secret_scan::scan_staged_payload(
            &self.store,
            &serde_json::to_vec(&question).map_err(|_| invalid("question encode failed"))?,
        )?;
        if question.id != candidate
            || question.class != DecisionClass::UsefulUpstream
            || !matches!(question.contract, AnswerContract::Noul)
            || question.accept_type
            || self.get_entity_type(&resident)? != Some(crate::registry::ENTITY_TYPE_AGENT_DEF)
        {
            return Err(invalid(
                "merge needs a resident's useful-upstream yes/no question",
            ));
        }
        let txn = self.store.env.read_txn()?;
        let snapshot = self.shared_merge_snapshot(&txn, &candidate)?;
        // A merge is reversible (ARCH-0053 r4, DEC-0006): activation
        // supersedes, the old revision stays readable, and
        // `roll_back_shared_skill_merge` restores it. The effect keeps the
        // default full undo fidelity.
        let effect = ComposedEffect::new(EffectFacts::new(format!(
            "skill.merge:{}:{}:{}",
            snapshot.binding,
            resident.to_hex(),
            blake3::hash(
                &serde_json::to_vec(&question).map_err(|_| invalid("question encode failed"))?
            )
        ))?)
        .digest();
        Ok(SharedSkillMergeAsk {
            candidate,
            binding: snapshot.binding,
            resident,
            question,
            effect,
        })
    }
    /// The owner's answer to a merge whose delta widens the skill's
    /// permissions. A merge that keeps or narrows them needs no answer.
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
    /// The typed useful-upstream decision and the held-out replay are the gate;
    /// no per-merge approval exists, because the merge is reversible (ARCH-0053
    /// r4, ARCH-0043: "No publish step exists"). A delta that widens the skill's
    /// permissions still asks, like any widening: it returns `PendingConsent`
    /// until the owner approves that exact effect.
    /// Both host callbacks run without a read or write transaction held. The
    /// binding, and any widening answer, are rechecked when activation +
    /// supersession commit together.
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
            if self.merge_widens_permissions_in_txn(&txn, &snapshot)?
                && crate::consent::approve_once_authorization_in_txn(
                    &self.store,
                    &txn,
                    &ask.effect,
                )?
                .is_none()
            {
                return Ok(SharedSkillMergeDisposition::PendingConsent);
            }
            snapshot
        };
        let decision = useful.decide(
            &ask.question,
            ask.resident,
            &snapshot.base,
            &snapshot.package,
            &snapshot.delta,
        )?;
        let useful_upstream = checked_useful_decision(&ask.question, ask.resident, &decision)?;
        let judge_revision = if useful_upstream {
            let revision = scorer.judge_revision().to_owned();
            crate::skill_optimize::validate_judge_revision(&revision)?;
            Some(revision)
        } else {
            None
        };
        let (before, after) = if useful_upstream {
            replay(scorer, &snapshot)?
        } else {
            (None, None)
        };
        if judge_revision
            .as_deref()
            .is_some_and(|revision| scorer.judge_revision() != revision)
        {
            return Err(invalid("shared-merge judge revision moved during scoring"));
        }
        let accepted = matches!((before, after), (Some(before), Some(after)) if after > before);
        let receipt = SharedSkillMergeReceipt {
            receipt_id: EntityId::now().to_hex(),
            delta: snapshot.delta.clone(),
            consent_digest: ask.effect.to_hex(),
            binding: ask.binding.clone(),
            useful_upstream,
            resident: ask.resident.to_hex(),
            question: ask.question.clone(),
            decision,
            before,
            after,
            held_out_digest: crate::skill_optimize::held_out_receipt_set_digest(&snapshot.evidence),
            accepted,
            judge_revision: judge_revision.clone(),
            displaced_by_revision: None,
            at: learned_at,
        };
        // A host-supplied provider pin or question can contain secret-shaped
        // text even on a no. Scan the entire durable receipt before consent
        // spend, activation, supersession, or history write.
        let encoded_receipt =
            serde_json::to_vec(&receipt).map_err(|_| invalid("merge receipt encode failed"))?;
        crate::batch::secret_scan::scan_staged_payload(&self.store, &encoded_receipt)?;
        self.with_write_txn(|txn| {
            if let Some(revision) = &judge_revision {
                crate::skill_optimize::ensure_current_judge_in_txn(self, txn, revision)?;
            }
            let current = self.check_merge_ask(txn, ask)?;
            let widening = if self.merge_widens_permissions_in_txn(txn, &current)? {
                Some(
                    crate::consent::approve_once_authorization_in_txn(
                        &self.store,
                        txn,
                        &ask.effect,
                    )?
                    .ok_or_else(|| invalid("the owner's permission answer is missing"))?,
                )
            } else {
                None
            };
            let mut control = read_control(&self.store, txn, &ask.candidate)?
                .ok_or_else(|| invalid("shared refinement control is missing"))?;
            if accepted {
                let mut admitted = snapshot.record.clone();
                admitted.approval_status = crate::claim::ClaimApprovalStatus::Approved;
                admitted.lifecycle_status = SkillLifecycle::Active;
                let data = crate::skill::encode_skill_record(&admitted)?;
                let refinement = RefinementAdmissionProof::for_skill(
                    ask.candidate,
                    snapshot.base_id,
                    &data,
                    &control.proposal_binding,
                    &receipt,
                )?;
                self.activate_refined_hub_record_in_txn(
                    txn,
                    &snapshot.record,
                    occurred,
                    learned_at,
                    refinement,
                )?;
                self.supersede_skill_record_in_txn(
                    txn,
                    &snapshot.base_id,
                    &ask.candidate,
                    occurred,
                    learned_at,
                )?;
            }
            if let Some(authorization) = &widening {
                crate::consent::spend_approve_once_in_txn(&self.store, txn, authorization)?;
            }
            control.state = if accepted {
                RefinementState::Admitted
            } else {
                RefinementState::Refused
            };
            put_control(&self.store, txn, &ask.candidate, &control)?;
            self.put_refinement_receipt_in_txn(
                txn,
                ask.candidate,
                RefinementReceipt::Skill(receipt.clone()),
                occurred,
                learned_at,
            )?;
            Ok(SharedSkillMergeDisposition::Ruled(Box::new(receipt)))
        })
    }
    /// Rolls back an admitted shared-skill merge. Rollback is supersede,
    /// archive, fork (ARCH-0053), and a superseded revision never loads as
    /// canon again, so the displaced revision is not revived: a new revision
    /// carrying its content, under a fresh version, supersedes the merged one
    /// and links `DerivedFrom` the revision it restores. Both earlier
    /// revisions stay readable. Returns the restoring revision.
    ///
    /// Refuses unless `merged` is the active revision a shared merge admitted.
    /// Once a later revision has superseded it, roll that one back instead.
    /// A protected (identity/alignment) revision never rolls back here, as it
    /// never merges here: the owner edits it by hand.
    pub fn roll_back_shared_skill_merge(
        &self,
        merged: &EntityId,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        let restore = EntityId::now();
        self.with_write_txn(|txn| {
            let not_rollbackable =
                || invalid("only the active revision a shared merge admitted rolls back");
            let control = read_control(&self.store, txn, merged)?.ok_or_else(not_rollbackable)?;
            let RefinementTarget::Skill { base, .. } = &control.target else {
                return Err(not_rollbackable());
            };
            let base = EntityId::from_hex(base).map_err(|_| invalid("merge base is malformed"))?;
            let current = self.read_skill_record_in_txn(txn, merged)?;
            let displaced = self.read_skill_record_in_txn(txn, &base)?;
            let protected = |record: &SkillRecord| {
                record
                    .governance_tier
                    .is_some_and(crate::skill::SkillGovernanceTier::is_protected)
            };
            if control.state != RefinementState::Admitted
                || current.lifecycle_status != SkillLifecycle::Active
                || displaced.lifecycle_status != SkillLifecycle::Superseded
                || protected(&current)
                || protected(&displaced)
            {
                return Err(not_rollbackable());
            }
            let mut record = displaced.clone();
            record.version = restore_version(&displaced.version, merged);
            // The rollback restores content; the current governance state stays.
            record.governance_tier = current.governance_tier;
            record.lifecycle_status = SkillLifecycle::Candidate;
            record.approval_status = crate::claim::ClaimApprovalStatus::Proposed;
            let mut provenance = match &displaced.provenance {
                rmpv::Value::Map(entries) => entries
                    .iter()
                    .filter(|(key, _)| !matches!(key.as_str(), Some("source" | "restores")))
                    .cloned()
                    .collect(),
                _ => Vec::new(),
            };
            provenance.push(("source".into(), "shared-skill-rollback".into()));
            provenance.push(("restores".into(), base.to_hex().into()));
            record.provenance = rmpv::Value::Map(provenance);
            let package = self
                .export_hub_package_in_txn(txn, &base)?
                .map(|package| restored_package(&package, &record))
                .transpose()?;
            record.content_hash = package.as_ref().map(HubPackage::content_hash).transpose()?;
            self.put_skill_record_in_txn(txn, &restore, &record, occurred, learned_at)?;
            if let Some(package) = &package {
                self.persist_hub_package_in_txn(txn, &restore, package)?;
                let hash = package.content_hash()?;
                self.scan_and_ingest_on_import_in_txn(
                    txn, &restore, hash, package, occurred, learned_at,
                )?;
            }
            if let Some(surface) = self.read_admitted_capability_surface_in_txn(txn, &base)? {
                self.write_admitted_capability_surface_in_txn(txn, &restore, &surface)?;
            }
            record.lifecycle_status = SkillLifecycle::Active;
            record.approval_status = crate::claim::ClaimApprovalStatus::Approved;
            let data = crate::skill::encode_skill_record(&record)?;
            let proof = super::HubAdmissionProof::rollback(restore, &data);
            self.admit_hub_skill_record_in_txn(txn, occurred, learned_at, data, proof)?;
            self.batch_in()
                .edge(
                    &restore,
                    crate::edge::EdgeKind::DerivedFrom,
                    &base,
                    crate::edge::EdgeKind::DerivedFrom
                        .default_weight()
                        .unwrap_or(0.2),
                )
                .apply(txn)?;
            self.supersede_skill_record_in_txn(txn, merged, &restore, occurred, learned_at)?;
            Ok(restore)
        })
    }
    pub fn shared_skill_merge_receipt(
        &self,
        candidate: &EntityId,
    ) -> Result<Option<SharedSkillMergeReceipt>> {
        let txn = self.store.env.read_txn()?;
        let mut receipt = match self.latest_refinement_receipt_in_txn(&txn, *candidate)? {
            Some(RefinementReceipt::Skill(receipt)) => Some(receipt),
            Some(RefinementReceipt::Claim(_)) => {
                return Err(invalid("wrong refinement receipt target"));
            }
            None => None,
        };
        if let Some(row) = receipt.as_mut()
            && let Some(revision) = &row.judge_revision
        {
            row.displaced_by_revision =
                crate::skill_optimize::displaced_judge_revision_in_txn(self, &txn, revision)?;
        }
        Ok(receipt)
    }
    /// A widening is any capability the candidate declares beyond the base's
    /// admitted surface. A base with no admitted surface admits none, so every
    /// declared capability then widens.
    fn merge_widens_permissions_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        snapshot: &MergeSnapshot,
    ) -> Result<bool> {
        let admitted = self
            .read_admitted_capability_surface_in_txn(txn, &snapshot.base_id)?
            .unwrap_or_default();
        Ok(!snapshot
            .package
            .capabilities
            .is_same_or_narrower_than(&admitted))
    }
    fn check_merge_ask(
        &self,
        txn: &heed::RoTxn<'_>,
        ask: &SharedSkillMergeAsk,
    ) -> Result<MergeSnapshot> {
        let snapshot = self.shared_merge_snapshot(txn, &ask.candidate)?;
        let resident_is_agent =
            crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, &ask.resident)?
                .and_then(|raw| crate::batch::EntityMetadataHeader::parse(&raw))
                .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_AGENT_DEF);
        if !resident_is_agent {
            return Err(invalid("merge resident is no longer an agent"));
        }
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
        let control = read_control(&self.store, txn, candidate)?
            .ok_or_else(|| invalid("shared refinement control is missing"))?;
        if !matches!(
            control.state,
            RefinementState::Pending | RefinementState::Refused
        ) || !matches!(&control.target, RefinementTarget::Skill { base, fork }
                if base == &delta.base && fork == &delta.submitted_fork)
            || control.base_binding != delta.base_binding
            || control.proposal_binding != delta.content_hash
        {
            return Err(invalid("shared refinement control moved"));
        }
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
/// Do not turn a host-provided bool or a different question's verdict into
/// authority. Abstention and malformed provenance leave the branch untouched.
pub(super) fn checked_useful_decision(
    question: &DecisionQuestion,
    resident: EntityId,
    decision: &TypedDecision,
) -> Result<bool> {
    let receipt = &decision.receipt;
    if receipt.question != question.id
        || receipt.question_version != question.version
        || receipt.principal != resident
        || receipt
            .providers
            .first()
            .is_none_or(|p| p.rung != DecisionRung::SystemOne)
        || receipt
            .providers
            .iter()
            .any(|p| p.model.trim().is_empty() || p.version.trim().is_empty())
        || receipt.band.validate().is_err()
        || decision
            .probability
            .is_none_or(|p| !p.is_finite() || !(0.0..=1.0).contains(&p))
        || decision.in_band
            != receipt
                .band
                .contains(decision.probability.unwrap_or_default())
        || !question.contract.accepts(&decision.answer)
    {
        return Err(invalid(
            "unbound or malformed System One useful-upstream answer",
        ));
    }
    match decision.answer {
        DecisionAnswer::Noul(value) => Ok(value),
        _ => Err(invalid("useful-upstream answer must be yes or no")),
    }
}

/// The rollback's version: fresh, and bounded like any skill version. It
/// names the displaced version while that fits; provenance names the revision.
fn restore_version(displaced: &str, merged: &EntityId) -> String {
    let suffix = format!("restore-{}", &merged.to_hex()[..12]);
    if displaced.len() + 1 + suffix.len() <= crate::skill::SKILL_VERSION_MAX_BYTES {
        format!("{displaced}-{suffix}")
    } else {
        suffix
    }
}

/// The displaced revision's package under the restoring record. A folder
/// package carries its version in SKILL.md frontmatter, so that one line
/// changes; a native package keeps its exact bytes, since its version is
/// native metadata.
fn restored_package(package: &HubPackage, record: &SkillRecord) -> Result<HubPackage> {
    let (files, hash) = match package.format {
        super::SkillPackageFormat::Native => (package.files.clone(), package.content_hash()?),
        super::SkillPackageFormat::Folder => {
            let files = with_frontmatter_version(&package.files, &record.version)?;
            let hash = super::folder::package_from_files(files.clone())?.content_hash()?;
            (files, hash)
        }
    };
    let mut record = record.clone();
    record.content_hash = Some(hash);
    super::folder::package_from_source(&record, files, package.format)
}

fn with_frontmatter_version(
    files: &[super::HubFile],
    version: &str,
) -> Result<Vec<super::HubFile>> {
    let mut files = files.to_vec();
    let file = files
        .iter_mut()
        .find(|file| file.path == "SKILL.md")
        .ok_or_else(|| invalid("restored revision has no instructions"))?;
    let text = std::str::from_utf8(&file.content)
        .map_err(|_| invalid("restored instructions are not UTF-8"))?;
    let (front, body) = text
        .strip_prefix("---\n")
        .and_then(|rest| rest.split_once("\n---\n"))
        .ok_or_else(|| invalid("SKILL.md needs frontmatter"))?;
    // Only a plainly safe version is written bare; any other is written
    // JSON-quoted, the one quoted form the frontmatter reader decodes exactly.
    let scalar = if version
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+' | '~'))
    {
        version.to_owned()
    } else {
        serde_json::to_string(version).map_err(|_| invalid("restored version encode failed"))?
    };
    let mut versioned = false;
    let front = front
        .lines()
        .map(|line| {
            if !versioned && line.starts_with("version:") {
                versioned = true;
                format!("version: {scalar}")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    if !versioned {
        return Err(invalid("SKILL.md frontmatter has no version"));
    }
    file.content = format!("---\n{front}\n---\n{body}").into_bytes();
    Ok(files)
}
