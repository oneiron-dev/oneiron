//! The optimizer's candidate is a Proposed artifact beside the live skill.
use super::brief::{SkillOptimizeAuthor, SkillOptimizeBrief};
use super::gate::SkillEditCycle;
use crate::artifact_hosting::{ArtifactBirthBody, ArtifactPurpose, ArtifactTrigger};
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::error::Result;
use crate::skill::SkillRecord;
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

#[expect(
    clippy::too_many_arguments,
    reason = "candidate and artifact share the optimizer transaction"
)]
pub(super) fn persist_candidate_artifact(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    proposal: EntityId,
    skill: EntityId,
    record: &SkillRecord,
    input: &[u8],
    cycle: &SkillEditCycle,
    author: &dyn SkillOptimizeAuthor,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<()> {
    let artifact = crate::codebase::entity_id_from_hash_material(
        b"oneiron.skill.candidate.artifact.v1",
        &[proposal.as_bytes()],
    )?;
    let prompt = vault.artifact_input_in_txn(txn, artifact, input, occurred, learned_at)?;
    let actor = vault.artifact_import_actor_in_txn(txn, occurred, learned_at)?;
    let run_ref = cycle
        .as_str()
        .strip_prefix(super::job::SKILL_EDIT_CYCLE_RUN_PREFIX)
        .unwrap_or(cycle.as_str())
        .to_owned();
    let mut birth = vault.artifact_birth_for_input_in_txn(
        txn,
        ArtifactTrigger::Skill(skill),
        prompt,
        Some(run_ref.clone()),
        author.model_id(),
        ArtifactPurpose::SkillCandidate,
    )?;
    birth.params_hash = author.params_hash();
    let body = BlobArtifactBody::new("skill-candidate.msgpack", "application/msgpack");
    vault.create_artifact_with_birth_in_txn(
        txn,
        artifact,
        ArtifactBirthBody::Blob(&body),
        &birth,
        actor,
        occurred,
        learned_at,
    )?;
    vault.append_blob_artifact_version_in_txn(
        txn,
        &artifact,
        &crate::skill::encode_skill_record(record)?,
        &BlobVersionProvenance::AgentRun { run_ref },
        actor,
        occurred,
        learned_at,
    )?;
    vault
        .batch_in()
        .edge(&artifact, crate::edge::EdgeKind::About, &proposal, 1.0)
        .apply(txn)
}

/// Canonical bytes of every field actually passed to the author, including only
/// the already-filtered dev evidence. Debug output is not a storage format.
pub(super) fn encode_brief(brief: &SkillOptimizeBrief) -> Result<Vec<u8>> {
    let discoveries: Vec<_> = brief
        .discovery_proposals
        .iter()
        .map(|proposal| {
            serde_json::json!({
                "judgment_sequence": proposal.judgment_sequence, "skill": proposal.skill.to_hex(),
                "evidence_receipts": proposal.evidence_receipts, "at": proposal.at,
            })
        })
        .collect();
    let substitutions: Vec<_> = brief
        .substitution_proposals
        .iter()
        .map(|proposal| {
            serde_json::json!({
                "proposal_id": proposal.proposal_id.to_hex(), "skill": proposal.skill.to_hex(),
                "scope": proposal.scope, "from": proposal.from, "to": proposal.to,
                "evidence_receipts": proposal.evidence_receipts, "rationale": proposal.rationale,
                "at": proposal.at, "decision": proposal.decision.map(|decision| serde_json::json!({
                    "verdict": decision.verdict.as_str(), "at": decision.at,
                })),
            })
        })
        .collect();
    crate::llm::canonical_json_bytes(&serde_json::json!({
        "v": 1, "skill": brief.skill.to_hex(), "skill_id": brief.skill_id,
        "desc": brief.desc, "version": brief.version,
        "posterior": { "alpha": brief.posterior.alpha, "beta": brief.posterior.beta },
        "prior": { "alpha": brief.prior.alpha, "beta": brief.prior.beta },
        "attributed_outcomes": brief.attributed_outcomes, "cited_receipts": brief.cited_receipts,
        "defect_receipts": brief.defect_receipts, "discovery_proposals": discoveries,
        "substitution_proposals": substitutions,
    }))
    .map_err(|_| crate::Error::InvalidClaimBody("skill optimizer birth input encode failed"))
}
