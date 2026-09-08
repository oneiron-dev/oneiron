//! The convert door itself: fence-checked selection in, mechanical hash dedup, and one
//! record landed in one write transaction.

use rmpv::Value;

use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::skill::{
    SkillContentHash, SkillDependency, SkillLifecycle, SkillRecord, canonical_skill_tree_hash,
};
use crate::skill_reliability::{ProvenanceTrustClass, SkillReliabilityPosterior};
use crate::temporal::TimeRange;

use super::provenance::{convert_version, provenance};
use super::selection::{nearest_skills, resolve_selection};
use super::types::{
    CONVERT_RATIONALE_MAX_BYTES, ConvertOutcome, ConvertRequest, RefineVerdict, SkillRefineBrief,
    SkillRefiner,
};

/// Converts selected turns/messages into a SKILL record (ARCH-0017 road 02).
///
/// The order of the steps IS the contract:
/// 1. resolve and FENCE-CHECK every selected ref. An off-record turn can never
///    reach the refiner, because a durable skill minted from fenced words would
///    outlive the session that was promised to evaporate — pipeline-inertness
///    is broken at the read, so the refusal has to precede the read;
/// 2. retrieve the nearest existing skills, so the refiner diffs against the
///    library instead of guessing at it;
/// 3. refine;
/// 4. recompute canonical identity from the returned tree — never trust the
///    refiner for it;
/// 5. exact-hash dedup and the landing run in ONE write transaction, so two
///    concurrent conversions of the same passage cannot both see "no holder"
///    and both create.
///
/// Approval is `approved` and lifecycle is `candidate`: ARCH-0017 rules that
/// user initiation IS consent for the CONVERSION, while ARCH-0053 §6 keeps
/// admission to canon the gate's act. A merge proposal is stamped `proposed`
/// instead — the user consented to converting their words, not to rewriting a
/// skill they did not name.
pub fn convert_messages_to_skill(
    vault: &Vault,
    request: &ConvertRequest,
    refiner: &dyn SkillRefiner,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<ConvertOutcome> {
    let said = resolve_selection(vault, request)?;
    let brief = SkillRefineBrief {
        neighbors: nearest_skills(vault, &said, request.hint.as_deref())?,
        said,
        hint: request.hint.clone(),
    };
    let refined = refiner.refine(&brief)?;
    let content_hash = canonical_skill_tree_hash(
        refined
            .files
            .iter()
            .map(|file| (file.path.as_str(), file.content.as_slice())),
    )?;
    let (rationale, merge_target) = match &refined.verdict {
        RefineVerdict::Mint { justification } => (justification.as_str(), None),
        RefineVerdict::MergeInto {
            existing,
            rationale,
        } => {
            // Grounding, not etiquette: a merge target the brief never showed
            // is a target the refiner did not diff against, so it cannot have
            // judged it near-duplicate.
            if !brief
                .neighbors
                .iter()
                .any(|neighbor| neighbor.entity == *existing)
            {
                return Err(Error::InvalidSkillBody(
                    "merge target must be one of the skills the refine brief offered",
                ));
            }
            (rationale.as_str(), Some(*existing))
        }
    };
    validate_text(
        rationale,
        CONVERT_RATIONALE_MAX_BYTES,
        "refiner rationale must be a non-empty string at most 1024 bytes",
    )?;

    vault.with_write_txn(|wtxn| {
        // The MECHANICAL tier, first and unconditionally: identical bytes are
        // ONE skill whichever road they arrive on, and no refiner verdict — not
        // even an insistent `Mint` — buys a second holder for them.
        if let Some(existing) = vault.skill_entity_for_content_hash_in_txn(&*wtxn, content_hash)? {
            return Ok(ConvertOutcome::DupPointer(existing));
        }
        let record = match merge_target {
            Some(existing) => {
                // Resolved at the WRITE door, not carried from the shortlist:
                // the proposal's parent has to still be there — and still be
                // proposable against — when it lands.
                let target = vault.read_skill_record_in_txn(wtxn, &existing)?;
                // `nearest_skills` keeps frozen revisions out of the brief, but
                // it read them BEFORE the refinement ran, and refinement runs
                // outside this transaction. A target superseded in that window
                // is dead on arrival: `supersede_skill_record` rejects a
                // non-active old revision, so the gate could never admit the
                // proposal. Refuse rather than land a record with no future.
                if target.lifecycle_status == SkillLifecycle::Superseded {
                    return Err(Error::InvalidSkillBody(
                        "merge target was superseded while the refinement ran",
                    ));
                }
                converted_record(
                    // The proposal continues the TARGET's skill id — that is
                    // what makes it a revision the admission gate can supersede
                    // with, rather than a rival skill under a new name.
                    &target.skill_id,
                    &refined.desc,
                    content_hash,
                    ClaimApprovalStatus::Proposed,
                    // And it continues the target's DEPENDENCY contract for the
                    // same reason: admitting a revision that declares none would
                    // amputate the requirements its predecessor shipped with.
                    // The refiner has no say — `RefinedSkill` carries no
                    // dependency channel, exactly so it cannot invent one.
                    target.dependencies,
                    provenance(&brief.said, rationale, Some(&existing)),
                )
            }
            None => converted_record(
                &refined.skill_id,
                &refined.desc,
                content_hash,
                ClaimApprovalStatus::Approved,
                // A minted skill declares nothing: dependencies are a curated
                // contract, and there is no prior revision to inherit one from.
                Vec::new(),
                provenance(&brief.said, rationale, None),
            ),
        };
        let id = EntityId::now();
        vault.put_skill_record_in_txn(wtxn, &id, &record, occurred, learned_at)?;
        Ok(match merge_target {
            Some(existing) => ConvertOutcome::MergeProposed {
                existing,
                proposal: id,
            },
            None => ConvertOutcome::Created(id),
        })
    })
}

/// Builds the record both verdicts land.
///
/// `generated` / `ClaimSource::Generated` is the honest stamp for either: an LLM
/// wrote these bytes, whoever chose the passage. ARCH-0053 §5 already names
/// "conversation convert" under [`ProvenanceTrustClass::Generated`], so the
/// confidence CACHE is seeded from that class's prior rather than from an
/// optimistic constant — a converted skill starts WEAK and earns its place.
fn converted_record(
    skill_id: &str,
    desc: &str,
    content_hash: SkillContentHash,
    approval: ClaimApprovalStatus,
    dependencies: Vec<SkillDependency>,
    provenance: Value,
) -> SkillRecord {
    SkillRecord::new(
        skill_id,
        desc,
        convert_version(content_hash),
        approval,
        SkillLifecycle::Candidate,
        ClaimSource::Generated,
        SkillReliabilityPosterior::seeded_from_provenance(ProvenanceTrustClass::Generated).mean(),
        true,
        false,
        dependencies,
        provenance,
    )
    .with_content_hash(content_hash)
}

pub(super) fn validate_text(text: &str, max_bytes: usize, context: &'static str) -> Result<()> {
    if text.trim().is_empty() || text.len() > max_bytes {
        return Err(Error::InvalidSkillBody(context));
    }
    Ok(())
}
