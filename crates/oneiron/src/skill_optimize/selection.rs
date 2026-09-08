//! Which skill the job may work on: the tier-filtered, dev-partitioned ranking and the reading behind it.

use std::collections::HashSet;

use crate::Vault;
use crate::claim::ClaimApprovalStatus;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_SKILL;
use crate::skill::SkillLifecycle;
use crate::skill_reliability::{SkillReliabilityPosterior, skill_reliability_prior};

use super::dials::{SKILL_SCAN_PAGE, skill_optimize_min_outcomes};
use super::gate::receipt_is_held_out;
use super::tier::tier_verdict;

/// One skill the job may work on, with the reading that ranked it.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct SkillOptimizeCandidate {
    pub skill: EntityId,
    /// The DEV-PARTITION posterior: the provenance prior folded with the
    /// attributed outcomes ONE-1449's split did NOT reserve.
    ///
    /// Deliberately not the projected `skill.reliability` claim (and never the
    /// record's `confidence` cache). That claim is a fold over BOTH sides of
    /// the split, so selecting on it would let held-out outcomes decide which
    /// skill gets rewritten and hand the drafting author a held-out aggregate —
    /// the leak the split exists to prevent, one level up from the receipt
    /// lists. The cost is honest and stated: only outcomes whose LOCAL ledger
    /// rows are present can be partitioned, so a posterior that arrived by sync
    /// is not counted here at all. Under-reading evidence delays an edit;
    /// over-reading it fits the edit to its own exam.
    pub posterior: SkillReliabilityPosterior,
    /// The provenance prior the posterior is judged against.
    pub prior: SkillReliabilityPosterior,
    /// Dev-partition attributed outcomes: the weight `posterior` holds above
    /// `prior`, and the quantity the N dial is compared against.
    pub attributed_outcomes: u32,
}

/// Every ACTIVE skill the automated loop may target, worst posterior mean
/// first.
///
/// The sweep is COMPLETE rather than paged-and-truncated: "the worst skill in
/// the library" is not a question a prefix of the type index can answer, and
/// silently ranking a prefix would make the job's choice depend on entity-id
/// order.
///
/// Ties break on entity id so two devices reading the same vault choose the
/// same skill.
///
/// # Errors
///
/// Storage errors; body errors from an undecodable SKILL record.
pub fn optimize_candidates(vault: &Vault) -> Result<Vec<SkillOptimizeCandidate>> {
    let min_outcomes = skill_optimize_min_outcomes(vault)?;
    let skills = all_skill_ids(vault)?;

    // One pass to learn which `skillId`s already have an unanswered proposed
    // revision, so the second pass can skip asking again.
    let mut open_questions: HashSet<String> = HashSet::new();
    let mut records = Vec::with_capacity(skills.len());
    for id in skills {
        let Some(record) = vault.get_skill_record(&id)? else {
            continue;
        };
        if record.lifecycle_status == SkillLifecycle::Candidate
            && record.approval_status == ClaimApprovalStatus::Proposed
        {
            open_questions.insert(record.skill_id.clone());
        }
        records.push((id, record));
    }

    let mut candidates = Vec::new();
    for (id, record) in records {
        if record.lifecycle_status != SkillLifecycle::Active {
            continue;
        }
        if open_questions.contains(&record.skill_id) {
            continue;
        }
        if !tier_verdict(vault, &id, &record)?.optimizable() {
            continue;
        }
        let prior = skill_reliability_prior(vault, &id)?;
        // ONE-1449: the DEV half, folded here. Both numbers this ranking rests
        // on are partitioned, so no held-out outcome votes on which skill the
        // author is asked to rewrite.
        let reading = dev_partition_reading(vault, &id, prior)?;
        if reading.attributed < min_outcomes {
            continue;
        }
        // And the RESERVE has to exist, because the gate scores against it and
        // nothing else. The two thresholds are independent draws on the same
        // ledger — N counts dev outcomes, the split reserves about one receipt
        // in five — so a skill can clear N with an empty reserve, and every
        // such skill used to buy an LLM draft the gate could not score. The
        // check is here, at SELECTION, for the reason the tier filter is:
        // an unscorable skill is absent from the list, not refused at the end.
        if reading.reserved == 0 {
            continue;
        }
        // Evidence of LOSS, not merely of use: the outcomes have to have moved
        // this skill below where its own birth path started it.
        if reading.posterior.mean() >= prior.mean() {
            continue;
        }
        candidates.push(SkillOptimizeCandidate {
            skill: id,
            posterior: reading.posterior,
            prior,
            attributed_outcomes: reading.attributed,
        });
    }
    candidates.sort_by(|left, right| {
        left.posterior
            .mean()
            .total_cmp(&right.posterior.mean())
            .then_with(|| left.skill.as_bytes().cmp(right.skill.as_bytes()))
    });
    Ok(candidates)
}

fn all_skill_ids(vault: &Vault) -> Result<Vec<EntityId>> {
    let mut out: Vec<EntityId> = Vec::new();
    loop {
        let page = vault.entities_by_type_page(ENTITY_TYPE_SKILL, out.last(), SKILL_SCAN_PAGE)?;
        let exhausted = page.len() < SKILL_SCAN_PAGE;
        out.extend(page);
        if exhausted {
            return Ok(out);
        }
    }
}

/// One skill's split, read once: the DEV fold, and how big the RESERVE is.
struct DevPartitionReading {
    /// The prior folded with the DEV outcomes, and nothing else.
    posterior: SkillReliabilityPosterior,
    /// How many DEV outcomes went into it — the N-dial quantity.
    attributed: u32,
    /// How many outcomes the gate reserved. Never folded and never shown; the
    /// only question asked of it is whether the gate would have anything to
    /// score at all.
    reserved: u32,
}

/// One skill's DEV-side evidence, folded into a posterior of its own.
///
/// The whole aggregate half of ONE-1449's leakage rule, in one function: the
/// job's ranking, its N-dial check and the brief it hands the author all read
/// this and nothing else, so a held-out outcome has no vote anywhere on the
/// authoring road — not as a receipt id, and not as a number derived from one.
///
/// The reserve is COUNTED on the same pass, and that count is not a leak: it
/// never touches the posterior, never reaches the author, and answers exactly
/// one question ("could the gate score this at all?") that selection has to ask
/// before it spends a draft. One walk rather than two, over one snapshot, so
/// the two sides of the split cannot be read from different ledger states.
///
/// Counted from the LOCAL outcome ledger rather than derived from the projected
/// claim, because the claim is the fold over both sides and cannot be
/// un-mixed. The consequence is stated where it is felt
/// ([`SkillOptimizeCandidate::posterior`]): evidence that arrived as a synced
/// posterior, with no local rows, is invisible to this job.
fn dev_partition_reading(
    vault: &Vault,
    skill: &EntityId,
    prior: SkillReliabilityPosterior,
) -> Result<DevPartitionReading> {
    let rtxn = vault.store.env.read_txn()?;
    let outcomes = crate::skill_reliability::attributed_outcome_results(vault, &rtxn, skill)?;
    let mut reading = DevPartitionReading {
        posterior: prior,
        attributed: 0,
        reserved: 0,
    };
    for (receipt, win) in outcomes {
        if receipt_is_held_out(skill, &receipt) {
            reading.reserved = reading.reserved.saturating_add(1);
            continue;
        }
        reading.posterior.apply(win);
        reading.attributed = reading.attributed.saturating_add(1);
    }
    Ok(reading)
}
