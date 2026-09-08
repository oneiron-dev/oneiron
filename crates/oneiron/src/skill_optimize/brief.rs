//! The author seam and the dev-partitioned evidence brief handed across it.

use std::collections::HashSet;

use rmpv::Value;

use crate::Vault;
use crate::edit_distance::miner::{MinedSkillEditProposal, pending_substitution_skill_edits};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::CallPurpose;
use crate::skill_attribution::{
    AttributionVerdict, SkillEditProposal, attribution_judgments, pending_edit_proposals,
};
use crate::skill_reliability::SkillReliabilityPosterior;

use super::gate::{dev_receipts, receipt_is_held_out};
use super::selection::SkillOptimizeCandidate;

/// Upper bound on any one evidence list handed to the author.
///
/// Mirrors `SKILL_RELIABILITY_MAX_CITED_RECEIPTS`, which already caps the
/// citation trace this brief is mostly built from: a brief is a summary, and a
/// summary that grows without bound is a ledger.
pub const SKILL_OPTIMIZE_MAX_BRIEF_EVIDENCE: usize = 64;

/// Upper bound on an author's rationale, matching `skill_convert`'s.
pub const SKILL_OPTIMIZE_RATIONALE_MAX_BYTES: usize = 1024;

/// The [`CallPurpose`] an author's LLM tier must stamp, so optimization calls
/// are budgeted and audited as their own class.
pub const SKILL_OPTIMIZE_CALL_PURPOSE_NAME: &str = "skill_optimize_draft";

/// Everything the author is allowed to reason from: the instructions as they
/// stand, and what real usage did with them.
///
/// Everything here is the DEV split (ONE-1449) — the receipt lists AND the
/// aggregates. The outcomes the gate reserved are filtered out of the lists and
/// were never folded into the numbers, so the text this author writes was
/// neither fitted to the evidence that will score it nor prompted by a summary
/// of it.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct SkillOptimizeBrief {
    pub skill: EntityId,
    /// The target's `skillId` — the proposal continues it, so a drafted
    /// revision is something the gate can supersede WITH.
    pub skill_id: String,
    /// The instructions as they stand. The edit is against this text.
    pub desc: String,
    pub version: String,
    /// The DEV-PARTITION posterior ([`SkillOptimizeCandidate::posterior`]).
    /// Never the projected `skill.reliability` claim: that one is a fold over
    /// both sides of the split, so showing it here would hand the author a
    /// held-out aggregate.
    pub posterior: SkillReliabilityPosterior,
    pub prior: SkillReliabilityPosterior,
    /// Dev-partition attributed outcomes — the count behind `posterior`.
    pub attributed_outcomes: u32,
    /// Receipts the reliability claim rests on (wins and losses both — the
    /// claim's own citation trace).
    pub cited_receipts: Vec<String>,
    /// Receipts of SK-04 `SkillDefect` judgments against this skill: the
    /// occasions its CONTENT was found wrong.
    pub defect_receipts: Vec<String>,
    /// Open SK-04 discovery proposals for this skill (content found MISSING),
    /// restricted to those resting only on DEV evidence.
    pub discovery_proposals: Vec<SkillEditProposal>,
    /// Open ED-04 mined substitution proposals for this skill (the same
    /// correction, made repeatedly), restricted to those resting only on DEV
    /// evidence.
    ///
    /// The partition is applied to the whole payload, not to its id list: a
    /// substitution carries the correction TEXT, which is the held-out outcome
    /// restated in the most usable form there is.
    pub substitution_proposals: Vec<MinedSkillEditProposal>,
}

/// The author's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SkillEditDraft {
    /// Replacement instructions the evidence supports, and why.
    Edit { desc: String, rationale: String },
    /// The evidence does not support an edit. Declining is a first-class
    /// answer: a job that must always produce something produces churn.
    Decline { rationale: String },
}

/// Drafts an instruction edit from real usage outcomes, or declines.
///
/// The host implements this against the engine's existing LLM surface under
/// [`skill_optimize_call_purpose`]; this module constructs no client (the
/// `SkillRefiner` / `AttributionJudge` posture). What the author returns is a
/// PROPOSAL either way — nothing it can say reaches canon without a human.
pub trait SkillOptimizeAuthor {
    /// Drafts the edit `brief` supports.
    ///
    /// # Errors
    ///
    /// Implementation-defined: an author that cannot answer must error rather
    /// than invent, and the attempt drafts nothing.
    fn draft(&self, brief: &SkillOptimizeBrief) -> Result<SkillEditDraft>;
}

/// The [`CallPurpose`] an author's LLM tier must stamp.
#[must_use]
pub fn skill_optimize_call_purpose() -> CallPurpose {
    CallPurpose::Other {
        name: SKILL_OPTIMIZE_CALL_PURPOSE_NAME.to_owned(),
    }
}

/// Reads everything [`run_skill_optimize`] hands the author for one candidate.
///
/// # Errors
///
/// Storage errors; [`Error::EntityNotFound`] when the candidate is gone.
pub fn optimize_brief(
    vault: &Vault,
    candidate: &SkillOptimizeCandidate,
) -> Result<SkillOptimizeBrief> {
    let record = vault
        .get_skill_record(&candidate.skill)?
        .ok_or(Error::EntityNotFound)?;
    // ONE-1449, the import-direction half of the leakage rule: this loader
    // resolves the DEV split once and every receipt list below is intersected
    // with it, so no held-out outcome can reach the author through any of the
    // three ledgers this brief draws on. One membership set rather than three
    // filters — a second spelling of the rule is a second thing to get wrong.
    let dev: HashSet<String> = dev_receipts(vault, &candidate.skill)?.into_iter().collect();
    let mut defect_receipts = Vec::new();
    for judgment in attribution_judgments(vault)? {
        if judgment.verdict != AttributionVerdict::SkillDefect
            || judgment.subject != candidate.skill
        {
            continue;
        }
        defect_receipts.extend(
            judgment
                .evidence_receipts
                .into_iter()
                .filter(|receipt| dev.contains(receipt)),
        );
    }
    truncate_oldest(&mut defect_receipts);

    // The same partition, applied to the PROPOSALS rather than only to the
    // receipt lists. A proposal is a receipt-bearing payload: it carries the
    // evidence ids it was mined from, and a substitution carries the correction
    // TEXT those outcomes produced. Filtering the two flat receipt vectors
    // while passing these through by skill left the leak intact in its richest
    // form — the author could read the reserve's corrections verbatim.
    //
    // A proposal is forwarded only if it can SHOW that every receipt it rests
    // on falls on the dev side of this skill's split: positive evidence, the
    // rule this module already applies to legacy tiers, and the same
    // deterministic partition the gate reserves by. One that cites nothing
    // cannot show it, so it is not shown either — the durable proposal is
    // untouched, and what changes is only what this READ hands the author.
    let mut discovery_proposals: Vec<SkillEditProposal> = pending_edit_proposals(vault)?
        .into_iter()
        .filter(|proposal| {
            proposal.skill == candidate.skill
                && rests_only_on_dev(&candidate.skill, &proposal.evidence_receipts)
        })
        .collect();
    truncate_oldest(&mut discovery_proposals);
    let mut substitution_proposals: Vec<MinedSkillEditProposal> =
        pending_substitution_skill_edits(vault)?
            .into_iter()
            .filter(|proposal| {
                proposal.skill == candidate.skill
                    && rests_only_on_dev(&candidate.skill, &proposal.evidence_receipts)
            })
            .collect();
    truncate_oldest(&mut substitution_proposals);

    Ok(SkillOptimizeBrief {
        skill: candidate.skill,
        skill_id: record.skill_id,
        desc: record.desc,
        version: record.version,
        posterior: candidate.posterior,
        prior: candidate.prior,
        attributed_outcomes: candidate.attributed_outcomes,
        cited_receipts: reliability_citations(vault, &candidate.skill)?
            .into_iter()
            .filter(|receipt| dev.contains(receipt))
            .collect(),
        defect_receipts,
        discovery_proposals,
        substitution_proposals,
    })
}

/// Whether every receipt a proposal rests on falls on the DEV side of this
/// skill's split.
///
/// The PARTITION ([`receipt_is_held_out`]), not the materialized dev LIST, and
/// the difference is the whole reason this is a separate function. The split is
/// a total function of `(skill, receipt)`; the dev list is the part of it that
/// has already become an attributed OUTCOME. Discovery and substitution
/// proposals cite their own ledgers' receipts, so asking the list would answer
/// "no" for every proposal ever minted and quietly delete a whole evidence
/// channel from the brief. Asking the partition answers the question actually at
/// issue — would the gate reserve this receipt? — for an id from any ledger,
/// including one that becomes an attributed outcome tomorrow.
///
/// Fail-closed on an empty citation list: a payload that cites nothing has not
/// shown that its content is dev-derived, and its text was still distilled from
/// outcomes somewhere. Under-showing evidence costs a draft some context;
/// over-showing it fits the draft to its own exam.
pub(super) fn rests_only_on_dev(skill: &EntityId, evidence: &[String]) -> bool {
    !evidence.is_empty() && !evidence.iter().any(|id| receipt_is_held_out(skill, id))
}

/// Keeps the most recent [`SKILL_OPTIMIZE_MAX_BRIEF_EVIDENCE`] entries.
///
/// Both ledgers this reads are mint-ordered (UUIDv7-derived keys), so dropping
/// from the FRONT drops the oldest — the same choice the reliability claim's
/// citation cap makes.
fn truncate_oldest<T>(evidence: &mut Vec<T>) {
    if evidence.len() > SKILL_OPTIMIZE_MAX_BRIEF_EVIDENCE {
        evidence.drain(..evidence.len() - SKILL_OPTIMIZE_MAX_BRIEF_EVIDENCE);
    }
}

/// The receipts the active `skill.reliability` claim cites, or none when the
/// skill has never been projected.
fn reliability_citations(vault: &Vault, skill: &EntityId) -> Result<Vec<String>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut best: Option<(usize, Vec<String>)> = None;
    for id in vault.claims_for_subject_in_txn(&rtxn, skill)? {
        let Some(body) = vault.get_claim_in_txn(&rtxn, &id)? else {
            continue;
        };
        if body.predicate != crate::skill_reliability::PREDICATE_SKILL_RELIABILITY
            || body.lifecycle != crate::claim::ClaimLifecycleStatus::Active
        {
            continue;
        }
        let Some(Value::Array(cited)) = body.evidence.as_ref() else {
            continue;
        };
        let receipts: Vec<String> = cited
            .iter()
            .filter_map(|entry| entry.as_str().map(str::to_owned))
            .collect();
        // A read landing mid-fork must not answer with whichever head the
        // edge index yielded first; the richest trace is the one to reason
        // from, exactly as the posterior read resolves on weight.
        if best.as_ref().is_none_or(|(len, _)| receipts.len() > *len) {
            best = Some((receipts.len(), receipts));
        }
    }
    Ok(best.map(|(_, receipts)| receipts).unwrap_or_default())
}
