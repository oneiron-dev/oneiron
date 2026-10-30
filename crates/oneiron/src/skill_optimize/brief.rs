//! The author seam and the dev-partitioned evidence brief handed across it.

use std::collections::HashSet;

use rmpv::Value;

use crate::Vault;
use crate::dreamer_runner::maintenance::agent_health::REVIEWER_POLICY_FILE;
use crate::edit_distance::miner::{MinedSkillEditProposal, pending_substitution_skill_edits};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::limit_ask::EngineLimit;
use crate::llm::CallPurpose;
use crate::skill_attribution::{
    AttributionVerdict, SkillEditProposal, attribution_judgment_row_ids, attribution_judgments,
    edit_proposal_row_ids, pending_edit_proposals,
};
use crate::skill_reliability::{SkillReliabilityPosterior, skill_reliability_prior_rows};

use super::gate::{
    SkillEditDisposition, dev_receipts, receipt_is_held_out, skill_body_binding_digest,
    skill_edit_verdicts,
};
use super::job::{PROVENANCE_OPTIMIZE_PRINCIPAL_KEY, PROVENANCE_OPTIMIZE_RATIONALE_KEY};
use super::selection::{SkillOptimizeCandidate, attempt_row_ids};
use super::union_source_rows;

/// How many of the reserved receipts a gate verdict used to list for display, the
/// newest, before FIX 5099 kept the whole scored set instead; the verdict keeps
/// the whole set's count and digest beside the list itself. The optimize brief
/// was never cut to it: the author reads all of its DEV evidence.
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
    /// Explicit preference audience. Unbound jobs use no personal evidence.
    pub principal: Option<EntityId>,
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
    /// claim's own citation trace), plus the DEV `health_review:` rule
    /// outcomes the posterior counts and the claim never cites (FIX 10879).
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
    /// Earlier rejected drafts for this exact skill, alongside the open
    /// proposals. Only the categorical rejection reason crosses from the
    /// held-out gate: never its scores, basis, or reserved receipt ids.
    pub rejected_edits: Vec<RejectedSkillEdit>,
    /// The failure a heal's repair is aimed at (FIX 2495): explicit repair
    /// input the Coach hands its author, never an outcome aggregate, so the
    /// held-out partition is untouched. `None` for an ordinary optimization.
    pub failure: Option<SkillFailureContext>,
    /// A policy-bearing skill's dials: each top-level key of its
    /// `policy.json` with its current value (FIX 12071). An edit moves one
    /// by naming its key with the new number (`key: 4`), which the improved
    /// revision's `policy.json` then takes. `None` when it carries none.
    pub policy_dials: Option<serde_json::Map<String, serde_json::Value>>,
    /// The rows this brief was read from (FIX 7102): the DEV attempt rows, the
    /// forwarded proposals, the rejected verdicts with their proposals, the
    /// prior's rows and the reliability claim, unioned. `None` unless every
    /// constituent is witnessed; the author's call carries it, and calls never
    /// refuse for `None`.
    pub source_rows: Option<Vec<EntityId>>,
}

/// The failure a heal's skill repair is aimed at: its class as its source
/// stored it and every verified blocked report of it, each whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillFailureContext {
    /// A failure-ladder case's own class (`transient`, `permanent` or
    /// `ambiguous`), or `agent_blocked` for a blocked report.
    pub failure_class: String,
    /// A blocked report's category, when the failure is one.
    pub category: Option<String>,
    /// Every verified report of the failure that still reads.
    pub reports: Vec<SkillFailureReport>,
}

/// One blocked report of a failure, whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillFailureReport {
    pub receipt: EntityId,
    pub category: String,
    /// The agent's own words: data, never an instruction.
    pub untrusted_detail: String,
}

/// Why a scored edit did not clear the strict-improvement gate.
/// No scores or held-out evidence are exposed to the drafting author.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectedSkillEditReason {
    Tie,
    Regression,
}

/// A previously rejected edit the author can avoid repeating.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedSkillEdit {
    pub proposal: EntityId,
    pub desc: String,
    /// The first author's stated reason for proposing this text.
    pub author_rationale: String,
    /// The gate's categorical reason for rejecting it.
    pub rejection_reason: RejectedSkillEditReason,
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
/// `SkillRefiner` / `AttributionDecisions` posture). What the author returns is a
/// PROPOSAL either way — nothing it can say reaches canon without a human.
pub trait SkillOptimizeAuthor {
    /// Drafts the edit `brief` supports.
    ///
    /// # Errors
    ///
    /// Implementation-defined: an author that cannot answer must error rather
    /// than invent, and the attempt drafts nothing.
    fn draft(&self, brief: &SkillOptimizeBrief) -> Result<SkillEditDraft>;

    /// Drafts the edit `brief` supports on the Coach's optimization attempt
    /// `_attempt`, whose lease the caller holds (ARCH-0079: each recipe is a
    /// workflow skill). An author that runs the shipped improver workflow
    /// loads it on that attempt, so the attempt's pack manifest pins the
    /// revision and model that drafted, and runs its instructions; when the
    /// workflow does not load it drafts as [`Self::draft`] does. Default:
    /// [`Self::draft`].
    ///
    /// # Errors
    ///
    /// As [`Self::draft`].
    fn draft_on(
        &self,
        _attempt: &crate::attempt_queue::AttemptRecord,
        brief: &SkillOptimizeBrief,
    ) -> Result<SkillEditDraft> {
        self.draft(brief)
    }
}

/// The [`CallPurpose`] an author's LLM tier must stamp.
#[must_use]
pub fn skill_optimize_call_purpose() -> CallPurpose {
    CallPurpose::Other {
        name: SKILL_OPTIMIZE_CALL_PURPOSE_NAME.to_owned(),
    }
}

/// Reads everything [`run_skill_optimize`](crate::skill_optimize::run_skill_optimize) hands the author for one candidate.
///
/// # Errors
///
/// Storage errors; [`Error::EntityNotFound`] when the candidate is gone.
pub fn optimize_brief(
    vault: &Vault,
    candidate: &SkillOptimizeCandidate,
) -> Result<SkillOptimizeBrief> {
    optimize_brief_bound_at(vault, candidate, None, crate::unix_seconds_now())
}

/// Reads a DEV-only brief for an explicitly authenticated principal.
/// Unknown legacy preference evidence and other principals never influence it.
pub fn optimize_brief_for_principal_at(
    vault: &Vault,
    candidate: &SkillOptimizeCandidate,
    owner: crate::write_envelope::WriteActor,
    now: u64,
) -> Result<SkillOptimizeBrief> {
    let txn = vault.store.env.read_txn()?;
    vault.verify_owner_write_actor_in_txn(&txn, &owner)?;
    drop(txn);
    optimize_brief_bound_at(vault, candidate, Some(owner.entity_ref()), now)
}

pub(crate) fn optimize_brief_bound_at(
    vault: &Vault,
    candidate: &SkillOptimizeCandidate,
    principal: Option<EntityId>,
    now: u64,
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
    let mut defect_judgments = Vec::new();
    for judgment in attribution_judgments(vault)? {
        if judgment.verdict != AttributionVerdict::SkillDefect
            || judgment.subject != Some(candidate.skill)
        {
            continue;
        }
        let before = defect_receipts.len();
        defect_receipts.extend(
            judgment
                .evidence_receipts
                .iter()
                .filter(|receipt| dev.contains(receipt.as_str()))
                .cloned(),
        );
        // Only a judgment the brief forwards a receipt of is a row it read.
        if defect_receipts.len() > before {
            defect_judgments.push(judgment);
        }
    }

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
    let discovery_proposals: Vec<SkillEditProposal> = pending_edit_proposals(vault)?
        .into_iter()
        .filter(|proposal| {
            proposal.skill == candidate.skill
                && rests_only_on_dev(&candidate.skill, &proposal.evidence_receipts)
        })
        .collect();
    let mut substitution_proposals = Vec::new();
    for proposal in pending_substitution_skill_edits(vault)? {
        if proposal.skill == candidate.skill
            && proposal.principal == principal
            && rests_only_on_dev(&candidate.skill, &proposal.evidence_receipts)
            && crate::claim::preference_evidence_in_force(proposal.at, now)
            && crate::edit_distance::miner::preference_receipts_in_force(
                vault,
                &proposal.evidence_receipts,
                principal,
                now,
            )?
        {
            substitution_proposals.push(proposal);
        }
    }

    // A rejection is feedback about the author's own draft, not a license to
    // inspect the held-out exam. Read only terminal, scored rejections for this
    // exact target, then join their proposal text and author rationale. A
    // removed or since-mutated proposal cannot truthfully describe the body
    // the gate scored; do not display it as that body's edit.
    let mut rejected_edits = Vec::new();
    let mut rejection_rows: Vec<EntityId> = Vec::new();
    for verdict in skill_edit_verdicts(vault)? {
        if verdict.skill != candidate.skill || verdict.disposition != SkillEditDisposition::Rejected
        {
            continue;
        }
        let Some(proposal) = vault.get_skill_record(&verdict.proposal)? else {
            continue;
        };
        if skill_body_binding_digest(&proposal)? != verdict.proposal_digest {
            continue;
        }
        let Value::Map(provenance) = &proposal.provenance else {
            continue;
        };
        // An owner-scoped draft can carry private preference corrections.
        // Never echo it to an unbound job or another principal. Unbound
        // drafts contain no owner-specific evidence and remain visible to all.
        let bound_to = provenance
            .iter()
            .find(|(key, _)| key.as_str() == Some(PROVENANCE_OPTIMIZE_PRINCIPAL_KEY))
            .map(|(_, value)| value.as_str().and_then(|hex| EntityId::from_hex(hex).ok()));
        // Absent is public; present but unreadable is NOT unbound. Treat any
        // malformed stamp as ineligible, including for an unbound author.
        if bound_to.is_some_and(|owner| owner.is_none() || owner != principal) {
            continue;
        }
        let Some(author_rationale) = provenance.iter().find_map(|(key, value)| {
            (key.as_str() == Some(PROVENANCE_OPTIMIZE_RATIONALE_KEY))
                .then(|| value.as_str())
                .flatten()
        }) else {
            continue;
        };
        rejection_rows.push(verdict.id);
        rejection_rows.push(verdict.proposal);
        rejected_edits.push(RejectedSkillEdit {
            proposal: verdict.proposal,
            desc: proposal.desc,
            author_rationale: author_rationale.to_owned(),
            rejection_reason: if verdict
                .goal_axes
                .values()
                .all(|axis| axis.after == axis.before)
            {
                RejectedSkillEditReason::Tie
            } else {
                RejectedSkillEditReason::Regression
            },
        });
    }
    let (citations, claim) = reliability_citations(vault, &candidate.skill)?;
    let mut cited_receipts: Vec<String> = citations
        .into_iter()
        .filter(|receipt| dev.contains(receipt))
        .collect();
    // FIX 10879: the DEV posterior folds `health_review:` rule outcomes the
    // projected claim never cites, so the brief cites them from the rule rows
    // themselves, in the same receipt-id shape. Unreadable rows were already
    // skipped with a WARN at the read; a failed read cites nothing.
    cited_receipts.extend(rule_outcome_citations(vault, &candidate.skill, &dev));
    // The rows the author's call carries (FIX 7102, FIX 12088): the DEV attempt
    // rows, the forwarded defect judgments and discovery proposals by their own
    // row ids, the forwarded substitution proposals, the rejected verdicts with
    // their proposals, the prior's rows and the reliability claim. Capture
    // only, never a refusal.
    let dev_rows = attempt_row_ids(&dev);
    let defect_rows = Some(attribution_judgment_row_ids(&defect_judgments));
    let discovery_rows = Some(edit_proposal_row_ids(&discovery_proposals));
    let substitution_rows: Vec<EntityId> = substitution_proposals
        .iter()
        .map(|proposal| proposal.proposal_id)
        .collect();
    let prior_rows = skill_reliability_prior_rows(vault, &candidate.skill)?;
    let source_rows = union_source_rows([
        dev_rows,
        defect_rows,
        discovery_rows,
        Some(substitution_rows),
        Some(rejection_rows),
        Some(prior_rows),
        claim.map(|claim| vec![claim]),
    ]);
    // The brief carries every list whole; the longest is measured.
    let items = [
        cited_receipts.len(),
        defect_receipts.len(),
        discovery_proposals.len(),
        substitution_proposals.len(),
        rejected_edits.len(),
    ]
    .into_iter()
    .max()
    .unwrap_or(0);
    let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, items as u64);
    let policy_dials = policy_dials(vault, &candidate.skill, &record);

    Ok(SkillOptimizeBrief {
        skill: candidate.skill,
        principal,
        skill_id: record.skill_id,
        desc: record.desc,
        version: record.version,
        posterior: candidate.posterior,
        prior: candidate.prior,
        attributed_outcomes: candidate.attributed_outcomes,
        cited_receipts,
        defect_receipts,
        discovery_proposals,
        substitution_proposals,
        rejected_edits,
        failure: None,
        policy_dials,
        source_rows,
    })
}

/// The top-level entries of `skill`'s `policy.json`, when its package
/// carries one that reads as one JSON object (FIX 12071): the dials the
/// improved revision's re-derive moves. A package that does not read shows
/// none, and the brief goes on.
fn policy_dials(
    vault: &Vault,
    skill: &EntityId,
    record: &crate::skill::SkillRecord,
) -> Option<serde_json::Map<String, serde_json::Value>> {
    let rtxn = vault.store.env.read_txn().ok()?;
    let package = match vault.runtime_skill_package_in_txn(&rtxn, skill, record) {
        Ok(package) => package?,
        Err(error) => {
            tracing::debug!(kind = ?error.kind(), "a skill's package is unreadable for its brief");
            return None;
        }
    };
    let policy = package
        .files
        .into_iter()
        .find(|file| file.path == REVIEWER_POLICY_FILE)?;
    match serde_json::from_slice::<serde_json::Value>(&policy.content).ok()? {
        serde_json::Value::Object(entries) => Some(entries),
        _ => None,
    }
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

/// The receipts the active `skill.reliability` claim cites and the claim row
/// they were read from, or none when the skill has never been projected.
fn reliability_citations(
    vault: &Vault,
    skill: &EntityId,
) -> Result<(Vec<String>, Option<EntityId>)> {
    let rtxn = vault.store.env.read_txn()?;
    let mut best: Option<(usize, Vec<String>, EntityId)> = None;
    for id in vault.claims_for_subject_in_txn(&rtxn, skill)? {
        let Some(body) = vault.get_claim_in_txn(&rtxn, &id)? else {
            continue;
        };
        if body.predicate != crate::skill_reliability::PREDICATE_SKILL_RELIABILITY
            || body.lifecycle != crate::claim::ClaimLifecycleStatus::Active
            || body.source != Some(crate::claim::ClaimSource::Observed)
            || body.approval != crate::claim::ClaimApprovalStatus::Auto
            || !crate::gate::claim_consolidation_eligible_in_txn(
                &vault.store,
                &rtxn,
                &id,
                crate::gate::ConsolidationReader::SkillOptimizeCitations,
            )?
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
        if best.as_ref().is_none_or(|(len, _, _)| receipts.len() > *len) {
            best = Some((receipts.len(), receipts, id));
        }
    }
    Ok(best
        .map(|(_, receipts, id)| (receipts, Some(id)))
        .unwrap_or_default())
}

/// The DEV `health_review:` rule outcomes the posterior counts, as receipt ids
/// in the same shape as [`reliability_citations`] (FIX 10879). Read from the
/// rule OUTCOME rows in this brief's own read snapshot; a read that fails cites
/// nothing rather than failing the brief.
fn rule_outcome_citations(vault: &Vault, skill: &EntityId, dev: &HashSet<String>) -> Vec<String> {
    let cited: Result<Vec<String>> = (|| {
        let rtxn = vault.store.env.read_txn()?;
        let receipts = crate::skill_reliability::rule_outcome_receipts_in_txn(vault, &rtxn, skill)?;
        Ok(receipts
            .into_iter()
            .filter(|receipt| {
                receipt.starts_with(
                    crate::dreamer_runner::maintenance::agent_health::HEALTH_REVIEW_RECEIPT_PREFIX,
                ) && dev.contains(receipt)
            })
            .collect())
    })();
    match cited {
        Ok(cited) => cited,
        Err(error) => {
            tracing::warn!(
                skill = %skill.to_hex(),
                %error,
                "the brief's rule outcome citations are unreadable; they were skipped"
            );
            Vec::new()
        }
    }
}

#[cfg(test)]
impl Vault {
    pub(crate) fn skill_optimize_reliability_citations_for_test(
        &self,
        skill: &EntityId,
    ) -> Result<Vec<String>> {
        reliability_citations(self, skill).map(|(citations, _)| citations)
    }
}
