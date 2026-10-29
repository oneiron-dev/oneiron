//! ED-03 (ONE-1759, ARCH-0056 §5): the amendment JUDGE, and everything a
//! judged amendment's shares earn.
//!
//! ```text
//! Δ RECEIPT (ED-01/02)  +  routing facts (recorded at the amendment door)
//!   └─ judge_amendment_hunks ──> AmendmentJudgment (label + share split)
//!        ├─ skill_defect %     → learning.edit_cost on the SKILL, at the
//!        │                       drafting executor, its share
//!        │                     → skill.reliability: the amended attempt's ONE
//!        │                       record becomes a loss of this share
//!        ├─ execution_lapse %  → learning.edit_cost on the ACTOR, its own
//!        │                       executor, its share
//!        │                     → one actor.lesson citing the receipt
//!        ├─ discovery %        → a skill EDIT PROPOSAL, minted through SK-04's door
//!        ├─ environment %      → nothing at all — the judgment row IS the record
//!        ├─ preference_shift % → a PREFERENCE proposal for ED-04's miner
//!        └─ unclear %          → holds; a row in the unclear ledger for the Dreamer
//! ```
//!
//! The proposal, the preference note and the unclear row ride the judgment
//! itself. The claim rows land in the projection passes, each recomputed from
//! the judgment ledger: [`project_edit_cost_claims`],
//! [`project_amendment_reliability`] and [`project_amendment_lessons`].
//! Reliability needs the attempt the amended proposal came from; the host
//! names it at the evidence door ([`AmendmentEvidence::with_attempt`]).
//!
//! A REJECTION takes the same judge before it charges anyone (FIX 7823). It
//! carries no Δ and no hunks, so it is one region, one label at 100%; its
//! judgment row is the record, and only the shares that charge a skill or an
//! actor reach a `learning.edit_cost` cell, counted rejected.
//!
//! # A verdict is a split
//!
//! The judge labels each changed hunk, and each hunk weighs its own measured
//! edit mass, so a judgment is a label + share vector summing to one
//! (ARCH-0056 §5, owner 2026-10-08). Every route takes only its share. A judge
//! that cannot split, or an amendment judged as one region, is one class at
//! 100% — the same path. A hunk whose label the judge holds below the
//! `attribution_unclear_floor` setting is `unclear`.
//!
//! # The judge extends SK-04, it does not fork it
//!
//! [`crate::skill_attribution`] landed the attempt lane: a FAILED attempt, two
//! routing facts, one of three verdicts. An amendment differs in exactly one
//! respect — the proposal was APPROVED, so "something was wrong" is no longer
//! given. A decider may amend a perfectly good proposal because the world moved
//! ([`AmendmentClass::Environment`]) or because they wanted it otherwise
//! ([`AmendmentClass::PreferenceShift`]).
//!
//! So this module adds ONE fact ([`AmendmentCause`]) and pre-filters on it.
//! The `ProposalWrong` arm is then handed VERBATIM to
//! [`AttributionDecisions`](crate::skill_attribution::AttributionDecisions) — SK-04's own decision path, SK-04's own rule table, SK-04's
//! own [`crate::skill_attribution::attribution_call_purpose`] for a model tier.
//! There is no second classifier here and no LLM client: the import direction
//! is the proof, and a host that wants a model tier implements SK-04's trait
//! rather than a new one.
//!
//! # Cost is a shared cell, never a raw Δ
//!
//! [`project_edit_cost_claims`] takes JUDGMENTS, not deltas — that signature is
//! the guard. A `d_norm` reaches a cell only after a class named who owns it,
//! as one evidence row per receipt, weighted by its share, in the shared
//! `learning.edit_cost` cell qualified by executor, consent scope and task
//! type (FIX 9797), in the project scope of the run or the reviewed claim
//! (FIX 6038). The learning projector recomputes the estimate from the
//! cell's rows, so a replay overwrites rather than double-counts, and
//! [`edit_cost_for`] reads it back. No parallel scalar head is kept.
//!
//! # The Blind Curator guard
//!
//! A judge biased toward "nothing was wrong" would quietly suppress every
//! contribution-based retirement downstream, and each individual verdict would
//! look defensible. [`run_judge_audit`] therefore runs the judge over a
//! held-out fixture set whose answers are already known — including one whose
//! honest answer is ABSTENTION — and persists the pass-rate as an aggregate.
//! The bias shows up as a number that moved, which is the only form in which it
//! is visible at all.

mod audit;
mod causes;
mod cells;
mod evidence_judge;
mod origin;
mod projector;
mod rejection;
mod scope_erase;
mod stored;
mod taxonomy;
mod triage;
mod worsening;

pub use self::audit::{
    AmendmentAuditFixture, AmendmentAuditRecord, held_out_amendment_fixtures, judge_audit_records,
    judge_audit_reports, run_judge_audit, run_judge_audit_with_decisions,
};
pub use self::causes::AmendmentCauseRecord;
pub use self::cells::edit_cost_for;
pub use self::evidence_judge::{
    amendment_evidence, amendment_judgments, judge_amendment, judge_amendment_hunks,
    judge_amendment_verdicts, judge_amendment_with, pending_preference_proposals,
    record_amendment_evidence,
};
pub use self::projector::{
    project_amendment_lessons, project_amendment_reliability, project_edit_cost_claims,
};
pub use self::taxonomy::{
    AmendmentCause, AmendmentClass, AmendmentEvidence, AmendmentJudgment, AmendmentShare,
    HunkLabel, PreferenceProposal, classify_amendment, validate_share_vector,
};
pub use self::triage::{
    AgentDefinitionRef, ArtifactPublisher, RecentChange, RecentChanges, SkillAtVersion,
    TriagePacket, TriageReceipt, TriageSubject, WorseningSignal, triage_packet,
};

pub(crate) use self::causes::amendment_causes_in_txn;
pub(in crate::edit_distance) use self::cells::record_untouched_in_txn;
pub(in crate::edit_distance) use self::evidence_judge::{
    amendment_evidence_in_txn, amendment_judgment_in_txn,
};
pub(in crate::edit_distance) use self::origin::UNKNOWN_EXECUTOR;
pub use self::rejection::judge_rejection_with_cause;
pub(in crate::edit_distance) use self::rejection::{
    Rejection, judge_rejection_in_txn, judge_rejection_with_cause_in_txn,
};
pub(crate) use self::scope_erase::erase_amendment_project_in_txn;

/// The recorded, grounded attempt→amendment joins, judged or not: every
/// evidence row that names the attempt its amended proposal came from, keyed
/// by that attempt's pack receipt id, in amendment receipt-id order.
///
/// One snapshot of the evidence ledger. The join is the one the evidence door
/// grounded ([`AmendmentEvidence::with_attempt`]); no judgment is read, and no
/// join is inferred from time or text.
///
/// # Errors
///
/// [`crate::error::Error::CorruptedIndex`] on an undecodable row; storage
/// errors.
pub fn amendments_by_attempt(
    vault: &crate::Vault,
) -> crate::error::Result<std::collections::BTreeMap<String, Vec<AmendmentEvidence>>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut by_attempt: std::collections::BTreeMap<String, Vec<AmendmentEvidence>> =
        std::collections::BTreeMap::new();
    for row in stored::EVIDENCE.iter_from(&vault.store, &rtxn, &[])? {
        let (receipt_id, row) = row?;
        let Some(attempt) = row.attempt else {
            continue;
        };
        if let Some(evidence) = amendment_evidence_in_txn(vault, &rtxn, &receipt_id)? {
            by_attempt.entry(attempt).or_default().push(evidence);
        }
    }
    Ok(by_attempt)
}

#[cfg(test)]
mod tests;

// The flat attribution.rs module used to provide these names to the sibling test
// module through `use super::*`: its own private crate/std import header (every
// attribution-internal item the tests name bare is a `pub` re-export above).
// After the directory split the seam re-imports the header so `tests.rs`
// resolves exactly as it did before.
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject, PREDICATE_ACTOR_EDIT_COST,
    PREDICATE_SKILL_EDIT_COST,
};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::skill_attribution::{
    AttributionJudge, AttributionVerdict, EditHunk, HunkVerdict, JudgeRequest, OutcomeEvidence,
};
#[cfg(test)]
use crate::temporal::TimeRange;

mod archive;
pub(crate) use archive::{imported_skill_cost_body, validate_imported_skill_cost};
