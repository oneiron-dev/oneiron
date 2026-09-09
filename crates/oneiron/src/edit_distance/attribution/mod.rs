//! ED-03 (ONE-1759, ARCH-0056 §5): the amendment JUDGE, and the `*.edit_cost`
//! claim rows a judged amendment earns.
//!
//! ```text
//! Δ RECEIPT (ED-01/02)  +  routing facts (recorded at the amendment door)
//!   └─ judge_amendment ──> AmendmentJudgment
//!        ├─ skill_defect     → skill.edit_cost   (SKILL entity)
//!        ├─ execution_lapse  → actor.edit_cost   (ACTOR entity)
//!        ├─ discovery        → nothing here; SK-04 already owns its consequence
//!        ├─ environment      → nothing at all — the judgment row IS the record
//!        └─ preference_shift → a PREFERENCE proposal for ED-04's miner
//! ```
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
//! [`AttributionJudge`] — SK-04's own trait, SK-04's own rule table, SK-04's
//! own [`crate::skill_attribution::attribution_call_purpose`] for an LLM tier.
//! There is no second classifier here and no LLM client: the import direction
//! is the proof, and a host that wants a model tier implements SK-04's trait
//! rather than a new one.
//!
//! # Cost is an AGGREGATE, never a raw Δ
//!
//! [`project_edit_cost_claims`] takes JUDGMENTS, not deltas — that signature is
//! the guard. A `d_norm` reaches a claim only after a class named who owns it,
//! and the value written is the mean over every persisted judgment sharing the
//! row's `(subject, scope)` pair. Recomputed from the judgment ledger on every
//! pass, so an interrupted pass leaves a stale row the next pass corrects,
//! never a double-counted one (the [`crate::skill_reliability`] posture).
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
mod evidence_judge;
mod projector;
mod stored;
mod taxonomy;

pub use self::audit::{
    AmendmentAuditFixture, held_out_amendment_fixtures, judge_audit_reports, run_judge_audit,
    run_judge_audit_with_judge,
};
pub use self::evidence_judge::{
    amendment_evidence, amendment_judgments, judge_amendment, judge_amendment_with,
    pending_preference_proposals, record_amendment_evidence,
};
pub use self::projector::{edit_cost_for, project_edit_cost_claims};
pub use self::taxonomy::{
    AmendmentCause, AmendmentClass, AmendmentEvidence, AmendmentJudgment, PreferenceProposal,
    classify_amendment,
};

pub(in crate::edit_distance) use self::evidence_judge::amendment_evidence_in_txn;

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
    AttributionJudge, AttributionVerdict, OutcomeEvidence, RuleAttributionJudge,
};
#[cfg(test)]
use crate::temporal::TimeRange;
