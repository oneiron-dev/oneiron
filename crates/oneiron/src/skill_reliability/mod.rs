//! ARCH-0053 §5 skill reliability (SK-05, ONE-1738): the Beta(α, β) posterior
//! that decides which skills load, and the demotion of the record's
//! `confidence` field to a rebuildable cache over it.
//!
//! ```text
//! SK-04 judgments ─┐
//!                  ├─▶ outcome ledger ─▶ Beta(α,β) ─▶ skill.reliability CLAIM (truth)
//! contributing ────┘   (per skill,                       │
//!  wins                 keyed by receipt)                ├─▶ SkillRecord.confidence (CACHE)
//!                                                        ├─▶ selection score (mean + UCB)
//!                                                        └─▶ floor crossing → quarantine PROPOSAL
//! ```
//!
//! **Residence, not shape (doc-13 r7).** Reliability is EPISTEMIC, so it lives
//! where epistemic things live: a projector-written superseding CLAIM on the
//! SKILL entity citing the receipts it rests on. The record field that used to
//! hold it is now a materialization — CID-7's demotion pattern, the same
//! "claims are truth, the record is cache" law the contact record follows.
//!
//! **What counts (§5).** Only two classes of outcome move the posterior:
//! - β: an SK-04-routed [`AttributionVerdict::SkillDefect`] judgment — the
//!   skill's content was wrong.
//! - α: a CONTRIBUTING WIN — a terminal pack receipt whose manifest loaded the
//!   skill, whose attempt COMPLETED, and which SK-04 routed to no judgment.
//!
//! Everything else contributes NOTHING, by construction rather than by
//! special-case: an [`AttributionVerdict::ExecutionLapse`] blames the actor and
//! its attempt failed, so it is neither a defect on this skill nor a win; a
//! [`AttributionVerdict::Discovery`] became an edit proposal, not a verdict on
//! reliability. ONE-1737's projector states the seam from its side: "Crediting
//! a win is the reliability posterior's job (ONE-1738), which reads the same
//! receipts."
//!
//! **Companion-surface skills are out** (ARCH-0053 §12 surrogate-verifier
//! residue). A companion skill produces no objective win signal — no attempt,
//! no terminal pack receipt, no attributed outcome — so it simply never enters
//! this ledger. That is why there is no companion special-case here: the input
//! set is attributed outcomes, and companion surfaces produce none.
//!
//! **No shared Beta module exists yet, deliberately.** The OF-184 registry
//! entry lists ONE-1248/1249/1250, but those tickets are PsychProfile storage,
//! SKILL provenance fields and CompactionPacket validation — none of them mints
//! shared posterior machinery. The only landed Beta/UCB code is
//! [`crate::critic::CriticReliability`], which is lens-scoped and carries its
//! own outcome-source policy. [`SkillReliabilityPosterior`] therefore MIRRORS
//! that shape (α, β, apply, mean, UCB) in ~40 lines without importing it;
//! extracting one shared trait is a job for whichever ticket actually owns
//! OF-184, and should be done with both call sites in hand rather than by
//! guessing a seam from one.

mod codec;
mod floor;
mod ledger;
mod posterior;
mod projector;
mod provenance;
mod read;

pub use self::floor::{
    DEFAULT_SKILL_RELIABILITY_FLOOR, PREDICATE_SKILL_QUARANTINE_PROPOSAL,
    SKILL_RELIABILITY_FLOOR_KEY, SKILL_RELIABILITY_FLOOR_MIN_OUTCOMES, check_reliability_floor,
    set_skill_reliability_floor, skill_reliability_floor,
};
pub use self::ledger::{SKILL_RELIABILITY_MAX_CITED_RECEIPTS, record_skill_contributing_win};
pub(crate) use self::ledger::{attributed_outcome_receipts, attributed_outcome_results};
pub use self::posterior::{
    ProvenanceTrustClass, SKILL_RELIABILITY_SCHEMA_VERSION, SkillReliabilityPosterior,
};
pub use self::projector::{
    PREDICATE_SKILL_RELIABILITY, project_skill_reliability, project_skill_reliability_for,
};
pub use self::provenance::{skill_provenance_trust_class, skill_reliability_prior};
pub use self::read::{
    rebuild_skill_confidence_cache, skill_reliability_posterior, skill_selection_score,
};

#[cfg(test)]
mod tests;

// The flat skill_reliability.rs module used to provide these names to the sibling test
// module through `use super::*`: its own private crate/std import header, and the two
// posterior key consts the tests name bare. After the directory split the seam
// re-imports them so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::posterior::{KEY_ALPHA, KEY_BETA};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::skill::{SkillContentHash, SkillRecord};
#[cfg(test)]
use crate::skill_attribution::{AttributionJudgment, AttributionVerdict};
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use rmpv::Value;
