//! Bayesian skill retrieval over the shared learning.reliability projection.
//!
//! The outcome ledger remains the attribution boundary: a contributing win,
//! routed skill defect or amended defect share belongs to the executor that
//! ran it. The receipt supplies its required task placement and scored axis.
//! Only anchored outcomes add own runs. Carried executor histories, parent
//! types and provenance enter as weighted priors; UNTESTED lasts until own
//! runs reach that weight. Judge conversions change the view, never receipts.
//! Skill arms pick by UCB through the shared Posterior interface. The scalar
//! SkillRecord confidence is only a diagnostic cache and never a ranking input.

mod amended;
mod callable;
mod codec;
mod floor;
mod ledger;
mod posterior;
mod priors;
mod projector;
mod provenance;
mod read;
mod resident;

pub(crate) use self::amended::{AmendedOutcome, reconcile_amended_outcomes_in_txn};
pub(crate) use self::callable::{project_callable_receipt_outcome, record_callable_invocation};
pub use self::floor::{
    DEFAULT_SKILL_RELIABILITY_FLOOR, PREDICATE_SKILL_QUARANTINE_PROPOSAL,
    SKILL_RELIABILITY_FLOOR_KEY, SKILL_RELIABILITY_FLOOR_MIN_OUTCOMES, check_reliability_floor,
    check_reliability_floor_for_executor, set_skill_reliability_floor, skill_reliability_floor,
};
pub use self::ledger::{
    SKILL_RELIABILITY_MAX_CITED_RECEIPTS, effective_skill_outcome,
    record_resident_skill_contributing_win, record_skill_contributing_win,
};
pub(crate) use self::ledger::{
    attributed_outcome_receipts, attributed_outcome_results, attributed_outcomes_weighted,
    mark_displaced_outcome_in_txn,
};
pub use self::posterior::{
    ProvenanceTrustClass, SKILL_RELIABILITY_SCHEMA_VERSION, SkillReliabilityPosterior,
};
pub use self::projector::{
    FIELD_SKILL_LEARNING_ANCHOR, FIELD_SKILL_TYPE_REF, PREDICATE_SKILL_RELIABILITY,
    SKILL_OUTCOME_AXIS, project_skill_reliability, project_skill_reliability_for,
    project_skill_reliability_for_executor,
};
pub use self::provenance::{skill_provenance_trust_class, skill_reliability_prior};
pub(crate) use self::provenance::skill_reliability_sources;
pub use self::read::{
    ExecutorReliability, SkillReliabilityQuery, read_skill_reliability,
    rebuild_skill_confidence_cache, skill_executor_reliability, skill_reliability_posterior,
    skill_reliability_posterior_for_executor, skill_selection_score,
    skill_selection_score_for_executor,
};
pub(crate) use self::read::{
    selection_posterior_for_query_in_txn, skill_selection_score_from_posterior, validate_executor,
};
pub use self::resident::rank_resident_skill_versions;

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

mod archive;
pub(crate) use archive::{imported_reliability_body, validate_imported_reliability};
