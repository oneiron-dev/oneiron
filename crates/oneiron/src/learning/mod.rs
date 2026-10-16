//! The `learning.*` measured-state family (ARCH-0003 #learning, ARCH-0079
//! #scoring): everything the vault measured about how well its own skills,
//! actors and settings work. It is never about the person, and it stays out
//! of the memory a companion reads.
//!
//! Four claims hold the measurements:
//!
//! | predicate | subject | form |
//! |---|---|---|
//! | `learning.reliability` | any skill role (task skill, judge, critic lens, team pattern, recipe) or an actor | beta |
//! | `learning.edit_cost` | a skill or an actor, after attribution | mean or counts |
//! | `learning.retest_noise` | a judge or any scorer | beta or mean |
//! | `learning.setting` | the skill that uses the knob, or the project | mean or counts |
//!
//! Receipts are the only input. Callers admit anchored outcomes into a cell
//! ([`record_evidence`]); one projector folds them with the cell's prior over
//! the window and writes one superseding head per cell. The family is
//! projector-only: the `learning` namespace is engine-reserved, so no ordinary
//! write can mint one. A thing's own runs are evidence; everything else is a
//! prior with an origin and a weight in runs ([`put_cell_prior`]). Judge swaps
//! are projections ([`record_judge_conversion`]), never rewrites. Team
//! coordination cost is a diagnostic beside the family, never a score
//! ([`coordination`]).

pub mod cell;
pub mod coordination;
pub mod estimate;
pub mod evidence;
pub mod honesty;
pub mod judge;
pub mod prior;
pub mod project;
pub mod read;
pub mod retest;

pub use cell::{LearningCell, LearningPredicate, ROOT_TYPE_NODE, TypeRef};
pub use coordination::{
    CoordinationCost, DuplicateWork, ReuseDelay, TeamEvent, coordination_cost, coordination_runs,
    derive_coordination_cost, label_duplicate_work, project_run_coordination,
    team_events_from_attempts,
};
pub use estimate::{
    BetaView, ESTIMATOR_VERSION, Estimate, EstimateForm, EstimateLabels, EstimateValue, Prior,
    PriorOrigin, Window,
};
pub use evidence::{
    Anchor, CellRow, EvidenceSource, LearningEvidence, Observation, record_evidence,
    withdraw_evidence,
};
pub use judge::{
    DivergenceCase, JudgeConversion, TakeoverVerdict, fit_score_map, judge_takeover_verdict,
    record_judge_conversion, withdraw_judge_conversion,
};
pub use prior::put_cell_prior;
pub use project::{SettingFit, reproject_all_cells};
pub use read::{LearningRead, learning_estimate, read_learning};
pub use retest::{Retest, RetestScore, record_retest};

pub(crate) use evidence::record_evidence_in_txn;
pub(crate) use project::validate_learning_claim_structure;

/// How often a thing worked.
pub const PREDICATE_LEARNING_RELIABILITY: &str = "learning.reliability";
/// How much people had to fix.
pub const PREDICATE_LEARNING_EDIT_COST: &str = "learning.edit_cost";
/// How often a judge disagrees with itself.
pub const PREDICATE_LEARNING_RETEST_NOISE: &str = "learning.retest_noise";
/// The fitted value of a named knob.
pub const PREDICATE_LEARNING_SETTING: &str = "learning.setting";

/// The whole family, an exact table: an unknown future `learning.*`
/// predicate is not silently read as one of these.
pub const LEARNING_PREDICATES: &[&str] = &[
    PREDICATE_LEARNING_RELIABILITY,
    PREDICATE_LEARNING_EDIT_COST,
    PREDICATE_LEARNING_RETEST_NOISE,
    PREDICATE_LEARNING_SETTING,
];

/// The family's namespace, engine-reserved.
pub const LEARNING_NAMESPACE: &str = "learning";

/// Whether `predicate` is in the `learning` namespace. Companion memory reads
/// exclude every such claim: learning views only.
#[must_use]
pub fn is_learning_predicate(predicate: &str) -> bool {
    predicate.split('.').next() == Some(LEARNING_NAMESPACE)
}
