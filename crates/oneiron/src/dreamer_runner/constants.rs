//! Pinned wire vocabulary for the private Dreamer runner rows.

// Referenced only by the intra-doc link below; `cfg(doc)` keeps it out of
// ordinary builds, where it would be an unused import.
#[cfg(doc)]
use crate::attempt_queue::AttemptQueue;

pub use crate::store::dreamer_attempt_kind::DREAMER_ATTEMPT_PAYLOAD_KEYS;
pub use crate::store::dreamer_attempt_kind::DREAMER_ATTEMPT_PAYLOAD_SCHEMA_VERSION;
pub use crate::store::dreamer_attempt_kind::DREAMER_MILESTONE_PREDICATE;
pub use crate::store::dreamer_attempt_kind::DREAMER_MILESTONE_VALUE_KEYS;
pub use crate::store::dreamer_attempt_kind::DREAMER_MILESTONE_VALUE_SCHEMA_VERSION;
pub use crate::store::dreamer_attempt_kind::DREAMER_RUNNER_ATTEMPT_KIND;

pub use crate::store::dreamer_attempt_kind::DEFAULT_DREAMER_CHILD_RESERVE_UNITS;
pub use crate::store::dreamer_attempt_kind::DEFAULT_DREAMER_TOURNAMENT_DEPTH_K;
pub use crate::store::dreamer_attempt_kind::DEFAULT_DREAMER_TOURNAMENT_FANOUT_M;
pub use crate::store::dreamer_attempt_kind::DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND;
pub use crate::store::dreamer_attempt_kind::DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND;
pub use crate::store::dreamer_attempt_kind::DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND;
pub use crate::store::dreamer_attempt_kind::DREAMER_FREE_TIME_FOR_HUMAN_ATTEMPT_KIND;
pub use crate::store::dreamer_attempt_kind::DREAMER_NOTE_REVIEW_ATTEMPT_KIND;
pub use crate::store::dreamer_attempt_kind::DREAMER_RECIPE_WAKE_ATTEMPT_KIND;
pub use crate::store::dreamer_attempt_kind::DREAMER_RESIDENT_DREAM_ATTEMPT_KIND;
pub use crate::store::dreamer_attempt_kind::DREAMER_SKILL_OPTIMIZE_ATTEMPT_KIND;
pub use crate::store::dreamer_attempt_kind::DREAMER_VAULT_CLEANUP_ATTEMPT_KIND;
pub use crate::store::dreamer_attempt_kind::DREAMER_WEAVE_RECIPE_ATTEMPT_KIND;
/// A Dreamer-lane TASK's realization: the one row `tasks.create` queues for
/// a TASK routed to the Dreamer, carrying the TASK's bare spec rather than
/// the runner envelope. Admitted on any wake after the wake recipes; its one
/// model step writes the research NOTE the TASK's result names.
pub const DREAMER_TASK_REALIZE_ATTEMPT_KIND: &str =
    crate::task_verb::highway_runner::REALIZE_ATTEMPT_KIND;
pub use crate::store::dreamer_attempt_kind::COACH_HEAL_ATTEMPT_KIND;
pub use crate::store::dreamer_attempt_kind::COACH_RETRIEVAL_TUNE_FACET;
pub use crate::store::dreamer_attempt_kind::DREAMER_HOME_NODE_DESIGNATION_KEYS;
pub use crate::store::dreamer_attempt_kind::DREAMER_HOME_NODE_DESIGNATION_SCHEMA_VERSION;
pub use crate::store::dreamer_attempt_kind::DREAMER_TURN_PROGRAM_ATTEMPT_KIND;
pub use crate::store::dreamer_attempt_kind::DREAMER_WEAVE_LENS_ATTEMPT_KIND;

// Storage/wire keys keep the legacy "job" spelling; ONE-1714 renamed code only.
pub(super) use crate::store::dreamer_attempt_payload::{KEY_PARENT_ATTEMPT, KEY_SCHEMA_VERSION};
pub(super) const KEY_ATTEMPT_ID: &str = "job_id";
pub(super) const KEY_MILESTONE: &str = "milestone";
pub(super) const KEY_AT: &str = "at";
pub(super) const KEY_BUDGET_ID: &str = "budget_id";
pub(super) const KEY_TOTAL_UNITS: &str = "total_units";
pub(super) const KEY_REMAINING_UNITS: &str = "remaining_units";
pub(super) const KEY_RESERVED_UNITS: &str = "reserved_units";
pub(super) const KEY_OVERDRAFT_UNITS: &str = "overdraft_units";
pub(super) const KEY_OWED_CALLS: &str = "owed_calls";
pub(super) const KEY_OWED_UNITS: &str = "owed_units";
pub(super) const KEY_UPDATED_AT: &str = "updated_at";
pub(super) const KEY_CREATED_AT: &str = "created_at";
pub(super) const KEY_NODE_ID: &str = "node_id";
pub(super) const KEY_CLASS: &str = "class";
pub(super) const KEY_ELECTED_AT: &str = "elected_at";
pub(super) const KEY_REASON: &str = "reason";
pub(super) const KEY_PARK_OWNER: &str = "park_owner";
pub(super) const KEY_PARKED_AT: &str = "parked_at";
pub(super) const KEY_CAUSE: &str = "cause";
pub(super) const KEY_CARRIED_SPEND: &str = "carried_spend";

// v2 adds the mandatory overdraft and owed keys (FIX 8702, 8728, 9015).
pub(super) const DREAMER_BUDGET_SCHEMA_VERSION: u64 = 2;
pub(super) const DREAMER_BUDGET_RESERVATION_SCHEMA_VERSION: u64 = 2;
pub(super) const DREAMER_RUN_TREE_SCHEMA_VERSION: u64 = 1;
// v2 adds the mandatory `park_owner` token; v1 rows (no owner) fail closed.
// The typed `cause` key is mandatory too: a row without one fails closed.
// v3 adds the mandatory `carried_spend` key (`None` encodes as nil).
pub(super) const DREAMER_PARKED_SCHEMA_VERSION: u64 = 3;
pub(super) const DREAMER_BUDGET_KEYS: [&str; 8] = [
    KEY_SCHEMA_VERSION,
    KEY_BUDGET_ID,
    KEY_TOTAL_UNITS,
    KEY_REMAINING_UNITS,
    KEY_RESERVED_UNITS,
    KEY_OVERDRAFT_UNITS,
    KEY_OWED_CALLS,
    KEY_UPDATED_AT,
];
pub(super) const DREAMER_BUDGET_RESERVATION_KEYS: [&str; 7] = [
    KEY_SCHEMA_VERSION,
    KEY_BUDGET_ID,
    KEY_ATTEMPT_ID,
    KEY_RESERVED_UNITS,
    KEY_OWED_UNITS,
    KEY_CREATED_AT,
    KEY_UPDATED_AT,
];
pub(super) const DREAMER_RUN_TREE_KEYS: [&str; 4] = [
    KEY_SCHEMA_VERSION,
    KEY_ATTEMPT_ID,
    KEY_PARENT_ATTEMPT,
    KEY_CREATED_AT,
];
pub(super) const DREAMER_PARKED_KEYS: [&str; 7] = [
    KEY_SCHEMA_VERSION,
    KEY_ATTEMPT_ID,
    KEY_REASON,
    KEY_CAUSE,
    KEY_PARK_OWNER,
    KEY_CARRIED_SPEND,
    KEY_PARKED_AT,
];

pub(super) const MIN_DREAMER_TOURNAMENT_SAMPLE_COUNT: u32 = 3;
pub(super) const DREAMER_CLAIM_AUTHORING_BUDGET_TRAP_ACTOR: &str = "dreamer-budget-trap";
pub(super) const DREAMER_CLAIM_AUTHORING_BUDGET_TRAP_NOTE: &str =
    "BudgetTrap: tournament claim authoring suspended for budget approval";
