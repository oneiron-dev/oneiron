//! Pinned wire vocabulary for the private Dreamer runner rows.

// Referenced only by the intra-doc link below; `cfg(doc)` keeps it out of
// ordinary builds, where it would be an unused import.
#[cfg(doc)]
use crate::attempt_queue::AttemptQueue;

/// Generic [`AttemptQueue`] kind used by Dreamer runner attempts.
pub const DREAMER_RUNNER_ATTEMPT_KIND: &str = "dreamer";
/// Current pinned Dreamer attempt payload schema version.
pub const DREAMER_ATTEMPT_PAYLOAD_SCHEMA_VERSION: u64 = 1;
/// Pinned on-disk MessagePack key set for Dreamer attempt payloads.
pub const DREAMER_ATTEMPT_PAYLOAD_KEYS: [&str; 4] =
    ["schema_version", "job_type", "input", "parent_job"];
/// Claim predicate used for durable Dreamer attempt milestones.
pub const DREAMER_MILESTONE_PREDICATE: &str = "dreamer.job_milestone";
/// Current pinned Dreamer milestone claim value schema version.
pub const DREAMER_MILESTONE_VALUE_SCHEMA_VERSION: u64 = 1;
/// Pinned on-disk MessagePack key set for Dreamer milestone claim values.
pub const DREAMER_MILESTONE_VALUE_KEYS: [&str; 4] = ["schema_version", "job_id", "milestone", "at"];
pub(super) const DREAMER_MILESTONE_INDEX_CANDIDATE_PREFIX: &[u8] = b"dreamer.milestone_index.v1.c:";
pub(super) const DREAMER_MILESTONE_INDEX_CLAIM_PREFIX: &[u8] = b"dreamer.milestone_index.v1.i:";
pub(super) const DREAMER_MILESTONE_INDEX_BACKFILLED_KEY: &[u8] =
    b"dreamer.milestone_index.v1.backfilled";
pub(super) const DREAMER_MILESTONE_INDEX_CANDIDATE_KEY_LEN: usize =
    DREAMER_MILESTONE_INDEX_CANDIDATE_PREFIX.len() + 16 + 8 + 8 + 16;

/// Default fan-out reservation for one Dreamer child, in token-like units.
pub const DEFAULT_DREAMER_CHILD_RESERVE_UNITS: u64 = 8_000;
/// Default OF-366 tournament candidate fan-out.
pub const DEFAULT_DREAMER_TOURNAMENT_FANOUT_M: u16 = 2;
/// Default OF-366 tournament refinement depth.
pub const DEFAULT_DREAMER_TOURNAMENT_DEPTH_K: u16 = 2;
/// MICRO consolidation queue kind. Private per-device attempt rows only.
pub const DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND: &str = "dreamer.consolidation.micro";
/// MESO consolidation queue kind. Private per-device attempt rows only.
pub const DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND: &str = "dreamer.consolidation.meso";
/// MACRO consolidation queue kind. Admission is restricted to the elected home node.
pub const DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND: &str = "dreamer.consolidation.macro";
/// Current pinned home-node designation schema version.
pub const DREAMER_HOME_NODE_DESIGNATION_SCHEMA_VERSION: u64 = 1;
/// Pinned on-disk MessagePack key set for the private home-node designation.
pub const DREAMER_HOME_NODE_DESIGNATION_KEYS: [&str; 4] =
    ["schema_version", "node_id", "class", "elected_at"];

// Storage/wire keys keep the legacy "job" spelling; ONE-1714 renamed code only.
pub(super) const KEY_SCHEMA_VERSION: &str = "schema_version";
pub(super) const KEY_ATTEMPT_TYPE: &str = "job_type";
pub(super) const KEY_INPUT: &str = "input";
pub(super) const KEY_PARENT_ATTEMPT: &str = "parent_job";
pub(super) const KEY_ATTEMPT_ID: &str = "job_id";
pub(super) const KEY_MILESTONE: &str = "milestone";
pub(super) const KEY_AT: &str = "at";
pub(super) const KEY_BUDGET_ID: &str = "budget_id";
pub(super) const KEY_TOTAL_UNITS: &str = "total_units";
pub(super) const KEY_REMAINING_UNITS: &str = "remaining_units";
pub(super) const KEY_RESERVED_UNITS: &str = "reserved_units";
pub(super) const KEY_UPDATED_AT: &str = "updated_at";
pub(super) const KEY_CREATED_AT: &str = "created_at";
pub(super) const KEY_NODE_ID: &str = "node_id";
pub(super) const KEY_CLASS: &str = "class";
pub(super) const KEY_ELECTED_AT: &str = "elected_at";
pub(super) const KEY_REASON: &str = "reason";
pub(super) const KEY_PARK_OWNER: &str = "park_owner";
pub(super) const KEY_PARKED_AT: &str = "parked_at";

pub(super) const DREAMER_BUDGET_SCHEMA_VERSION: u64 = 1;
pub(super) const DREAMER_BUDGET_RESERVATION_SCHEMA_VERSION: u64 = 1;
pub(super) const DREAMER_RUN_TREE_SCHEMA_VERSION: u64 = 1;
// v2 adds the mandatory `park_owner` token; v1 rows (no owner) fail closed.
pub(super) const DREAMER_PARKED_SCHEMA_VERSION: u64 = 2;
pub(super) const DREAMER_BUDGET_KEYS: [&str; 6] = [
    KEY_SCHEMA_VERSION,
    KEY_BUDGET_ID,
    KEY_TOTAL_UNITS,
    KEY_REMAINING_UNITS,
    KEY_RESERVED_UNITS,
    KEY_UPDATED_AT,
];
pub(super) const DREAMER_BUDGET_RESERVATION_KEYS: [&str; 6] = [
    KEY_SCHEMA_VERSION,
    KEY_BUDGET_ID,
    KEY_ATTEMPT_ID,
    KEY_RESERVED_UNITS,
    KEY_CREATED_AT,
    KEY_UPDATED_AT,
];
pub(super) const DREAMER_RUN_TREE_KEYS: [&str; 4] = [
    KEY_SCHEMA_VERSION,
    KEY_ATTEMPT_ID,
    KEY_PARENT_ATTEMPT,
    KEY_CREATED_AT,
];
pub(super) const DREAMER_PARKED_KEYS: [&str; 5] = [
    KEY_SCHEMA_VERSION,
    KEY_ATTEMPT_ID,
    KEY_REASON,
    KEY_PARK_OWNER,
    KEY_PARKED_AT,
];
pub(super) const DREAMER_PRIVATE_BUDGET_PREFIX: &[u8] = b"dreamer:budget:";
pub(super) const DREAMER_PRIVATE_BUDGET_RESERVATION_PREFIX: &[u8] = b"dreamer:budget_reservation:";
pub(super) const DREAMER_PRIVATE_RUN_TREE_PREFIX: &[u8] = b"dreamer:run_tree:";
pub(super) const DREAMER_PRIVATE_PARKED_PREFIX: &[u8] = b"dreamer:parked:";
pub(super) const DREAMER_PRIVATE_HOME_NODE_KEY: &[u8] = b"dreamer:home_node_macro:v1";
pub(super) const MAX_DREAMER_ATTEMPT_TYPE_LEN: usize = 128;
pub(super) const MAX_DREAMER_BUDGET_ID_LEN: usize = 128;
pub(super) const MAX_DREAMER_PARK_REASON_LEN: usize = 512;
pub(super) const MAX_DREAMER_PARK_OWNER_LEN: usize = 128;

pub(super) const MIN_DREAMER_TOURNAMENT_SAMPLE_COUNT: u32 = 3;
pub(super) const DREAMER_CLAIM_AUTHORING_BUDGET_TRAP_ACTOR: &str = "dreamer-budget-trap";
pub(super) const DREAMER_CLAIM_AUTHORING_BUDGET_TRAP_NOTE: &str =
    "BudgetTrap: tournament claim authoring suspended for budget approval";
