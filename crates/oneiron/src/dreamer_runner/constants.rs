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
/// A per-vault, owner-admitted workflow skill executed under the Dreamer stamp.
pub const DREAMER_WEAVE_RECIPE_ATTEMPT_KIND: &str = "dreamer.weave_recipe";
/// The wake policy's recipe lane (ARCH-0026 #wake): one attempt per policy
/// decision, naming the recipe whose input row the policy outbox holds.
/// Vault-local, like maintenance: it is never a partition and needs no home
/// election, though a recipe body may queue Macro work that does. Doubles as
/// the payload `job_type`.
pub const DREAMER_RECIPE_WAKE_ATTEMPT_KIND: &str = "dreamer.recipe_wake";
/// SKILL-OPT maintenance queue kind (ONE-1448). Private per-device attempt
/// rows, like MICRO/MESO: the job only DRAFTS gated proposals, so a second
/// device drafting one is a second question for a human, never a second edit.
///
/// Doubles as the payload `job_type` this attempt carries — the dotted-name
/// convention `dreamer.reflection.gap_scan` and
/// `dreamer.edit_distance.substitution_mine` already use — so the kind gate
/// and the payload discriminator can never drift apart.
pub const DREAMER_SKILL_OPTIMIZE_ATTEMPT_KIND: &str = "dreamer.skill_optimize";
/// ARCH-0073 vault auto-cleanup queue kind (ONE-1931). Private per-device
/// attempt rows, like MICRO/MESO and SKILL-OPT: the pass reads one vault's own
/// rows and, in the default propose-first posture, only DRAFTS a proposal, so
/// a second device running it is a second question for a human, never a
/// second archive.
///
/// Doubles as the payload `job_type` this attempt carries, following the same
/// dotted-name convention as [`DREAMER_SKILL_OPTIMIZE_ATTEMPT_KIND`], so the
/// kind gate and the payload discriminator cannot drift apart. Registered on
/// the TIMER wake (Macro scope) alone — see
/// [`crate::dreamer_runner::EnqueueDreamerVaultCleanupAttempt`].
pub const DREAMER_VAULT_CLEANUP_ATTEMPT_KIND: &str = "dreamer.vault_cleanup";
/// ARCH-0032 stage 2 NOTE review queue kind (OF-073): the Dreamer reads the
/// NOTEs whose kind allows extraction and promotes the beliefs each one
/// grounds. A Nightly child, admitted on the Timer wake (Macro scope) like the
/// cleanup pass; private per-device rows, since every write goes through the
/// promotion gate.
///
/// Doubles as the payload `job_type`, so the kind gate and the payload
/// discriminator cannot drift apart.
pub const DREAMER_NOTE_REVIEW_ATTEMPT_KIND: &str = "dreamer.note_review";
/// A resident's own dreaming (OF-490): one Nightly child per resident whose
/// definition is on and whose dreaming is not off. It runs under the
/// resident's own stamp, not the Dreamer's, and writes the resident's diary.
/// Admitted on the Timer wake (Macro scope) after the NOTE review.
///
/// Doubles as the payload `job_type`.
pub const DREAMER_RESIDENT_DREAM_ATTEMPT_KIND: &str = "dreamer.resident_dream";
/// A Dreamer-lane TASK's realization: the one row `tasks.create` queues for
/// a TASK routed to the Dreamer, carrying the TASK's bare spec rather than
/// the runner envelope. Admitted on any wake after the wake recipes; its one
/// model step writes the research NOTE the TASK's result names.
pub const DREAMER_TASK_REALIZE_ATTEMPT_KIND: &str =
    crate::task_verb::highway_runner::REALIZE_ATTEMPT_KIND;
/// The weave lens's generate step (OF-499): one saved digest period
/// rendered through the shipped `weave-report` skill on a lent model, queued
/// in the period's publication. Its render lands on the period's row.
///
/// Doubles as the payload `job_type`.
pub const DREAMER_WEAVE_LENS_ATTEMPT_KIND: &str = "dreamer.weave_lens";
/// The Coach's live heal queue kind (ARCH-0066 #coach): one attempt per
/// failure-ladder case the escalation hands to the Coach. Host-run, like agent
/// dispatch: the wake driver never admits it; a host Coach leases it with
/// [`crate::dreamer_runner::DreamerRunnerStore::admit_next_coach_heal`].
/// Doubles as the payload `job_type`.
pub const COACH_HEAL_ATTEMPT_KIND: &str = "coach.heal";
/// The Coach's nightly retrieval-tuning facet on the maintenance lane,
/// registered beside the cleanup pass on the Timer wake.
pub const COACH_RETRIEVAL_TUNE_FACET: &str = "coach.retrieval_tune";
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
pub(super) const KEY_CAUSE: &str = "cause";

pub(super) const DREAMER_BUDGET_SCHEMA_VERSION: u64 = 1;
pub(super) const DREAMER_BUDGET_RESERVATION_SCHEMA_VERSION: u64 = 1;
pub(super) const DREAMER_RUN_TREE_SCHEMA_VERSION: u64 = 1;
// v2 adds the mandatory `park_owner` token; v1 rows (no owner) fail closed.
// The typed `cause` key is mandatory too: a row without one fails closed.
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
pub(super) const DREAMER_PARKED_KEYS: [&str; 6] = [
    KEY_SCHEMA_VERSION,
    KEY_ATTEMPT_ID,
    KEY_REASON,
    KEY_CAUSE,
    KEY_PARK_OWNER,
    KEY_PARKED_AT,
];

pub(super) const MIN_DREAMER_TOURNAMENT_SAMPLE_COUNT: u32 = 3;
pub(super) const DREAMER_CLAIM_AUTHORING_BUDGET_TRAP_ACTOR: &str = "dreamer-budget-trap";
pub(super) const DREAMER_CLAIM_AUTHORING_BUDGET_TRAP_NOTE: &str =
    "BudgetTrap: tournament claim authoring suspended for budget approval";
