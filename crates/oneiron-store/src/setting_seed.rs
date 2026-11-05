//! Learned numeric setting specifications and shipped seeds.

/// One learned knob: its key, its bounds and the value it ships with.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SettingSpec {
    /// The catalog key, the `setting_key` a seed or pin row targets.
    pub key: &'static str,
    /// Lowest admissible value, inclusive.
    pub min: f64,
    /// Highest admissible value, inclusive.
    pub max: f64,
    /// The shipped seed: the value in force until the owner seeds or pins one.
    pub seed: f64,
}

/// The attribution judge's confidence floor (ARCH-0056 §5 #unclear-floor):
/// below it, a hunk's verdict is recorded as `unclear` and charges nobody.
pub const ATTRIBUTION_UNCLEAR_FLOOR: SettingSpec = SettingSpec {
    key: "attribution_unclear_floor",
    min: 0.0,
    max: 1.0,
    seed: 0.6,
};

/// How long a group commit at the vault's single writer may wait, with its
/// queue empty, for writes already on their way, in milliseconds counted from
/// when the group opened (ARCH-0019 group-commit invariant, OF-536). It bounds
/// that idle wait only: writes already queued join regardless, up to
/// [`GROUP_COMMIT_MAX_WRITES`], until one that runs alone (a host's callback)
/// or holds a session-overlay segment closes the group. A group never waits
/// when no write is on its way, so a lone writer pays nothing; zero closes
/// every group as soon as its queue is empty.
pub const GROUP_COMMIT_WINDOW_MS: SettingSpec = SettingSpec {
    key: "group_commit_window_ms",
    min: 0.0,
    max: 50.0,
    seed: 2.0,
};

/// The most logical writes one group commit carries before it closes. One
/// gives every logical write its own transaction and fsync.
pub const GROUP_COMMIT_MAX_WRITES: SettingSpec = SettingSpec {
    key: "group_commit_max_writes",
    min: 1.0,
    max: 4096.0,
    seed: 256.0,
};

/// The share of credit a used lineage hop passes up (ARCH-0003
/// #learning-settings `credit_decay`): halving per hop by default.
pub const CREDIT_DECAY: SettingSpec = SettingSpec {
    key: "credit_decay",
    min: 0.0,
    max: 1.0,
    seed: 0.5,
};

/// Whether used lineage hops pass late credit up at all (ARCH-0037
/// #lineage-credit, the power user's off switch): on at one half or more.
pub const CREDIT_ENABLED: SettingSpec = SettingSpec {
    key: "credit_enabled",
    min: 0.0,
    max: 1.0,
    seed: 1.0,
};

/// The most used hops late credit climbs from an outcome (ARCH-0037
/// #lineage-credit); at its maximum, the full used chain, canon's default.
pub const CREDIT_DEPTH_CAP: SettingSpec = SettingSpec {
    key: "credit_depth_cap",
    min: 0.0,
    max: 1024.0,
    seed: 1024.0,
};

/// Whether late credit crosses only hops a contribution check measured
/// (ARCH-0037 #lineage-credit): on at one half or more; off by default, so
/// an unchecked used hop passes credit.
pub const CREDIT_CHECK_EVERY_HOP: SettingSpec = SettingSpec {
    key: "credit_check_every_hop",
    min: 0.0,
    max: 1.0,
    seed: 0.0,
};

/// The probability of a random audit (`audit_rate`). Its floor is strictly
/// above zero: the honesty floor never samples nothing.
pub const AUDIT_RATE: SettingSpec = SettingSpec {
    key: "audit_rate",
    min: 0.001,
    max: 1.0,
    seed: 0.05,
};

/// The `learning.*` window: old runs halve in weight every this many days, so
/// a silent vendor update under one model id shows up in the estimate.
pub const LEARNING_WINDOW_HALF_LIFE_DAYS: SettingSpec = SettingSpec {
    key: "learning_window_half_life_days",
    min: 1.0,
    max: 3650.0,
    seed: 90.0,
};

/// The weight in runs a catalog seed carries as a `learning.setting` prior
/// when the owner has seeded nothing.
pub const LEARNING_SHIPPED_PRIOR_RUNS: SettingSpec = SettingSpec {
    key: "learning_shipped_prior_runs",
    min: 0.0,
    max: 100.0,
    seed: 2.0,
};

/// The most runs a borrowed reading (a parent type's, another executor's)
/// counts as: carried weakly, so a cell's own runs soon outweigh it.
pub const LEARNING_BORROWED_PRIOR_RUNS: SettingSpec = SettingSpec {
    key: "learning_borrowed_prior_runs",
    min: 0.0,
    max: 100.0,
    seed: 2.0,
};

/// The share of credited runs whose followed skills get a matched-fork
/// contribution check (ARCH-0037 #lineage-credit): each check regenerates a
/// step twice, with and without the skill. Zero checks none.
pub const CONTRIBUTION_CHECK_RATE: SettingSpec = SettingSpec {
    key: "contribution_check_rate",
    min: 0.0,
    max: 1.0,
    seed: 0.1,
};

/// The spawn planner's solo-first gate floor (ARCH-0079 #planner, OF-541):
/// when solo's measured success rate for a task type is at or above this,
/// a team must clear [`PLANNER_SOLO_MARGIN`] past solo to displace it.
pub const PLANNER_SOLO_SUCCESS_FLOOR: SettingSpec = SettingSpec {
    key: "planner_solo_success_floor",
    min: 0.0,
    max: 1.0,
    seed: 0.7,
};

/// How far past solo's success rate a team shape must project before the
/// planner prefers it once the solo-first gate is engaged.
pub const PLANNER_SOLO_MARGIN: SettingSpec = SettingSpec {
    key: "planner_solo_margin",
    min: 0.0,
    max: 1.0,
    seed: 0.05,
};

/// The spawn width at which a plan counts as big and the planner ladder
/// climbs to its strong rung regardless of care.
pub const PLANNER_BIG_PLAN_WIDTH: SettingSpec = SettingSpec {
    key: "planner_big_plan_width",
    min: 1.0,
    max: 10000.0,
    seed: 16.0,
};
