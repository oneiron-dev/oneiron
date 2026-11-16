//! Moved from `crates/oneiron/src/learning_setting.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::setting_seed::ATTRIBUTION_UNCLEAR_FLOOR;
pub use oneiron_store::setting_seed::AUDIT_RATE;
pub use oneiron_store::setting_seed::CONTRIBUTION_CHECK_RATE;
pub use oneiron_store::setting_seed::CREDIT_CHECK_EVERY_HOP;
pub use oneiron_store::setting_seed::CREDIT_DECAY;
pub use oneiron_store::setting_seed::CREDIT_DEPTH_CAP;
pub use oneiron_store::setting_seed::CREDIT_ENABLED;
pub use oneiron_store::setting_seed::GROUP_COMMIT_MAX_WRITES;
pub use oneiron_store::setting_seed::GROUP_COMMIT_WINDOW_MS;
pub use oneiron_store::setting_seed::LEARNING_BORROWED_PRIOR_RUNS;
pub use oneiron_store::setting_seed::LEARNING_SHIPPED_PRIOR_RUNS;
pub use oneiron_store::setting_seed::LEARNING_WINDOW_HALF_LIFE_DAYS;
pub use oneiron_store::setting_seed::PLANNER_BIG_PLAN_WIDTH;
pub use oneiron_store::setting_seed::PLANNER_SOLO_MARGIN;
pub use oneiron_store::setting_seed::PLANNER_SOLO_SUCCESS_FLOOR;
pub use oneiron_store::setting_seed::SettingSpec;

/// The fewest families an offer eval set needs (FIX 10446): the owner's
/// floor for a measured card. Zero asks for none.
pub const EVAL_FLOOR_MIN_FAMILIES: SettingSpec = SettingSpec {
    key: "eval_floor_min_families",
    min: 0.0,
    max: 1_000_000.0,
    seed: 0.0,
};

/// The fewest families each required floor slice needs (FIX 10446). Zero
/// asks for none.
pub const EVAL_FLOOR_MIN_FAMILIES_PER_SLICE: SettingSpec = SettingSpec {
    key: "eval_floor_min_families_per_slice",
    min: 0.0,
    max: 1_000_000.0,
    seed: 0.0,
};

pub const ROW_VERSION: u8 = 2;

pub const ROW_LABEL: &str = "learning setting row";
