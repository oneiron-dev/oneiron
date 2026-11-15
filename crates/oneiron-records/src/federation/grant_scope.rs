//! Moved from `crates/oneiron/src/federation/grant_scope.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// A Steward reads across its vault root.
pub const STEWARD_READ_VERB: &str = "read";

/// A Steward lands what it derives (for an agent: the Auto ceiling and the
/// `Generated` permit its consolidation needs).
pub const STEWARD_DERIVE_VERB: &str = "derive";

/// A Steward archives inside its grant, reversibly.
pub const STEWARD_ARCHIVE_VERB: &str = "archive";

/// A Steward tunes the engine's knobs (untangle 6.6, S66-1), one verb per
/// class of knob (lead 10 Nov 06:5x), so an owner gives an agent only the
/// classes it needs: maintenance cadence, work budgets inside the owner's
/// caps, system-agent wake cadence, and which recipe a knowledge job runs.
/// Owner acts stay outside them. No role default gives them: the Coach's
/// default grant names all four, and an owner can give any of them to any
/// agent.
pub const ENGINE_CONTROLS_MAINTENANCE_CADENCE_VERB: &str = "engine.controls.maintenance_cadence";

/// The work-budget class of `engine.controls` (see above).
pub const ENGINE_CONTROLS_WORK_BUDGET_VERB: &str = "engine.controls.work_budget";

/// The wake-cadence class of `engine.controls` (see above).
pub const ENGINE_CONTROLS_WAKE_CADENCE_VERB: &str = "engine.controls.wake_cadence";

/// The knowledge-recipe class of `engine.controls` (see above).
pub const ENGINE_CONTROLS_KNOWLEDGE_RECIPE_VERB: &str = "engine.controls.knowledge_recipe";

/// The four `engine.controls` class verbs.
pub const ENGINE_CONTROLS_VERBS: [&str; 4] = [
    ENGINE_CONTROLS_MAINTENANCE_CADENCE_VERB,
    ENGINE_CONTROLS_WORK_BUDGET_VERB,
    ENGINE_CONTROLS_WAKE_CADENCE_VERB,
    ENGINE_CONTROLS_KNOWLEDGE_RECIPE_VERB,
];
