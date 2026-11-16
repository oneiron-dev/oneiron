//! Moved from `crates/oneiron/src/federation/engine_controls.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::federation::grant_scope;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The class of knob a change touches. Each class has its own grant verb
/// ([`Self::grant_verb`]); the class names the change in its receipt.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EngineControlClass {
    /// Maintenance schedules and cadences: compaction, cleanup, retention
    /// sweeps, consolidation and nightly passes, recall upkeep.
    MaintenanceCadence,
    /// Per-pass and per-job budgets, clamped to the owner's caps.
    WorkBudget,
    /// The system agents' wake cadence, quiet hours and trigger thresholds.
    WakeCadence,
    /// Which skill or recipe a knowledge job runs.
    KnowledgeRecipe,
}

impl EngineControlClass {
    /// Every class, in the order the grants list them.
    pub const ALL: [Self; 4] = [
        Self::MaintenanceCadence,
        Self::WorkBudget,
        Self::WakeCadence,
        Self::KnowledgeRecipe,
    ];

    /// The Steward verb a holder's grant names to change a knob of this
    /// class.
    #[must_use]
    pub const fn grant_verb(self) -> &'static str {
        match self {
            Self::MaintenanceCadence => grant_scope::ENGINE_CONTROLS_MAINTENANCE_CADENCE_VERB,
            Self::WorkBudget => grant_scope::ENGINE_CONTROLS_WORK_BUDGET_VERB,
            Self::WakeCadence => grant_scope::ENGINE_CONTROLS_WAKE_CADENCE_VERB,
            Self::KnowledgeRecipe => grant_scope::ENGINE_CONTROLS_KNOWLEDGE_RECIPE_VERB,
        }
    }
}

/// One change made through the engine-control door: the receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineControlChange {
    /// Who made it: the owner's PERSON or the holder's principal.
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    pub by: EntityId,
    /// Whether `by` acted as the owner rather than as a holder.
    pub owner: bool,
    pub class: EngineControlClass,
    /// The knob, by its stored name.
    pub knob: String,
    /// The value it was set to, as the knob's door renders it.
    pub value: String,
    pub changed_at: u64,
}
