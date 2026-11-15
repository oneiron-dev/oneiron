//! Moved from `crates/oneiron/src/llm/run_admission/admission/origin.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Serialize;

/// What a bound run's calls serve, as the engine stamped it before the run
/// began (FIX 4453): the agent, its free-time cycle and item, the label every
/// call carries and the spend scope its spend lands on. Fixed for the run's
/// life; never read from a prompt or from the run's name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunAttribution {
    pub agent: oneiron_contracts::entity_id::EntityId,
    pub cycle: oneiron_contracts::entity_id::EntityId,
    pub item: oneiron_contracts::entity_id::EntityId,
    pub purpose: oneiron_model::llm::CallPurpose,
    pub spend_scope: String,
}
