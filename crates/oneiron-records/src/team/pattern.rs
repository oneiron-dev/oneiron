//! Moved from `crates/oneiron/src/team/pattern.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::team::pattern::PatternLaunchSpec;
pub use oneiron_verb_wire::team::pattern::TeamAxis;
pub use oneiron_verb_wire::team::pattern::TeamPattern;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// A skill bound to the pattern it teaches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatternSkill {
    pub skill: EntityId,
    pub pattern: TeamPattern,
    /// The pattern's default setting; a team may run it either way.
    pub default_axis: TeamAxis,
    /// The plain line: "for tasks like X, Y usually works".
    pub works_well_for: String,
    /// The task-type nodes the line names; each gets the weak prior.
    pub works_well_for_types: Vec<String>,
    pub at: u64,
}

/// A team's executor mix: its sorted, distinct model ids joined by `+`, or
/// their digest when the join would not fit a cell qualifier.
#[must_use]
pub fn model_mix(models: &[String]) -> String {
    let set: BTreeSet<&str> = models.iter().map(String::as_str).collect();
    let joined = set.into_iter().collect::<Vec<_>>().join("+");
    if joined.is_empty() {
        return "unknown".to_owned();
    }
    if joined.len() <= 256 {
        return joined;
    }
    format!(
        "mix#{}",
        &oneiron_contracts::entity_id::bytes_to_hex_lower(
            blake3::hash(joined.as_bytes()).as_bytes()
        )[..32]
    )
}
