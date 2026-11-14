//! Moved from `crates/oneiron/src/task_verb/fanout_launch.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub(super) use crate::task_verb::fanout_launch::scrub::FanoutRecipientScrub;
pub(super) use crate::task_verb::fanout_launch::scrub::scrub_pathology_for;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::task_verb::fanout_launch::FanoutCheckChoice;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// The plan target of a wave task with no assignee: the default realization.
pub const WAVE_DEFAULT_REALIZATION: &str = "tasks.realize";

pub fn check_row_ref(kind: &str, launch_ref: EntityId) -> String {
    format!("fanout_check_row:{kind}:{}", launch_ref.to_hex())
}
pub mod scrub;
