//! Moved from `crates/oneiron/src/failure_signals/code_fix/queue.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;

/// One record a batch carries: its public id and the worlds its failure
/// touched (local only, never sent).
pub type CodeFixShare = (String, Vec<EntityId>);
