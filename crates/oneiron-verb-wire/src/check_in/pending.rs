//! Moved from `crates/oneiron/src/check_in/pending.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// Whether a holder is a person or an agent. Only a person rung waits; an
/// agent answers at once or passes up (ARCH-0082 #waits, ruling R2).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HolderKind {
    Person,
    Agent,
}
