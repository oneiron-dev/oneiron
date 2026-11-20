//! Moved from `crates/oneiron/src/store/checkpoint_payload/instance.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Where one incarnation stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    /// The owner's current incarnation: a capture seals the owner under it.
    Active,
    /// Released by an ordinary delete: nothing new is sealed under it, and
    /// its leaf stays for the checkpoints holding it until their retention
    /// ends.
    Retained,
    /// Erased: its leaf is retired, and no capture seals the owner again.
    Erased,
}
