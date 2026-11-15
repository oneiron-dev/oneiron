//! Moved from `crates/oneiron/src/world_keys/state.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// Whether a lost machine would take the world with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorldRecoveryState {
    /// The world reads everywhere: the vault's own recovery covers it.
    NotPrivate,
    /// The world's current key has a wrap to this install's pinned root.
    Covered,
    /// A private world whose current key this install's kit cannot open: no pinned
    /// root, no key yet, or no wrap to the pinned root.
    NoKit,
}

/// Whether the pad the world's current key needs is on this machine (FIX
/// 348), apart from its kit coverage ([`WorldRecoveryState`]): a covered world
/// whose pad never arrived here still opens nowhere here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorldPadAvailability {
    /// The current key's pad is here: in its row, or in key custody.
    Present,
    /// The world has a current key and its pad has not reached this machine.
    Missing,
    /// A private world with no key yet: no pad is owed.
    NoCurrentKey,
    /// The world's keys were destroyed here with the world.
    Destroyed,
    /// The world reads everywhere and has no key: none is needed.
    NotRequired,
    /// The pad's state could not be read here.
    Unavailable,
}
