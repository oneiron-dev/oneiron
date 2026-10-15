//! The no-kit warning (ruling fix 10): a typed state. Clients word it; the engine
//! stores no sentence.

use super::RecoveryRootId;

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

/// - `private`: the world's effective read is not everywhere.
/// - `pinned`: this install's root (R1). A root this install does not pin never
///   counts.
/// - `current_key_roots`: the roots the world's current key is wrapped to.
#[must_use]
pub fn recovery_state(
    private: bool,
    pinned: Option<RecoveryRootId>,
    current_key_roots: &[RecoveryRootId],
) -> WorldRecoveryState {
    match (private, pinned) {
        (false, _) => WorldRecoveryState::NotPrivate,
        (true, Some(root)) if current_key_roots.contains(&root) => WorldRecoveryState::Covered,
        (true, _) => WorldRecoveryState::NoKit,
    }
}
