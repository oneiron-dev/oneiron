//! Moved from `crates/oneiron/src/secret_custody/cloud_registration/mod.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Where one slot's binding stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudRegistrationPhase {
    /// Linked and usable.
    Linked,
    /// A refresh is reserved: its token may be spent. Never sent again.
    InFlight,
    /// The family is lost or uncertain: the owner logs in again.
    NeedsLogin,
    /// The owner logged out: the binding is stopped, the slot kept for the
    /// owner's erase.
    LoggedOut,
    /// A later login replaced it: kept for the owner's erase.
    Replaced,
    /// The owner's erase took it: its record, name and value are gone, and
    /// the row stays until every key of it is retired, so a later erase
    /// still reports it.
    Erasing,
}

impl CloudRegistrationPhase {
    /// Whether this is the owner's current link for its issuer.
    #[must_use]
    pub const fn current(self) -> bool {
        matches!(self, Self::Linked | Self::InFlight | Self::NeedsLogin)
    }
}
