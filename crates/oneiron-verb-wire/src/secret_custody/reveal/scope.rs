//! Moved from `crates/oneiron/src/secret_custody/reveal/scope.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::secret_custody::reveal::types::RevealGrantScope;

impl RevealGrantScope {
    /// Every scope, the narrowest first: the order a reveal's cover is tried
    /// and the owner's choices are listed.
    pub const ALL: [Self; 4] = [Self::Run, Self::Task, Self::Project, Self::EveryProject];
}
