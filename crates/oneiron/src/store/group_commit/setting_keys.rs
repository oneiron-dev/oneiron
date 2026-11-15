//! The vault writer's group commit learned knobs (ARCH-0003 #learning-settings; Setting stage 3): catalogue
//! keys a fit learns under the owner's seeds and pins. The crate's build script places each row in the
//! setting catalogue.

use crate::setting::{Kind, LEARNED_SCOPES};

crate::setting::setting_keys! {
    /// How long a group commit at the vault's single writer may wait, with its
    /// queue empty, for writes already on their way, in milliseconds counted from
    /// when the group opened (ARCH-0019 group-commit invariant, OF-536). It bounds
    /// that idle wait only: writes already queued join regardless, up to
    /// [`GROUP_COMMIT_MAX_WRITES`], until one that runs alone (a host's callback)
    /// or holds a session-overlay segment closes the group. A group never waits
    /// when no write is on its way, so a lone writer pays nothing; zero closes
    /// every group as soon as its queue is empty.
    pub GROUP_COMMIT_WINDOW_MS: f64 = "group_commit.window_ms" {
        kind: Kind::new(|| 2.0).learned(0.0, 50.0),
        scopes: &LEARNED_SCOPES,
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };

    /// The most logical writes one group commit carries before it closes. One
    /// gives every logical write its own transaction and fsync.
    pub GROUP_COMMIT_MAX_WRITES: f64 = "group_commit.max_writes" {
        kind: Kind::new(|| 256.0).learned(1.0, 4096.0),
        scopes: &LEARNED_SCOPES,
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };
}
