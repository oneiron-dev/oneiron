//! Moved from `crates/oneiron/src/secret_custody/reveal/types.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::fmt;
use zeroize::Zeroizing;

/// The reach of the owner's standing answer to one reveal (FIX 2354): the
/// grant "approve and stop asking" writes covers this connection × this
/// class × this reach. Each reach is its own grant; none is a wildcard.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RevealGrantScope {
    /// The project the reveal was asked in, until revoked: the default.
    #[default]
    Project,
    /// Every project, until revoked.
    EveryProject,
    /// The task the asking run works, until revoked.
    Task,
    /// The one run (the leased try) that asked; another run asks again.
    Run,
}

impl RevealGrantScope {
    /// The pinned scope word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::EveryProject => "every_project",
            Self::Task => "task",
            Self::Run => "run",
        }
    }
}
