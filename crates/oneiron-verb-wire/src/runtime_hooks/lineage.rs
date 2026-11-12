//! Moved from `crates/oneiron/src/runtime_hooks/lineage.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::borrow::Cow;
use std::collections::BTreeSet;

/// Why a check was raised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HookCheckReason {
    /// The same hook fired again inside its own causal chain.
    Cycle,
    /// The chain reached [`MAX_LINEAGE_DEPTH`].
    Depth,
}

impl HookCheckReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cycle => "cycle",
            Self::Depth => "depth",
        }
    }
}
