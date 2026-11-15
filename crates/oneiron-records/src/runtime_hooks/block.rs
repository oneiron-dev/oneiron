//! Moved from `crates/oneiron/src/runtime_hooks/block.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

pub const DEFAULT_TOKEN_CAP: u32 = 512;

/// How long a block lasts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookBlockLifetime {
    /// This many board deliveries.
    Deliveries(u32),
    /// Until a claim whose predicate matches this glob lands.
    UntilPredicate(String),
}

impl Default for HookBlockLifetime {
    fn default() -> Self {
        Self::Deliveries(1)
    }
}
