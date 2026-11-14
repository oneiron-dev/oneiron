//! Moved from `crates/oneiron/src/workspace_roster/house_link.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// What one receipt records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HouseLinkAct {
    /// The house took its role in the org.
    Bind,
    /// The house left it.
    Unbind,
}

impl HouseLinkAct {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Bind => "bind",
            Self::Unbind => "unbind",
        }
    }
}
