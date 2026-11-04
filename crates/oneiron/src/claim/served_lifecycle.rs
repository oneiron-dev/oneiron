//! Lifecycle version exposed by a scoped claim read.

use serde::{Deserialize, Serialize};

/// Lifecycle version served to a caller. The claim lifecycle chain is the
/// version; this rider does not introduce a second revision counter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServedLifecycle {
    Active,
    Superseded(String),
    Retracted,
    Installed(String),
}
