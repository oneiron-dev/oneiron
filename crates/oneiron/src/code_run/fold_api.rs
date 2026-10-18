//! Typed public calls on a credential's attached live run. The run's own
//! code-mode calls keep their implicit run and positional fold span.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunAttachRequest {
    pub run: String,
    #[serde(default)]
    pub rebind: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunAttached {
    pub live_run: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FoldMarkRequest {
    pub live_run: String,
    pub from: u64,
    pub through: u64,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FoldCompactRequest {
    pub live_run: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FoldUnfoldRequest {
    pub live_run: String,
    pub fold: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FoldRunRequest {
    pub live_run: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FoldHistoryRequest {
    pub live_run: String,
    /// First durable step to read, inclusive.
    pub from: u64,
    /// Maximum number of durable steps in this page; must be positive.
    pub limit: usize,
}

/// These verbs need the serving host's live-run registry, never an embedded
/// actor-only handle. No run id or stored attachment substitutes for its lease.
pub fn host_required<I, O>(
    _memory: &crate::memory::Memory<'_>,
    _input: &I,
) -> crate::memory::MemoryResult<O> {
    Err(crate::memory::MemoryError::new(
        crate::memory::MEMORY_CODE_LEASE_REQUIRED,
        "this call requires the serving host's attached live run",
        &["Use the typed HTTP or SDK call with the live_run returned by self.run.attach."],
    ))
}
