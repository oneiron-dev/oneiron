//! Moved from `crates/oneiron/src/gate/consult_fanout_values.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Optional per-peer rate evidence window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsultFanOutRate {
    pub window_secs: u64,
    pub spike_at: u32,
}

/// Per-actor create quota within one node-local time window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskCreateRateLimit {
    pub limit: usize,
    pub window_seconds: u64,
}

impl Default for TaskCreateRateLimit {
    fn default() -> Self {
        Self {
            limit: 10,
            window_seconds: 60,
        }
    }
}

/// Policy path supplied by an authenticated host for a frozen consult plan.
/// The vault level is implicit; each additional level names its parent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsultFanOutScope {
    pub project_ref: Option<String>,
    pub subproject_ref: Option<String>,
    pub thread_ref: Option<String>,
}
