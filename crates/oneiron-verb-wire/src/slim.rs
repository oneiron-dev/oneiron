//! Moved from `crates/oneiron/src/slim.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::heap_drop::HeapDropReport;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::atomic::AtomicU64;
use std::time::Instant;

/// Why the host asked for a shed. Observability only — the engine never
/// compares it, or `waited_secs`, against a policy constant.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ShedCause {
    LongOutboundWait,
    MemoryPressure,
}

/// Why a shed was refused. Every variant is defined unconditionally so the
/// public outcome shape does not vary by build feature.
#[derive(
    Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ShedBlocker {
    NoPendingOutboundStep,
    MultiplePendingOutboundSteps {
        count: usize,
    },
    SyncWindowBusy {
        window_key: String,
        outstanding_handles: usize,
    },
    AlreadySlimForDifferentStep,
}
pub mod public;
