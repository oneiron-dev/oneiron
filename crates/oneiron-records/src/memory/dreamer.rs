//! Moved from `crates/oneiron/src/memory/dreamer.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::outbound::*;
use crate::memory::*;
pub use oneiron_verb_wire::memory::dreamer::DreamerAttemptRef;
pub use oneiron_verb_wire::memory::dreamer::DreamerAttemptView;
pub use oneiron_verb_wire::memory::dreamer::DreamerParkCauseView;
pub use oneiron_verb_wire::memory::dreamer::DreamerParkedAttemptView;
use serde::Deserialize;
use serde::Serialize;

/// One Dreamer consolidation enqueue (BRIDGE-03).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConsolidationAttemptInput {
    /// Consolidation scope: `micro` | `meso` | `macro`.
    pub scope: String,
    /// Opaque attempt input (stored as MessagePack in the queue payload).
    pub input: serde_json::Value,
    /// Optional run correlation id.
    pub run_id: Option<String>,
    /// Optional advisory dedupe key (cost coalescer, not a lock).
    pub dedupe_key: Option<String>,
    /// Unix seconds; `None` ⇒ now.
    pub now: Option<u64>,
}
