//! Moved from `crates/oneiron/src/memory/merge_queue_doors/checker_types.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::merge_queue::types::CheckPhase;
pub use oneiron_verb_wire::memory::merge_queue_doors::checker_types::MergeQueueCheckRequest;
pub use oneiron_verb_wire::memory::merge_queue_doors::checker_types::MergeQueueCheckStatusRequest;
pub use oneiron_verb_wire::memory::merge_queue_doors::checker_types::MergeQueueDiagnoseRequest;
pub use oneiron_verb_wire::memory::merge_queue_doors::checker_types::MergeQueueInitializeRequest;
pub use oneiron_verb_wire::memory::merge_queue_doors::checker_types::QueueCheckPhase;
use serde::Deserialize;
use serde::Serialize;

impl From<QueueCheckPhase> for CheckPhase {
    fn from(phase: QueueCheckPhase) -> Self {
        match phase {
            QueueCheckPhase::Fast => Self::Fast,
            QueueCheckPhase::Slow => Self::Slow,
        }
    }
}
