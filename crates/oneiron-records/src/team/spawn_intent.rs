//! Moved from `crates/oneiron/src/team/spawn_intent.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::team::task_exposure::TaskExposure;
pub use oneiron_verb_wire::team::spawn_intent::SpawnErasure;
pub use oneiron_verb_wire::team::spawn_intent::SpawnPhase;
use serde::Deserialize;
use serde::Serialize;

/// Domain of a frozen pattern pack's body hash.
pub const PACK_BODY_CONTEXT: &str = "oneiron spawn frozen pattern pack body v1";

/// Where a leader run's task held the frozen pack's SKILL.md, as an erased
/// intent keeps it (FIX 11787): the byte span, separator included, and the
/// hash of those bytes, with no skill, revision or text. A continuation
/// claimed after the erase reads no pack, and its task, its source run's
/// fork, still holds the text there; the span lets it lay a tombstone over
/// exactly those bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErasedPackSpan {
    pub start: usize,
    pub end: usize,
    /// BLAKE3 of the task bytes in `start..end`.
    pub content_hash: [u8; 32],
}

impl From<&TaskExposure> for ErasedPackSpan {
    fn from(exposure: &TaskExposure) -> Self {
        Self {
            start: exposure.start,
            end: exposure.end,
            content_hash: exposure.content_hash,
        }
    }
}
