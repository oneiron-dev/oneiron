//! `self.memory.self_model`: the caller's own self-model SUMMARY text with its live revision, or why it is absent.

use serde::{Deserialize, Serialize};

use crate::claim::ScopedReadResult;
use crate::memory::{Memory, MemoryResult};
use crate::scope_summary::SummaryReadRequest;
use crate::vault::RevisionRef;

/// `self.memory.self_model`'s answer: the existing `SelfModelRead` on the wire.
/// `Read` carries the SUMMARY's current words and the LIVE revision they were read at in the serving
/// snapshot; `Absent` names why it is not worn: `unreadable`, `stale`, `not_self_model` or `not_own`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SelfModelReadView {
    /// Its current words, masked as the reader reads secrets, and the live revision of the SUMMARY.
    Read {
        text: String,
        revision: Option<RevisionRef>,
    },
    /// Why it is not worn.
    Absent { why: String },
}

impl From<crate::scope_summary::SelfModelRead> for SelfModelReadView {
    fn from(read: crate::scope_summary::SelfModelRead) -> Self {
        match read {
            crate::scope_summary::SelfModelRead::Read { text, revision } => {
                Self::Read { text, revision }
            }
            crate::scope_summary::SelfModelRead::Absent(why) => Self::Absent {
                why: why.to_owned(),
            },
        }
    }
}

/// `self.memory.self_model` on a handle: reads `input.summary_ref` as the handle's actor's own
/// self-model, on its own scoped SUMMARY lane at `Recorded`, with the existing purpose, ownership
/// and staleness checks. `input.spans` is ignored: the read returns the full text, not spans.
/// An agent needs its live owner Grant listing `self.memory.self_model`, checked in the serving
/// snapshot; a person stands by liveness. FORBIDDEN names a caller with no live Grant. The
/// serving receipt travels with the value.
pub fn self_memory_self_model_embedded(
    memory: &Memory<'_>,
    input: SummaryReadRequest,
) -> MemoryResult<ScopedReadResult<SelfModelReadView>> {
    let summary =
        crate::vault::entity_refs::resolve_entity_ref(memory.vault(), &input.summary_ref)?;
    let read = memory.read_self_model_summary_receipted(&summary)?;
    Ok(read.map(SelfModelReadView::from))
}
