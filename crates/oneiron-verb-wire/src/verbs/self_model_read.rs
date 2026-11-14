//! Moved from `crates/oneiron/src/verbs/self_model_read.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::revision_ref::RevisionRef;
use serde::Deserialize;
use serde::Serialize;

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
