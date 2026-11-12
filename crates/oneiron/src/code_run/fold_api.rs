//! Typed public calls on a credential's attached live run. The run's own
//! code-mode calls keep their implicit run and positional fold span.

use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_verb_wire::code_run::fold_api::{
    FoldCompactRequest, FoldHistoryRequest, FoldMarkRequest, FoldRunRequest, FoldUnfoldRequest,
    RunAttachRequest, RunAttached,
};

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
