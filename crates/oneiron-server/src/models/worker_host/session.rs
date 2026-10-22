//! Exact conversation sessions on this process's managed EXL3 workers
//! (DESIGN-V2 §3.2, R2), host side: the coordinator.
//!
//! A turn whose call carries a segment manifest naming its conversation,
//! sent to a worker whose hello advertises the session ops, runs on a
//! session ([`open_turn`]): the session for its key is created or reused, a
//! working branch is forked at the frontier the worker verified for the
//! turn's canonical path, and the turn generates on that branch, its whole
//! board rendered and admitted fresh. Any other turn, and a turn whose
//! session op fails, runs exactly as before. The board is never kept: only
//! the authorized canonical prefix and the selected log are.
//!
//! Once the reply is committed to the conversation ([`reply_committed`]),
//! the successor is staged on its own task: the canonical path with the new
//! messages is appended and verified, only its new suffix is computed
//! against the retained prefix (never the working branch's state, which
//! attended the board), what it was admitted under is rechecked through the
//! turn's [`CheckpointAuthority`], and it is published by compare-and-swap
//! on the base checkpoint's token digest and HEAD. A downgrade, a withdrawn
//! source or a stale HEAD rejects it and drops the session. A next turn
//! never waits for it: it forks from what is published, and the worker
//! computes the missing suffix in its working branch.
//!
//! The registry lives in memory, per worker incarnation: it is never
//! persisted or restored as truth, and a new epoch, an eviction or lost
//! residency drops a session. A drop waits for the worker's release before
//! its entry's bytes leave the accounting; the worker's cheap stats on each
//! answer move the device ledger. Receipts claim nothing from metadata: the
//! native `final`'s passes say what was read and what was computed.
#[cfg(unix)]
mod commit;
#[cfg(unix)]
mod policy;
#[cfg(unix)]
mod registry;
#[cfg(unix)]
mod turn;

use std::sync::Arc;

use oneiron::EntityId;
use oneiron::llm::{SegmentManifest, SessionInvalidation};

#[cfg(unix)]
pub(super) use registry::Registry;
#[cfg(unix)]
pub(in crate::models) use turn::open_turn;

/// What a turn's canonical path was admitted under, held by the turn and
/// rechecked before its successor is published.
pub(crate) trait CheckpointAuthority: Send + Sync {
    /// Whether the credential, the read scope and the disclosure ceiling the
    /// path was admitted under hold now, and every source it was read from
    /// (`commit`'s reply among them) still reads. Runs off the runtime.
    fn recheck(&self, commit: &ReplyCommit) -> AuthorityVerdict;
}

/// A recheck's outcome.
pub(crate) enum AuthorityVerdict {
    Holds,
    Rejects(SessionInvalidation),
}

/// A reply committed to the conversation: the HEAD it lands at, its
/// MESSAGE, and its text as it was saved.
pub(crate) struct ReplyCommit {
    pub(crate) head: EntityId,
    pub(crate) message: EntityId,
    pub(crate) text: String,
}

/// Stages and publishes the successor of the turn `manifest` described,
/// once its reply is committed, if that turn ran on a session. Returns at
/// once; nothing waits for it, and a turn that ran on none leaves nothing
/// to do.
pub(crate) fn reply_committed(
    manifest: &SegmentManifest,
    commit: ReplyCommit,
    authority: Arc<dyn CheckpointAuthority>,
) {
    #[cfg(unix)]
    commit::reply_committed(manifest, commit, authority);
    #[cfg(not(unix))]
    let _ = (manifest, commit, authority);
}
