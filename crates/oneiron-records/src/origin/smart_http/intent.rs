//! Moved from `crates/oneiron/src/origin/smart_http/intent.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RoTxn;
use heed::RwTxn;
use serde::Deserialize;
use serde::Serialize;
use std::ops::Bound;
use std::path::Path;

/// Per-ref completion, independent of the backend's transport success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceivePackRefStatus {
    /// Publication and its attachments are durable.
    Published,
    /// The backend did not leave this ref at the proposed value.
    NotApplied,
    /// A previously observed effect was replaced; recovery never overwrites it.
    Superseded,
    /// An observed effect still needs publication or attachment recovery.
    Pending,
    /// The backend applied this ref's move, but a `Published` publication
    /// had already made that move, and this push needs objects it never
    /// certified. Terminal: the move is consumed, so no publication of it can
    /// certify more, and retrying it would only refuse again.
    Uncertified,
    /// The backend applied this ref's move, but an erase took the push's
    /// pusher or admitting host before it was published: recovery observed
    /// the move and publishes nothing under them (FIX 5022). Terminal.
    AppliedUnpublished,
}
