//! Scheduling class carried by stored extraction markers.

use serde::{Deserialize, Serialize};

/// The scheduling class of one extraction call. It orders calls in a host's
/// dispatcher and is never part of the input, its digest or a marker's dedupe
/// key: the tagger never sees it. A tagging marker carries one, and the
/// reconciler passes each marker's effective class (FIX 6755).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractionWork {
    /// A call someone waits on: the explicit tag door, and a marker a chat or
    /// voice witness commit owes. It goes before every waiting bulk call, and
    /// a running call is never pre-empted for it.
    Live,
    /// Everything else: a marker an import, a host executor, a promotion, a
    /// publication or a recovery owes, and feedback redaction.
    Bulk,
}
