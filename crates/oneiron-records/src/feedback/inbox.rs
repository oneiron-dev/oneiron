//! Moved from `crates/oneiron/src/feedback/inbox.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// How a note reached the inbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackInboxVia {
    /// A plain GET link carrying the text in its query.
    Link,
    /// A POST carrying the text as its body.
    Post,
    /// A POST carrying a v1 feedback bundle a vault sent.
    Bundle,
    /// A POST carrying a content-free issue signature a vault's Coach sent
    /// (`oneiron.issue_signature.v1`), read back typed; its text is the exact
    /// canonical body.
    Signature,
}
