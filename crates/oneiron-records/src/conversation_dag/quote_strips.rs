//! Moved from `crates/oneiron/src/conversation_dag/quote_strips.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::conversation_dag::quote_strips::ReplyStripsRequest;
use serde::Deserialize;
use serde::Serialize;

/// How a strip's quote stands against its message now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStripStatus {
    /// The message is still at the pinned version.
    Live,
    /// The message changed since the pin; the quoted span still reads the same.
    Edited,
    /// The span no longer maps, or this vault holds no pinned text for it.
    Drifted,
    /// The message has been erased; no text is shown.
    Redacted,
}

/// One reply quoting a span of the group's message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteReplyStrip {
    /// The TURN the citing message is part of, or a native append's own.
    pub reply_turn: String,
    /// The MESSAGE that carries the quote (FIX 2028); absent for a native
    /// append, which its TURN cites.
    pub reply_message: Option<String>,
    /// The anchor the strip resolves through: `<message>:<citation>` names a
    /// document citation pin, `<message>#<body hash>` an atomic message's
    /// immutable text by its BLAKE3 hash.
    pub pin_ref: String,
    /// The quoted text at the pinned version; `None` when redacted or not held.
    pub excerpt: Option<String>,
    pub status: QuoteStripStatus,
}

/// The strips quoting one MESSAGE, in chronological reply order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteReplyGroup {
    pub message_ref: String,
    pub strips: Vec<QuoteReplyStrip>,
}

/// Groups in order of their first strip on the page. A group may continue
/// on the next page under the same `message_ref`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyStripsPage {
    pub groups: Vec<QuoteReplyGroup>,
    /// The last strip's citer, the next page's `after`; `None` means the
    /// thread has no further strip.
    pub next_after: Option<String>,
}
