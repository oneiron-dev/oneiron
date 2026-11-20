//! Moved from `crates/oneiron/src/feeds/mod.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::feeds::FeedEdge;
pub use oneiron_verb_wire::feeds::FeedEntryKind;
pub use oneiron_verb_wire::feeds::FeedGap;
pub use oneiron_verb_wire::feeds::FeedReadRequest;
pub use oneiron_verb_wire::feeds::FeedResyncFrom;
pub use oneiron_verb_wire::feeds::FeedStart;
pub use oneiron_verb_wire::feeds::FeedSubscriptionRequest;

/// How long a cursor in a pruned source stays held without an acknowledgement, in seconds on
/// the vault's recording clock (lead call K, 10 Nov). Past it the prune no longer keeps the rows
/// it has not acknowledged, and its subscription's reads answer [`FeedRead::Gap`]. An ack
/// refreshes a cursor even when it moves nothing, so a reader that acks each page never lapses.
pub const FEED_RETENTION_SECS: u64 = 7 * 24 * 60 * 60;

/// Domain of the digest over the entries a wake scan's lane is shown.
pub const WAKE_SHOWN_DOMAIN: &[u8] = b"oneiron:feed-wake-shown:v1";
