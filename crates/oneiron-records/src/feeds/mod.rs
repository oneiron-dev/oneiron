//! Moved from `crates/oneiron/src/feeds/mod.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use aes_gcm::Aes256Gcm;
use aes_gcm::Nonce;
use aes_gcm::aead::Aead;
use aes_gcm::aead::KeyInit;
use aes_gcm::aead::Payload;
use base64::Engine as _;
pub use oneiron_verb_wire::feeds::FeedEdge;
pub use oneiron_verb_wire::feeds::FeedEntryKind;
pub use oneiron_verb_wire::feeds::FeedGap;
pub use oneiron_verb_wire::feeds::FeedReadRequest;
pub use oneiron_verb_wire::feeds::FeedResyncFrom;
pub use oneiron_verb_wire::feeds::FeedStart;
pub use oneiron_verb_wire::feeds::FeedSubscriptionRequest;
use rand::RngCore;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// How long a cursor in a pruned source stays held without an acknowledgement, in seconds on
/// the vault's recording clock (lead call K, 10 Nov). Past it the prune no longer keeps the rows
/// it has not acknowledged, and its subscription's reads answer [`FeedRead::Gap`]. An ack
/// refreshes a cursor even when it moves nothing, so a reader that acks each page never lapses.
pub const FEED_RETENTION_SECS: u64 = 7 * 24 * 60 * 60;

/// Domain of the digest over the entries a wake scan's lane is shown.
pub const WAKE_SHOWN_DOMAIN: &[u8] = b"oneiron:feed-wake-shown:v1";
