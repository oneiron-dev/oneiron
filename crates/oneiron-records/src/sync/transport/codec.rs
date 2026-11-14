//! Moved from `crates/oneiron/src/sync/transport/codec.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Serialize;
use std::collections::VecDeque;
use std::io::Read;
use std::pin::Pin;
use std::sync::LazyLock;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;
use std::task::ready;

/// One inner tag's counts. `tag` 63 also holds every higher tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct TagBytesRow {
    pub tag: u8,
    pub out_frames: u64,
    pub out_raw: u64,
    pub out_sent: u64,
    pub in_frames: u64,
    pub in_raw: u64,
    pub in_received: u64,
}
