//! Moved from `crates/oneiron/src/context_board/stream/events.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::context_board::stream::frames::StreamConnectionId;
pub use oneiron_verb_wire::context_board::stream::events::SubscriptionScope;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionReceipt {
    pub connection: StreamConnectionId,
    pub active: BTreeSet<SubscriptionScope>,
}
