//! Core half of `merge_queue::source_types`: its store-layer items live in `oneiron_store::merge_queue::source_types` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::merge_queue::source_types::*;

use super::MergeQueue;
use crate::EntityId;
use serde::{Deserialize, Serialize};

/// A queue an owner's checked init requests on: a native repository's own
/// root, or a served import's materialized source with the descriptor its
/// init work freezes.
pub(crate) struct PreparedQueueInit<'a> {
    pub(crate) queue: MergeQueue<'a>,
    pub(crate) source: Option<ServedQueueSource>,
}
