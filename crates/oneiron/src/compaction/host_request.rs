//! Core half of `compaction::host_request`: its store-layer items live in `oneiron_store::compaction::host_request` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::compaction::host_request::*;

use super::CompactionWindowMessage;
use crate::entity_id::EntityId;
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_verb_wire::compaction::host_request::HostCompactRequest;
