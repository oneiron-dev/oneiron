//! Moved from `crates/oneiron/src/connector_key/slate_draft.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// A recommendation needs this many connectors' rulings, and a strict
/// majority of them, before it pre-fills a tighter setting.
pub const PAST_RULING_MIN_CONNECTORS: u32 = 2;
