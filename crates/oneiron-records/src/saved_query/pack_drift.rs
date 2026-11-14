//! Moved from `crates/oneiron/src/saved_query/pack_drift.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// A pack version move that touches predicates a query reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackDrift {
    /// Pack the definition was written against.
    pub from_pack_id: String,
    /// Version the definition was written against.
    pub from_version: String,
    /// Pack now installed.
    pub to_pack_id: String,
    /// Version now installed.
    pub to_version: String,
    /// Predicates whose meaning or spelling moved.
    pub affected_predicates: Vec<String>,
}
