//! Moved from `crates/oneiron/src/entity_doc/succession.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use loro::LoroDoc;
use loro::VersionVector;
use serde::Deserialize;
use serde::Serialize;

/// The meta key a rebuilt document's proof sits under.
pub const SUCCEEDS: &str = "entity_doc_succeeds";
