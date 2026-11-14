//! Moved from `crates/oneiron/src/embed/repo_projection/derived/storage.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RoTxn;
use heed::RwTxn;
use serde::Deserialize;
use serde::Serialize;

/// The one schema a row is written in.
pub const REPO_DERIVED_INDEX_COPY_SCHEMA: u8 = 1;
