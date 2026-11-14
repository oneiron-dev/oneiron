//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/claim_source_recheck.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::time::Duration;
use std::time::Instant;

/// The maintenance facet the re-check of one provider-deleted, kept message
/// rides.
pub const CLAIM_SOURCE_RECHECK_FACET: &str = "dreamer.claim_source_recheck";

/// The payload key the declaration rides under.
pub const DECLARATION_KEY: &str = "declaration";
