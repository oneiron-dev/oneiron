//! Moved from `crates/oneiron/src/sync/note.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use loro::LoroDoc;
use loro::LoroValue;
use loro::ValueOrContainer;
pub(crate) use oneiron_store::deletion::window_document_format::is_native;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// The explainer a bundle that lost a member keeps, as the erase leaves it:
/// it can quote what left.
pub const REDACTED: &str = "redacted";
