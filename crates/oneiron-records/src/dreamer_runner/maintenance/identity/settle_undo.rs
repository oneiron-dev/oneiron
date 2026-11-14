//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/identity/settle_undo.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// The hint row's name in a revert's settings list.
pub const HINT_ROW: &str = "identity_hint";
