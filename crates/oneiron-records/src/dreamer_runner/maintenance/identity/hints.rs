//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/identity/hints.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// A hint row's key: the kind, the name's identity-hint digest and the
/// entity the answers named.
pub type HintKey = ([u8; 1], [u8; 32], EntityId);
