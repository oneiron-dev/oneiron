//! Moved from `crates/oneiron/src/recovery/canonical/source_audiences.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use loro::LoroDoc;
use loro::LoroValue;
use loro::ValueOrContainer;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// One carried binding or policy revision: its key and its bytes, as the
/// window map holds them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalSourceAudience {
    pub key: String,
    pub value: Vec<u8>,
}
