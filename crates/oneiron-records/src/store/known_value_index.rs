//! Moved from `crates/oneiron/src/store/known_value_index.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::store::known_history::KNOWN_TAG_BYTES;
use heed::RoTxn;
use heed::RwTxn;
pub(crate) use oneiron_store::known_value_index::forms::decodings;
pub(crate) use oneiron_store::known_value_index::forms::occurrences;
use std::cmp::Reverse;
use std::collections::BTreeSet;
use std::ops::Range;
use std::sync::Arc;
use zeroize::Zeroize;
use zeroize::Zeroizing;

/// How many bytes of a value's first window its tag keeps.
pub const TAG_BYTES: usize = KNOWN_TAG_BYTES;
