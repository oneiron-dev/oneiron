//! Moved from `crates/oneiron/src/store/known_history.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RoTxn;
use heed::RwTxn;
use std::sync::Arc;
use std::sync::Weak;
use zeroize::Zeroize;
use zeroize::Zeroizing;

/// How many bytes of a value's first window an entry's tag keeps.
pub const KNOWN_TAG_BYTES: usize = 8;
