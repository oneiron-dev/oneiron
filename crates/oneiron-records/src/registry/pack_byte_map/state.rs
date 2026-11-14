//! Moved from `crates/oneiron/src/registry/pack_byte_map/state.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use std::collections::BTreeSet;

// The final local pack slot doubles as the shared subtype carrier on overflow.
// This is an allocation policy, not a globally identified entity kind.
pub const SHARED_HANDLE: u8 = 247;
