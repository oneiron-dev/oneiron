//! Moved from `crates/oneiron/src/typed_body/carried_fork.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RoTxn;
use heed::RwTxn;
use loro::Frontiers;
use loro::LoroDoc;
use loro::VersionVector;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// Whether version `a` holds every operation version `b` does. A version
/// not recorded (empty) holds none and is held by none, but by another not
/// recorded.
pub fn version_covers(a: &[u8], b: &[u8]) -> bool {
    if a.is_empty() || b.is_empty() {
        return a.is_empty() && b.is_empty();
    }
    VersionVector::decode(b).is_ok_and(|b| version_covers_vv(a, &b))
}

/// Whether version `a`, encoded, holds every operation `b` does. A version
/// not recorded holds none.
pub fn version_covers_vv(a: &[u8], b: &VersionVector) -> bool {
    !a.is_empty() && VersionVector::decode(a).is_ok_and(|a| a.includes_vv(b))
}
