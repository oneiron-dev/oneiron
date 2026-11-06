//! Core half of `store::known_value_index::rolling`: its store-layer items live in `oneiron_store::known_value_index::rolling` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::known_value_index::rolling::*;

use zeroize::Zeroize;

// A scan's hits keep one bit per window length, and there are at most
// `TAG_WINDOW` of them.
const _: () = assert!(super::TAG_WINDOW <= 32);
