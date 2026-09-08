//! Per-database accessor seam for the session write-overlay (ARCH-0052, D2).
//!
//! Canonical accessors pass through to heed. A composed accessor keeps one
//! immutable overlay snapshot for its whole logical read while writes route to
//! the live transaction segment. Merged scans stream the base cursor and the
//! bounded overlay delta together, preserving page-borrowed base values.

mod accessors;
mod iters;
mod merge;

#[cfg(test)]
mod tests;

pub(crate) use self::accessors::{OverlayDb, OverlayStrDb};

// Only OverlayDb/OverlayStrDb are named outside this module
// (`crate::overlay_db::OverlayDb` in store/vault/pipeline callers); the merge
// engine and iterator enums are constructed and matched inside it, so they
// stay defined `pub(crate)` in their children and are imported directly via
// `super::merge::` / `super::iters::` with no re-export.

// The flat overlay_db.rs module used to provide these names to the sibling test
// module through `use super::*`: its own private crate/std import header, and
// every overlay-internal item the tests name bare. After the directory split
// the seam re-imports both so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::merge::*;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::session_overlay::{
    OverlayKeyspace, SessionOverlay, SnapshotMergePlan, SnapshotMergeRow,
};
#[cfg(test)]
use heed::Database;
#[cfg(test)]
use heed::types::Bytes;
#[cfg(test)]
use std::borrow::Cow;
#[cfg(test)]
use std::collections::BTreeSet;
#[cfg(test)]
use std::sync::Arc;
