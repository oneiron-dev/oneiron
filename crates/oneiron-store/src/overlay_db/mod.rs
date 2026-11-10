//! Per-database accessor seam for the session write-overlay (ARCH-0052, D2).
//!
//! Canonical accessors pass through to heed. A composed accessor keeps one
//! immutable overlay snapshot for its whole logical read while writes route to
//! the live transaction segment. Merged scans stream the base cursor and the
//! bounded overlay delta together, preserving page-borrowed base values.

pub mod accessors;
pub mod iters;
pub mod merge;

#[cfg(test)]
mod tests;

pub use self::accessors::{OverlayDb, OverlayStrDb};

// Only OverlayDb/OverlayStrDb are named outside this module
// (`oneiron::overlay_db::OverlayDb` in store/vault/pipeline callers); the merge
// engine and iterator enums are constructed and matched inside it. Their
// modules are public because the accessors' public signatures name them.
