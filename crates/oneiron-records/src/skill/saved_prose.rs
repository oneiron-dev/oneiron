//! Moved from `crates/oneiron/src/skill/saved_prose.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Serialize;
use std::path::Path;

/// The extension of a source file whose text is prose; any other file is a
/// script or data and cites nothing.
pub const PROSE_EXTENSION: &str = "md";
