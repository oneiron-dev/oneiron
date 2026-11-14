//! Moved from `crates/oneiron/src/lens/mediation/mediation_quote.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Serialize;

/// Half-open offsets in Unicode scalar values, not UTF-8 bytes or UTF-16 units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LensQuoteRange {
    pub start: usize,
    pub end: usize,
}

/// What proving an issued quote found (FIX 9895; the drift answer is a call,
/// canon silent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LensQuoteProof {
    /// The reader may still read the message, and its cursors still select
    /// the text they quoted, wherever edits elsewhere moved them.
    Live,
    /// The reader may still read the message, but the quote no longer reads
    /// as issued: its text was edited or deleted, or a key lifted inside it
    /// since now reads to this reader as its handle.
    Drifted,
}
