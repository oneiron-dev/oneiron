//! Bounded credential scanning across transport and content-defined boundaries.

use oneiron_base::error::Error;
use oneiron_base::error::GateError;
use oneiron_base::error::Result;

/// The longest key a provider rule reads from where it starts.
pub const KEY_MAX: usize = 128;

/// How much of a run of one repeated character a seam keeps: as much as the
/// longest token any text rule measures (a stream keeps 128 bytes of one too),
/// so the run reads as it did.
pub const RUN_KEEP: usize = 128;

/// How much of a run of whitespace a seam keeps: its first two characters,
/// which every text rule reads as it reads the whole run (the assignment
/// rule's `export ` prefix strips only before a run of one space).
pub const SPACE_KEEP: usize = 2;

/// The part of a long segment a seam's tail holds.
#[derive(Clone, Copy)]
pub enum Part {
    /// The key, past its first [`PART_KEEP`].
    Key,
    /// The value's start, until it holds [`PART_KEEP`].
    Value,
    /// What follows the value's start; `true` once some of it was dropped.
    Rest(bool),
}

pub fn segment_break(byte: u8) -> bool {
    matches!(byte, b'\n' | b'\r' | b',' | b';' | b'{' | b'}')
}

pub fn advance(pattern: &[u8], matched: usize, byte: u8) -> usize {
    if matched == 0 {
        return usize::from(byte == pattern[0]);
    }
    if pattern[matched] == byte {
        return matched + 1;
    }
    // Tiny patterns: recomputing the proper prefix is bounded by eleven bytes.
    // This handles six-or-more leading dashes without missing a BEGIN marker.
    let mut candidate = [0u8; 12];
    candidate[..matched].copy_from_slice(&pattern[..matched]);
    candidate[matched] = byte;
    let candidate = &candidate[..matched + 1];
    (1..=pattern.len().min(candidate.len()))
        .rev()
        .find(|&n| candidate.ends_with(&pattern[..n]))
        .unwrap_or(0)
}

pub fn denied(reason: &'static str) -> Error {
    Error::Gate(GateError::GateWriteRejected {
        outcome: "deny",
        reason_codes: vec!["gate.secret_scan.detected", reason],
    })
}
