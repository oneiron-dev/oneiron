//! An unflagged window's sieve audit as a weave report serves it (OF-498f):
//! refs as hex, offsets as bytes, kinds by name.

use serde::{Deserialize, Serialize};

/// What the expensive path found in a source range the cheap sieve flagged
/// nothing in: the range as refs and UTF-8 byte offsets, and each span it
/// found there. `discovered: []` is a negative label: the audit agrees.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeaveSieveFindingView {
    /// What the rules expected of the range: `unflagged`.
    pub expectation: String,
    pub window_ref: String,
    pub turn_ref: String,
    pub source_ref: String,
    pub start: u64,
    pub end: u64,
    pub discovered: Vec<WeaveSieveDiscoveryView>,
    pub agrees: bool,
    pub audited_at: u64,
}

/// One span the expensive path found in a window, by its byte offsets into
/// the window's source text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeaveSieveDiscoveryView {
    pub start: u64,
    pub end: u64,
    pub kind: String,
    pub confidence: u8,
}
