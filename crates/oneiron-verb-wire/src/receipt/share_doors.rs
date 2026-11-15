//! Moved from `crates/oneiron/src/receipt/share_doors.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// One pinned citation of a shared brief, as the viewer may see it. A
/// citation the share or the viewer's own read withholds is `redacted`, and
/// then says nothing of its lifecycle, confidence or quote.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedBriefCitation {
    /// The cited CLAIM, as 32 hex.
    pub claim_ref: String,
    pub stale: bool,
    pub drifted: bool,
    pub redacted: bool,
    pub confidence: Option<f32>,
    /// `active`, `superseded` or `retracted`; none when redacted.
    pub lifecycle: Option<String>,
    pub quote: Option<String>,
}
