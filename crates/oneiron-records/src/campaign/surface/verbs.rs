//! Moved from `crates/oneiron/src/campaign/surface/verbs.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

/// One surface invocation: a verb name and its JSON body.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SurfaceCall {
    /// Verb name; must be one of [`CAMPAIGN_SELF_VERBS`] or
    /// [`CAMPAIGN_PROGRAM_VERBS`].
    pub verb: String,
    /// Verb-specific request body.
    pub body: Value,
}

/// One surface result, echoing the verb that produced it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SurfaceReply {
    /// Canonical verb name.
    pub verb: String,
    /// Verb-specific response body.
    pub body: Value,
}
