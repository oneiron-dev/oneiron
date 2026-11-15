//! Moved from `crates/oneiron/src/blob_artifact/esign/notice_door.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The signing document whose staged notices the caller sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignNoticesDispatchRequest {
    /// The artifact the signing overlay lives on.
    pub document_ref: String,
}
