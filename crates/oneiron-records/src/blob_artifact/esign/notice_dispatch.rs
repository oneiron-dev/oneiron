//! Moved from `crates/oneiron/src/blob_artifact/esign/notice_dispatch.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::blob_artifact::esign::seal::SealedItem;
use serde::Deserialize;
use serde::Serialize;

/// Frozen transition intent, staged with its triggering claim. The cloud edge
/// receives the sealed artifact refs only after the email send gate allows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EsignNotice {
    pub document: String,
    pub recipient: String,
    pub email: String,
    pub transition: String,
    pub dispatch_ref: Option<String>,
    pub sealed_items: Vec<SealedItem>,
    pub principal: Option<String>,
    pub event_ref: Option<String>,
    pub generation: Option<String>,
}
