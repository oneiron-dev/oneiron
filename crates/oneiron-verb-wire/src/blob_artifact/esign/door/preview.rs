//! Moved from `crates/oneiron/src/blob_artifact/esign/door/preview.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::blob_artifact::esign::render::presentation::FieldLayout;
use crate::blob_artifact::esign::render::presentation::PageGeometry;
use serde::Deserialize;
use serde::Serialize;

/// One recipient ceremony item to preview under its signing capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignSigningPreviewRequest {
    pub token: String,
    pub item: usize,
}

/// The pinned item's page geometry and fields, as `POST /sign/preview` lays them out.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignSigningPreviewView {
    pub pages: Vec<PageGeometry>,
    pub fields: Vec<FieldLayout>,
}
