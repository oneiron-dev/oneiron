//! Git-LFS wire DTOs and batch types.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// The two batch operations Git-LFS defines.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(super) enum LfsBatchOperation {
    Upload,
    Download,
}

/// One `(oid, size)` pair a batch asks about.
#[derive(Clone, Debug, Deserialize)]
pub(super) struct LfsBatchObject {
    pub(super) oid: String,
    pub(super) size: u64,
}

/// A Git-LFS batch request.
#[derive(Clone, Debug, Deserialize)]
pub(super) struct LfsBatchRequest {
    pub(super) operation: LfsBatchOperation,
    /// Absent means "the client did not narrow the transfer set", which stock
    /// clients spell by omitting the field. A non-empty set that does not name
    /// `basic` is a refusal: this origin serves one adapter.
    #[serde(default)]
    pub(super) transfers: Vec<String>,
    pub(super) objects: Vec<LfsBatchObject>,
}

#[derive(Debug, Serialize)]
pub(super) struct LfsAction {
    pub(super) href: String,
}

#[derive(Debug, Serialize)]
pub(super) struct LfsObjectError {
    pub(super) code: u16,
    pub(super) message: &'static str,
}

#[derive(Debug, Serialize)]
pub(super) struct LfsBatchResponseObject {
    pub(super) oid: String,
    pub(super) size: u64,
    pub(super) authenticated: bool,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) actions: BTreeMap<&'static str, LfsAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) error: Option<LfsObjectError>,
}

#[derive(Debug, Serialize)]
pub(super) struct LfsBatchResponse {
    pub(super) transfer: &'static str,
    pub(super) objects: Vec<LfsBatchResponseObject>,
}

/// What an accepted upload made durable.
#[derive(Debug, Serialize)]
pub(super) struct LfsUploadResponse {
    pub(super) oid: String,
    pub(super) size: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct LfsVerifyRequest {
    pub(super) oid: String,
    pub(super) size: u64,
}

#[derive(Debug, Serialize)]
pub(super) struct LfsVerifyResponse {
    pub(super) oid: String,
    pub(super) size: u64,
    pub(super) ok: bool,
}
