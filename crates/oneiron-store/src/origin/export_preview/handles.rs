//! A preview's identity and its byte handles (FIX 6869, G4 PR3, CALL O).
//!
//! The identity is recomputed from the pins and both complete pinned trees
//! on every call: no table, cache, token, key or expiry. It binds the
//! served name, the anchor, the origin and object store, the revision, the
//! full ref, the explicit expectation and both roots, then the sealed
//! revision's partition digest and the all-blob digest of each captured
//! side. No time, live ref, endpoint, checkout or caller enters it, so a
//! ref that moves rebinds nothing. A handle is an unsigned selector into
//! the changed paths of that recomputed preview.
use std::collections::BTreeMap;

use crate::code_tree_blob::CodeTreeBlob;
use crate::origin::export_preview::types::CodeExportByteHandle;
use crate::origin::export_preview::types::CodeExportFileBytes;
use crate::origin::export_preview::types::CodeExportPreview;
use crate::origin::export_preview::types::CodeExportSide;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::entity_id::bytes_to_hex_lower;

/// The one versioned identity domain (CALL O `preview_identity`).
pub const PREVIEW_IDENTITY_DOMAIN: &[u8] = b"oneiron:code-export-preview:v1";

pub fn part(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

pub fn optional(hasher: &mut blake3::Hasher, value: Option<&str>) {
    match value {
        None => {
            hasher.update(&[0]);
        }
        Some(value) => {
            hasher.update(&[1]);
            part(hasher, value.as_bytes());
        }
    }
}
