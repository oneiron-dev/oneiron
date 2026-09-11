//! Edit manifest and warnings.

use super::{AnchorEffect, EditOp, OfficeFormat};
use crate::error::{ArtifactError, Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Serialization version for [`EditManifest`]. Bump on any incompatible change
/// to the op vocabulary or manifest shape.
pub const EDIT_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Whether the pipeline ran in full-edit or minimal-mutation mode. Heavy
/// pivot/chart/macro workbooks force [`MutationMode::Minimal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationMode {
    Full,
    Minimal,
}

/// Stable warning codes surfaced on the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WarningCode {
    HeavyPivotMinimalMutation,
    ChartsPresentMinimalMutation,
    MacrosPresentMinimalMutation,
    SessionReported,
}

/// A pipeline warning: a stable code plus human detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EditWarning {
    pub code: WarningCode,
    pub detail: String,
}

impl EditWarning {
    #[must_use]
    pub fn new(code: WarningCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

/// The canonical cell-level edit manifest (D7: the manifest is the diff and the
/// re-anchoring input). Self-contained and versioned for durable storage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EditManifest {
    pub schema_version: u32,
    pub format: OfficeFormat,
    /// The ops actually applied by the session — no phantom ops, no missing
    /// ops (the session reports exactly what it did).
    pub ops: Vec<EditOp>,
    /// The OPC parts that legitimately changed, observed by diffing the input
    /// and output packages (authoritative, not derived from the ops).
    pub touched_parts: BTreeSet<String>,
    pub mutation_mode: MutationMode,
    pub warnings: Vec<EditWarning>,
}

impl EditManifest {
    /// The anchor-remapping effects, in op order, for ARTL-2 replay.
    #[must_use]
    pub fn anchor_effects(&self) -> Vec<AnchorEffect> {
        self.ops.iter().filter_map(EditOp::anchor_effect).collect()
    }

    /// One diff line per op (D7 semantic diff; the viewer never re-parses two
    /// binaries).
    #[must_use]
    pub fn render_diff(&self) -> Vec<String> {
        self.ops.iter().map(EditOp::render).collect()
    }

    /// Field-name-tagged MessagePack encoding for durable storage (ARTL-4).
    pub fn to_msgpack(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec_named(self).map_err(|_| {
            Error::Artifact(ArtifactError::InvalidEditManifest(
                "edit manifest failed to encode",
            ))
        })
    }

    /// Decodes a manifest from [`EditManifest::to_msgpack`] bytes.
    pub fn from_msgpack(bytes: &[u8]) -> Result<Self> {
        let manifest: Self = rmp_serde::from_slice(bytes).map_err(|_| {
            Error::Artifact(ArtifactError::InvalidEditManifest(
                "edit manifest failed to decode",
            ))
        })?;
        if manifest.schema_version != EDIT_MANIFEST_SCHEMA_VERSION {
            return Err(Error::Artifact(ArtifactError::InvalidEditManifest(
                "edit manifest schema version is unsupported",
            )));
        }
        Ok(manifest)
    }
}
