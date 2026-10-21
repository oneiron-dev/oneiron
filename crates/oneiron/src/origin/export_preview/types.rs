//! The wire shapes of the exact export preview (FIX 6869, G4 PR3).
//!
//! A preview names one explicit sealed revision against one explicit ref
//! expectation and answers its complete before and after trees: every
//! path, and every changed leaf's mode, size, Git object and BLAKE3 hash,
//! each with a byte handle. A handle is an unsigned selector the read
//! recomputes, never a capability. Either answer is complete or a typed
//! hold naming what blocks it: a hold carries no partial list, byte,
//! digest or handle. Every key is emitted; an absent value is `null`.
use serde::{Deserialize, Serialize};

use crate::EntityId;

/// One explicit export expectation to preview. It names no actor, Grant or
/// owner proof: the door's caller is its credential's own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeExportPreviewRequest {
    /// The registered served name, with no `.git` suffix.
    pub repo: String,
    /// The served CODE anchor the revision's queue serves (32 hex). It
    /// selects the repository before the revision is looked up and asserts
    /// no authority.
    pub code_repo: EntityId,
    /// The caller's own live checkout of the served store, 32 lower-hex.
    pub checkout: String,
    /// That checkout's live lease epoch.
    pub epoch: u64,
    /// The sealed CodeRevision the export would write.
    pub revision: EntityId,
    /// The full ref the export would advance, such as `refs/heads/main`.
    pub ref_name: String,
    /// The value the export would be decided against; `null` is an absent
    /// ref and an empty before tree. Never discovered for the caller.
    pub expected_old_oid: Option<String>,
    /// The same explicit `/git` door base the export takes.
    pub endpoint: String,
}

/// One exact preview: both complete trees and their changed leaves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeExportPreview {
    pub request: CodeExportPreviewRequest,
    /// The served CODE anchor, never the imported snapshot's id.
    pub code_repo: EntityId,
    /// The object-store-derived origin id.
    pub origin_repo_id: EntityId,
    /// The object store's hex identity, never a host path.
    pub object_store: String,
    /// The expected commit's root tree, 40 hex; `null` only for an absent
    /// expectation.
    pub source_tree: Option<String>,
    /// The sealed revision's checked root tree, 40 hex.
    pub target_tree: String,
    /// The sealed revision's complete inventory digest, 64 hex.
    pub inventory_digest: String,
    /// This preview's identity, 64 hex: a selector, not a capability.
    pub preview_digest: String,
    /// Always `true` on an answer: complete raw bytes, modes and presence.
    pub exact: bool,
    /// The ref's value when the preview read it; an observation only.
    pub observed_ref_oid: Option<String>,
    /// Whether the expectation matched that observation. A stale preview
    /// stays exact for its own pins.
    pub expected_matches_observed: bool,
    /// Every leaf path of the before tree, sorted by bytes.
    pub before_paths: Vec<String>,
    /// Every leaf path of the after tree, sorted by bytes.
    pub after_paths: Vec<String>,
    /// Each path whose presence, bytes or mode differs, sorted by bytes.
    pub files: Vec<CodeExportFileDelta>,
}

/// One changed path: its before and after leaf, `null` where absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeExportFileDelta {
    pub path: String,
    pub before: Option<CodeExportFileIdentity>,
    pub after: Option<CodeExportFileIdentity>,
}

/// One leaf of one side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeExportFileIdentity {
    /// 33188, 33261 or 40960 (0o100644, 0o100755, 0o120000).
    pub mode: u32,
    pub size_bytes: u64,
    /// The Git blob object id, 40 hex.
    pub git_oid: String,
    /// The BLAKE3 hash of the exact raw bytes, 64 hex.
    pub content_hash: String,
    pub handle: CodeExportByteHandle,
}

/// Which tree of a preview.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CodeExportSide {
    Before,
    After,
}

/// Selects one changed leaf of one recomputed preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeExportByteHandle {
    pub preview_digest: String,
    pub side: CodeExportSide,
    /// The inventory path, never a host pathname.
    pub path: String,
}

/// Reads one changed leaf of the preview `preview` names again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeExportFileReadRequest {
    pub preview: CodeExportPreviewRequest,
    pub handle: CodeExportByteHandle,
}

/// One leaf's exact raw bytes, with its identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeExportFileBytes {
    pub handle: CodeExportByteHandle,
    pub mode: u32,
    pub size_bytes: u64,
    pub git_oid: String,
    pub content_hash: String,
    /// The bytes as a JSON array of integers 0..255; a link's target bytes.
    pub bytes: Vec<u8>,
}

/// A preview answer: complete, or held whole.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CodeExportPreviewAnswer {
    Ready { preview: CodeExportPreview },
    Held { hold: CodeExportPreviewHold },
}

/// A byte read answer: the exact leaf, or held whole.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CodeExportFileReadAnswer {
    Ready { file: CodeExportFileBytes },
    Held { hold: CodeExportPreviewHold },
}

/// Why no exact answer is released: every blocking source the caller may
/// see by name, and at most one line for the rest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeExportPreviewHold {
    /// Always [`CODE_EXPORT_PREVIEW_HELD`].
    pub code: String,
    /// Sorted and deduplicated.
    pub blockers: Vec<CodeExportPreviewBlocker>,
}

/// The one hold code.
pub const CODE_EXPORT_PREVIEW_HELD: &str = "code_export_preview_held";

/// One blocking source, why it blocks and what clears it.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct CodeExportPreviewBlocker {
    pub source: CodeExportBlockingSource,
    pub reason: CodeExportPreviewBlockReason,
    pub message: String,
    pub way_out: String,
}

/// What blocks: a record, a leaf of one side, a Git object, an evidence
/// link, or the one line for everything outside a Grant.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodeExportBlockingSource {
    Entity {
        entity: EntityId,
    },
    File {
        side: CodeExportSide,
        path: String,
        entity: Option<EntityId>,
    },
    Object {
        object_store: String,
        oid: String,
    },
    Evidence {
        reference: String,
    },
    OutsideGrant,
}

/// The typed reason a source blocks.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CodeExportPreviewBlockReason {
    Unavailable,
    Withheld,
    Masked,
    IncompleteEvidence,
    Unreviewed,
    UnsupportedTree,
    OutsideGrant,
}

impl CodeExportPreviewBlocker {
    pub(crate) fn new(
        source: CodeExportBlockingSource,
        reason: CodeExportPreviewBlockReason,
        message: impl Into<String>,
        way_out: impl Into<String>,
    ) -> Self {
        Self {
            source,
            reason,
            message: message.into(),
            way_out: way_out.into(),
        }
    }

    /// The one line a Grant holder reads for every source outside it: no
    /// id, path, hash or count.
    pub(crate) fn outside_grant() -> Self {
        Self::new(
            CodeExportBlockingSource::OutsideGrant,
            CodeExportPreviewBlockReason::OutsideGrant,
            "outside your Grant",
            "Ask an Owner to grant the required source scope, or have an Owner read this preview.",
        )
    }
}

impl CodeExportPreviewHold {
    /// `blockers`, sorted and deduplicated, under the one hold code.
    pub(crate) fn of(mut blockers: Vec<CodeExportPreviewBlocker>) -> Self {
        blockers.sort();
        blockers.dedup();
        Self {
            code: CODE_EXPORT_PREVIEW_HELD.to_owned(),
            blockers,
        }
    }
}

impl CodeExportPreviewBlockReason {
    /// The fixed explanation a Grant holder reads for a source it may see:
    /// it names nothing beyond the source itself.
    pub(crate) const fn grant_message(self) -> &'static str {
        match self {
            Self::Unavailable => "this source is not available to the preview",
            Self::Withheld => "this source is withheld from your credential or by custody",
            Self::Masked => "your credential reads a masked copy of this file, not its exact bytes",
            Self::IncompleteEvidence => "this source's evidence is incomplete",
            Self::Unreviewed => "this revision's changes or imported bytes are not yet reviewed",
            Self::UnsupportedTree => "this tree holds a shape the exact preview does not export",
            Self::OutsideGrant => "outside your Grant",
        }
    }
}
