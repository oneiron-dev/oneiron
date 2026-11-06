//! Core half of `batch::export::bundle_types`: its store-layer items live in `oneiron_store::batch::export::bundle_types` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::batch::export::bundle_types::*;

use super::ExportEntity;
use serde::{Deserialize, Serialize};

/// Source files stay exact. A credential-bearing file is redacted, never
/// base64-encoded around the mandatory serializer inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportSourceFile {
    pub path: String,
    pub content: ExportSourceContent,
    pub sha256: Option<String>,
}

/// A source file's bytes as the archive carries them (FIX 10101): UTF-8 text
/// inline; any other bytes as the archive file `files/<blake3>`, by its
/// BLAKE3 and length, read by the credential scan before it is attached and
/// again as it is imported; nothing when the scan redacts the file. Binary
/// bytes are never a reason to redact. Import also reads UTF-8 bytes carried
/// as a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ExportSourceContent {
    Text(String),
    File(crate::serialize::ExportBodyFile),
    Redacted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportFileTree {
    /// Canonical skill-tree SHA-256 law, also used for agent folders.
    /// Absent whenever any file is redacted; never a false identity claim.
    pub content_hash: Option<String>,
    pub files: Vec<ExportSourceFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportSkillBundle {
    pub entity: ExportEntity,
    /// Actual persisted SKILL.md/scripts, not a rendering of the record metadata.
    pub source_tree: Option<ExportFileTree>,
    /// Source syntax, never an approval or a provenance assertion.
    pub source_format: Option<crate::write_envelope::skill_source::SkillPackageFormat>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportAgentBundle {
    /// Names the actual AGENT_DEF row in the evidence ledger.
    pub entity_id: String,
    /// Locally captured birth/fork identity, or untrusted lineage from an imported
    /// archive (the owning row carries Imported source). Never a current-parent guess.
    #[serde(rename = "forkHash")]
    pub fork_hash: Option<String>,
    pub source_tree: Option<ExportFileTree>,
    pub omission: Option<AgentBundleOmission>,
}
