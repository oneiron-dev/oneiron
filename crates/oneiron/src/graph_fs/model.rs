//! Core half of `graph_fs::model`: its store-layer items live in `oneiron_store::graph_fs::model` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::graph_fs::model::*;

use crate::claim::ScopedRead;
use crate::entity_id::bytes_to_hex_lower;
use crate::store::RetrievalRunId;
use crate::store::sandbox_import::SandboxImportClass;
use crate::store::sandbox_import::SandboxLinkedImport;

const GRAPH_FS_READDIR_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("graph_fs.readdir", SandboxImportClass::ReadOnly);

const GRAPH_FS_READ_FILE_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("graph_fs.read_file", SandboxImportClass::ReadOnly);

const GRAPH_FS_READ_LINK_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("graph_fs.read_link", SandboxImportClass::ReadOnly);

const GRAPH_FS_GREP_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("graph_fs.grep", SandboxImportClass::ReadOnly);

const GRAPH_FS_LS_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("graph_fs.ls", SandboxImportClass::ReadOnly);

const GRAPH_FS_FIND_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("graph_fs.find", SandboxImportClass::ReadOnly);

const GRAPH_FS_CAT_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("graph_fs.cat", SandboxImportClass::ReadOnly);

const GRAPH_FS_HEAD_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("graph_fs.head", SandboxImportClass::ReadOnly);

const GRAPH_FS_WC_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("graph_fs.wc", SandboxImportClass::ReadOnly);

pub const GRAPH_FS_HOST_IMPORTS: &[SandboxLinkedImport] = &[
    GRAPH_FS_READDIR_IMPORT,
    GRAPH_FS_READ_FILE_IMPORT,
    GRAPH_FS_READ_LINK_IMPORT,
    GRAPH_FS_GREP_IMPORT,
    GRAPH_FS_LS_IMPORT,
    GRAPH_FS_FIND_IMPORT,
    GRAPH_FS_CAT_IMPORT,
    GRAPH_FS_HEAD_IMPORT,
    GRAPH_FS_WC_IMPORT,
];

#[derive(Debug, Clone, PartialEq)]
pub struct GraphFsCommandOutput {
    pub(super) bytes: Vec<u8>,
    pub(super) next_cursor: Option<String>,
    pub(super) decision: GraphFsCoreutilsDecision,
    pub(super) decision_reason: String,
    pub(super) telemetry_run_id: Option<RetrievalRunId>,
    pub(super) read_receipt: Option<oneiron_contracts::claim::ScopedReadReceipt>,
}

impl GraphFsCommandOutput {
    /// Receipt for every scoped read the command made, folded: the indexed
    /// search and final hydration of claim grep, the file a cat, head, wc or
    /// grep read, and the listings an ls or walk read. `None` when the
    /// command made no scoped read (the temporal pushdowns scan by policy).
    #[must_use]
    pub fn read_receipt(&self) -> Option<&oneiron_contracts::claim::ScopedReadReceipt> {
        self.read_receipt.as_ref()
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    #[must_use]
    pub fn next_cursor(&self) -> Option<&str> {
        self.next_cursor.as_deref()
    }

    #[must_use]
    pub fn decision(&self) -> GraphFsCoreutilsDecision {
        self.decision
    }

    #[must_use]
    pub fn decision_reason(&self) -> &str {
        &self.decision_reason
    }

    #[must_use]
    pub fn telemetry_run_id(&self) -> Option<RetrievalRunId> {
        self.telemetry_run_id
    }
}

pub struct GraphFsResolver<'read, 'vault> {
    pub(super) scoped_read: &'read ScopedRead<'vault>,
    pub(super) options: GraphFsOptions,
    pub(super) snapshot: Option<(crate::entity_id::EntityId, [u8; 32])>,
    /// The mounting handle reads repo bytes masked (FIX 7608 2b-ii, FIX
    /// 8964): a byte-recipient hint, never a scoped-read key or authority.
    pub(super) repo_masked: bool,
}

impl<'vault> ScopedRead<'vault> {
    #[must_use]
    pub fn graph_fs(&self, options: GraphFsOptions) -> GraphFsResolver<'_, 'vault> {
        GraphFsResolver::new(self, options)
    }
}
