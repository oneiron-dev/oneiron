//! Canonical commit authorship, message and file modes.

use crate::entity_id::EntityId;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeCommitMetadata {
    /// The canonical author; `None` when the author was erased before the
    /// seal (FIX 7348): the record keeps its modes and the chain seals, and
    /// its export alone holds.
    pub author: Option<EntityId>,
    pub message: String,
    /// Unlisted tested files are ordinary mode 100644 files.
    pub file_modes: BTreeMap<[u8; 32], u32>,
}
impl CodeCommitMetadata {
    #[must_use]
    pub fn new(author: EntityId, message: impl Into<String>) -> Self {
        Self {
            author: Some(author),
            message: message.into(),
            file_modes: BTreeMap::new(),
        }
    }
    /// Metadata whose author was erased before the seal (FIX 7348).
    #[must_use]
    pub fn authorless(message: impl Into<String>) -> Self {
        Self {
            author: None,
            message: message.into(),
            file_modes: BTreeMap::new(),
        }
    }
    #[must_use]
    pub fn with_file_mode(mut self, document: [u8; 32], mode: u32) -> Self {
        self.file_modes.insert(document, mode);
        self
    }
}
