//! Canonical commit authorship, message and file modes.

use crate::entity_id::EntityId;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeCommitMetadata {
    pub author: EntityId,
    pub message: String,
    /// Unlisted tested files are ordinary mode 100644 files.
    pub file_modes: BTreeMap<[u8; 32], u32>,
}
impl CodeCommitMetadata {
    #[must_use]
    pub fn new(author: EntityId, message: impl Into<String>) -> Self {
        Self {
            author,
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
