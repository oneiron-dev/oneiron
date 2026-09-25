//! File edit verbs, cursor spans, operation receipts and tested frontiers.

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::write_envelope::WriteActor;

/// One tested file state. The operation fold includes durable actor stamps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeDocumentFrontier {
    pub document_id: [u8; 32],
    pub repo: String,
    pub path: String,
    /// Canonically ordered Loro version vector, not the per-session revision fold.
    pub version: Vec<(u64, i32)>,
    pub op_fold: [u8; 32],
    pub text_hash: [u8; 32],
}

/// One edit against Unicode scalar offsets in the session's observed text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeFileEdit {
    pub path: String,
    pub start: usize,
    pub end: usize,
    pub expected: String,
    pub replacement: String,
    pub new_path: Option<String>,
}

impl CodeFileEdit {
    /// Lowers a whole-file proposal to its smallest contiguous changed span.
    /// The unchanged prefix and suffix never become deletion operations.
    pub fn between(path: &str, old: &str, new: &str) -> Self {
        let old: Vec<char> = old.chars().collect();
        let new: Vec<char> = new.chars().collect();
        let prefix = old.iter().zip(&new).take_while(|(a, b)| a == b).count();
        let suffix = old[prefix..]
            .iter()
            .rev()
            .zip(new[prefix..].iter().rev())
            .take_while(|(a, b)| a == b)
            .count();
        Self {
            path: path.to_owned(),
            start: prefix,
            end: old.len() - suffix,
            expected: old[prefix..old.len() - suffix].iter().collect(),
            replacement: new[prefix..new.len() - suffix].iter().collect(),
            new_path: None,
        }
    }

    /// A path change is a metadata operation on the same document identity.
    pub fn rename(path: &str, new_path: &str) -> Self {
        Self {
            path: path.to_owned(),
            start: 0,
            end: 0,
            expected: String::new(),
            replacement: String::new(),
            new_path: Some(new_path.to_owned()),
        }
    }
}

/// A cursor-anchored symbol span. Encoded Loro cursors survive snapshot reopen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSpanAnchor {
    pub document_id: [u8; 32],
    pub start: Vec<u8>,
    pub end: Vec<u8>,
    pub content_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeSpanResolution {
    Mapped {
        start: usize,
        end: usize,
    },
    /// The original span was deleted or changed. Never silently select new text.
    Drifted,
}

/// Durable per-operation receipt; sequence is ordered within one document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeEditReceipt {
    pub document_id: [u8; 32],
    pub session_id: EntityId,
    pub actor: WriteActor,
    pub sequence: u64,
    pub peer_id: u64,
    pub counter_start: i32,
    pub counter_end: i32,
    pub edit: CodeFileEdit,
    pub before: CodeDocumentFrontier,
    pub after: CodeDocumentFrontier,
}
