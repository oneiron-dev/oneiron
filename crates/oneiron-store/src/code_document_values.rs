//! Tested code file frontiers, text edits and Git metadata edits.

use oneiron_base::error::{ArtifactError, Error, Result};
use serde::{Deserialize, Serialize};

/// One tested file state. The operation fold includes each operation's
/// durable stamp, which names no actor: the actor is on its receipts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeDocumentFrontier {
    pub document_id: [u8; 32],
    pub repo: String,
    pub path: String,
    /// Canonically ordered Loro version vector, not the per-session revision fold.
    pub version: Vec<(u64, i32)>,
    pub op_fold: [u8; 32],
    pub text_hash: [u8; 32],
    /// The Git file state this document asserts (G4 PR2); `None` for an
    /// ordinary text document, which asserts none and encodes as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_presence: Option<CodeFilePresence>,
}

/// One edit against Unicode scalar offsets in the session's observed text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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

/// Whether a path holds a file, and its Git mode when it does. `present`
/// holds exactly when `mode` is set; an absent path has no mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeFilePresence {
    pub present: bool,
    pub mode: Option<u32>,
}

impl CodeFilePresence {
    /// A file at `mode`.
    #[must_use]
    pub fn file(mode: u32) -> Self {
        Self {
            present: true,
            mode: Some(mode),
        }
    }

    /// No file.
    #[must_use]
    pub fn absent() -> Self {
        Self {
            present: false,
            mode: None,
        }
    }

    /// A well-formed state: present with a kept mode, or absent with none.
    ///
    /// # Errors
    /// Presence and mode that disagree, or a mode no code file keeps.
    pub fn validate(&self) -> Result<()> {
        match (self.present, self.mode) {
            (true, Some(mode)) => crate::code_snapshot::file_mode::validate_code_file_mode(mode),
            (false, None) => Ok(()),
            _ => Err(invalid()),
        }
    }
}

/// One reviewed metadata change of one path: the exact state it was made
/// against, the state it leaves, and an explicit same-document rename.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeFileMetadataEdit {
    pub path: String,
    pub expected: CodeFilePresence,
    pub replacement: CodeFilePresence,
    /// A normalized destination for a present file, never guessed.
    pub new_path: Option<String>,
}

impl CodeFileMetadataEdit {
    /// The edit that moves `path` from `expected` to `replacement`.
    #[must_use]
    pub fn between(path: &str, expected: CodeFilePresence, replacement: CodeFilePresence) -> Self {
        Self {
            path: path.to_owned(),
            expected,
            replacement,
            new_path: None,
        }
    }

    /// Whether this edit removes its path.
    #[must_use]
    pub fn removes(&self) -> bool {
        self.expected.present && !self.replacement.present
    }

    /// CALL M (`validate_received_file_metadata`): absent and empty are
    /// distinct, and every present state names its exact Git mode. A
    /// rename moves a present file only; an edit that changes nothing is
    /// refused here, on this metadata path alone.
    ///
    /// # Errors
    /// A malformed state or path, or an empty change.
    pub fn validate(&self, repo: &str) -> Result<()> {
        validate_path(repo, &self.path)?;
        self.expected.validate()?;
        self.replacement.validate()?;
        if let Some(new_path) = &self.new_path {
            validate_path(repo, new_path)?;
            if *new_path == self.path || !self.expected.present || !self.replacement.present {
                return Err(invalid());
            }
        } else if self.expected == self.replacement {
            return Err(invalid());
        }
        Ok(())
    }
}

pub fn invalid() -> Error {
    Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
        "invalid code document state",
    ))
}

pub fn validate_path(repo: &str, path: &str) -> Result<()> {
    if repo.trim().is_empty()
        || repo.len() > 4096
        || repo.contains('\0')
        || path.is_empty()
        || path.len() > 4096
        || path.starts_with('/')
        || path.contains(['\\', '\0'])
        || path.split('/').any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(invalid());
    }
    Ok(())
}

/// A cursor-anchored symbol span. Encoded Loro cursors survive snapshot reopen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSpanAnchor {
    pub document_id: [u8; 32],
    pub start: Vec<u8>,
    pub end: Vec<u8>,
    pub content_hash: [u8; 32],
}

/// One family of a code document's stored rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeDocumentRows {
    /// The live head: its text and every operation's edit.
    Head,
    /// One tested frontier's text.
    Frontier,
    /// One ingress receipt's edit.
    Ingress,
}
