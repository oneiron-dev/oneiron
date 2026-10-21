//! A code document's Git file metadata as stamped operations (FIX 6869, G4
//! PR2): whether the path holds a file and with which mode, beside its
//! text. A removal keeps the document's text and frees its path; an empty
//! file is present with no bytes; an executable bit or a symlink is a mode.
//!
//! Metadata is written into the document's Loro `meta` map (`present`,
//! `mode`, and `path` for an explicit rename) by the one shared edit
//! writer, so a metadata change earns its own operation fold and receipt.
//! An ordinary text document never asserts metadata: its frontier carries
//! none, and nothing here infers a mode, a removal or a rename from text.
use loro::{LoroMap, LoroValue, ValueOrContainer};
use serde::{Deserialize, Serialize};

use super::codec::{invalid, validate_path};
use super::{CodeDocumentSession, CodeEditReceipt, CodeFileEdit};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::write_envelope::WriteActor;

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
    pub(crate) fn validate(&self) -> Result<()> {
        match (self.present, self.mode) {
            (true, Some(mode)) => crate::codebase::validate_code_file_mode(mode),
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
    pub(crate) fn validate(&self, repo: &str) -> Result<()> {
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

/// The metadata `meta` asserts, or `None` for a document that never
/// asserted any. Both keys are written together; one alone is corruption.
///
/// # Errors
/// A malformed or partial assertion.
pub(super) fn presence_in(meta: &LoroMap) -> Result<Option<CodeFilePresence>> {
    let present = match meta.get("present") {
        None => None,
        Some(ValueOrContainer::Value(LoroValue::Bool(present))) => Some(present),
        Some(_) => return Err(invalid()),
    };
    let mode = match meta.get("mode") {
        None => None,
        Some(ValueOrContainer::Value(LoroValue::I64(mode))) => {
            Some(u32::try_from(mode).map_err(|_| invalid())?)
        }
        Some(_) => return Err(invalid()),
    };
    let presence = match (present, mode) {
        (None, None) => return Ok(None),
        (Some(present), mode) => CodeFilePresence { present, mode },
        (None, Some(_)) => return Err(invalid()),
    };
    presence.validate()?;
    Ok(Some(presence))
}

/// Writes `edit`'s replacement into `meta`, after checking the state the
/// document asserts, if any, is `edit`'s expected one. A document that
/// asserted nothing takes its expected state from the caller's bound base.
///
/// # Errors
/// An asserted state other than the expected one, or a Loro failure.
pub(super) fn apply_presence(meta: &LoroMap, edit: &CodeFileMetadataEdit) -> Result<()> {
    if presence_in(meta)?.is_some_and(|asserted| asserted != edit.expected) {
        return Err(crate::Error::ConcurrentWrite(
            "document metadata changed since its reviewed base",
        ));
    }
    meta.insert("present", edit.replacement.present)
        .map_err(|_| invalid())?;
    match edit.replacement.mode {
        Some(mode) => meta
            .insert("mode", i64::from(mode))
            .map_err(|_| invalid())?,
        None if meta.get("mode").is_some() => meta.delete("mode").map_err(|_| invalid())?,
        None => {}
    }
    Ok(())
}

impl Vault {
    /// Applies one reviewed metadata change once, under the durable
    /// `operation` identity: the same writer, stamp, receipt and snapshot
    /// rows as a text edit, with an empty text span. A replay with the
    /// same identity and change appends nothing.
    ///
    /// # Errors
    /// A malformed change, a document whose asserted state differs, an
    /// identity reused with another change, or a store failure.
    pub fn apply_code_file_metadata_edit_once(
        &self,
        operation: EntityId,
        session: &mut CodeDocumentSession,
        edit: &CodeFileMetadataEdit,
        actor: WriteActor,
    ) -> Result<CodeEditReceipt> {
        let text = CodeFileEdit {
            path: edit.path.clone(),
            start: 0,
            end: 0,
            expected: String::new(),
            replacement: String::new(),
            new_path: edit.new_path.clone(),
        };
        self.apply_code_file_edit_once_with(operation, session, &text, Some(edit), actor)
    }
}
