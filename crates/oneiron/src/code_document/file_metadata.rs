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

use super::codec::{invalid, validate_path};
use super::{CodeDocumentSession, CodeEditReceipt, CodeFileEdit};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::write_envelope::WriteActor;

pub use crate::store::code_document_values::{CodeFileMetadataEdit, CodeFilePresence};

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
