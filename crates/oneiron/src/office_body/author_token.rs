//! A DOCX export's default author (FIX 4513, Engine ruling B 10-19): the
//! bytes carry an opaque token, not the actor.
//!
//! An export the caller gave no author lands its tracked revision under a
//! fresh token, [`DOCX_AUTHOR_TOKEN_MARKER`] and a new id's hex, minted per
//! export and never derived from the actor. Its export record keeps the
//! token beside the actor, and the revision group hashes the token, so the
//! stored bytes and their content hash name no one. An author the caller
//! typed is document content and lands as typed.
//!
//! A copy leaving the vault reads each token it carries through the export
//! rows: the actor's hex while the actor stands, [`ERASED_CALL_IDENTITY`]
//! once its erase forgot it. Only `word/document.xml` is read, and only a
//! copy that carries a token is zipped again. A token no row here names
//! stays as it is: one opaque id in place of another. The stored bytes and
//! every reader inside the vault keep the token.
//!
//! [`ERASED_CALL_IDENTITY`]: crate::receipt::ERASED_CALL_IDENTITY

use std::collections::BTreeMap;

use heed::RoTxn;
use oneiron_docedit::retained_opc::Package;

use super::{EXPORTS, OfficeBodyExportRequest, OfficeBodyKind};
use crate::Vault;
use crate::error::Result;

/// What a default author's token starts with; a new id's 32 hex characters
/// follow. It is no actor's id and no other marker's (FIX 4513).
pub(crate) const DOCX_AUTHOR_TOKEN_MARKER: &str = "oneiron-author:";

/// The hex characters after the marker.
const TOKEN_HEX_LEN: usize = 32;

/// The package part a DOCX keeps its tracked revisions in.
const DOCUMENT_PART: &str = "word/document.xml";

/// The author an export lands in its bytes, the one its record shows, and
/// the token, when it is one.
pub(super) struct ExportAuthor {
    pub(super) landed: String,
    pub(super) shown: String,
    pub(super) token: Option<String>,
}

impl ExportAuthor {
    /// The request's author as the caller gave it, or for a DOCX with none,
    /// a fresh token the record shows as the exporting actor. Another format
    /// lands no author.
    pub(super) fn of(
        vault: &Vault,
        kind: OfficeBodyKind,
        request: &OfficeBodyExportRequest<'_>,
    ) -> Result<Self> {
        let actor = request.actor.entity_ref();
        if let Some(author) = request.author {
            return Ok(Self {
                landed: author.to_owned(),
                shown: author.to_owned(),
                token: None,
            });
        }
        let token = match kind {
            OfficeBodyKind::Docx => Some(format!(
                "{DOCX_AUTHOR_TOKEN_MARKER}{}",
                vault.new_entity_id()?.to_hex()
            )),
            OfficeBodyKind::Xlsx | OfficeBodyKind::Pptx => None,
        };
        Ok(Self {
            landed: token.clone().unwrap_or_else(|| actor.to_hex()),
            shown: actor.to_hex(),
            token,
        })
    }
}

impl Vault {
    /// `bytes`, a copy of a stored version leaving the vault, with each
    /// default-author token read through the export rows (see the module).
    /// Any other file, and a DOCX with no token or none a row names, is
    /// returned as it is.
    ///
    /// # Errors
    ///
    /// Storage errors reading the export rows.
    pub(crate) fn resolve_docx_authors(&self, bytes: Vec<u8>) -> Result<Vec<u8>> {
        if !bytes.starts_with(b"PK\x03\x04") {
            return Ok(bytes);
        }
        let txn = self.store.env.read_txn()?;
        self.resolve_docx_authors_in_txn(&txn, bytes)
    }

    /// [`Vault::resolve_docx_authors`] in the caller's snapshot.
    ///
    /// # Errors
    ///
    /// Storage errors reading the export rows.
    pub(crate) fn resolve_docx_authors_in_txn(
        &self,
        txn: &RoTxn<'_>,
        bytes: Vec<u8>,
    ) -> Result<Vec<u8>> {
        if !bytes.starts_with(b"PK\x03\x04") {
            return Ok(bytes);
        }
        // A package this vault's limits do not read was never an export's
        // projection: it is served as it is.
        let Ok(limits) = self.docedit_package_limits_in_txn(txn) else {
            return Ok(bytes);
        };
        let Ok(mut package) =
            Package::open(&bytes, limits, &crate::office_body::document_resources())
        else {
            return Ok(bytes);
        };
        let Ok(Some(document)) = package.part(DOCUMENT_PART) else {
            return Ok(bytes);
        };
        let marker = DOCX_AUTHOR_TOKEN_MARKER.as_bytes();
        if !document
            .windows(marker.len())
            .any(|window| window == marker)
        {
            return Ok(bytes);
        }
        // Every row, by token: an undo, a restore or a fork copies a
        // version's bytes into another version, so the version is no key.
        let authors: BTreeMap<Vec<u8>, String> = EXPORTS
            .scan(&self.store, txn)?
            .into_iter()
            .filter_map(|(_, record)| Some((record.token?.into_bytes(), record.actor.to_hex())))
            .collect();
        let Some(resolved) = swap_tokens(&document, &authors) else {
            return Ok(bytes);
        };
        match package
            .replace_xml_part(DOCUMENT_PART, resolved)
            .and_then(|()| package.export())
        {
            Ok(presented) => Ok(presented),
            Err(_) => Ok(bytes),
        }
    }
}

/// `document` with each token `authors` names replaced by its author;
/// `None` when it names none.
fn swap_tokens(document: &[u8], authors: &BTreeMap<Vec<u8>, String>) -> Option<Vec<u8>> {
    let marker = DOCX_AUTHOR_TOKEN_MARKER.as_bytes();
    let len = marker.len() + TOKEN_HEX_LEN;
    let mut out = Vec::with_capacity(document.len());
    let mut swapped = false;
    let mut at = 0;
    while let Some(&byte) = document.get(at) {
        let author = document
            .get(at..at.saturating_add(len))
            .filter(|token| token.starts_with(marker))
            .and_then(|token| authors.get(token));
        match author {
            Some(author) => {
                out.extend_from_slice(author.as_bytes());
                swapped = true;
                at += len;
            }
            None => {
                out.push(byte);
                at += 1;
            }
        }
    }
    swapped.then_some(out)
}
