//! Repo bytes a Memory handle's masked reader reads (FIX 7608 slice 2a,
//! ASK 1). The owner reading at the owner's own door reads stored bytes; a
//! handle bound to another credential, and any handle a code run's host
//! origin rides (whatever credential it carries), reads repo bytes masked.
//! The choice changes what is projected only: never the actor, authorship,
//! admission or what is read.
//!
//! A handle the host bound to an MCP tool call (FIX 8961) reads repo bytes
//! masked too, the owner's own credential included: the tool, not the
//! owner, receives them. The marker only masks; it admits nothing, and the
//! owner's HTTP, CLI and SDK doors never carry it.
//!
//! A hydrated row is a repo file only when it is a snapshot ASSET holding
//! its bytes inline: its id is derived from their BLAKE3, which is the hash
//! a repo mark keeps. Every other row, and every row no mark covers, reads
//! as it always has.

use std::borrow::Cow;

use heed::RoTxn;

use super::{Memory, MemoryResult};
use crate::Vault;
use crate::code_document::CodeDocumentFrontier;
use crate::codebase::snapshot_asset_entity_id;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::origin::secret_marks::{
    RepoMarkFacts, RepoSecretMarkLookup, repo_secret_marks_for_hash_in_txn,
};
use crate::origin::secret_projection::{
    REPO_OPAQUE_FILE_BYTES, RepoBodyProjection, RepoOpaqueFile, project_repo_bytes_in_txn,
    sourced_opaque_in_txn,
};
use crate::registry::ENTITY_TYPE_ASSET;

mod reveal;

/// The body a masked reader reads of the hydrated row `id`, in `txn`:
/// `None` unless the row is a repo snapshot ASSET whose inline bytes a repo
/// mark covers, and then their projection.
///
/// # Errors
/// A store failure, or a mark that does not decode.
pub(crate) fn repo_asset_body_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    body: &[u8],
) -> Result<Option<Vec<u8>>> {
    if entity_type != ENTITY_TYPE_ASSET {
        return Ok(None);
    }
    let hash = *blake3::hash(body).as_bytes();
    if snapshot_asset_entity_id(&hash)? != *id {
        return Ok(None);
    }
    let marks = repo_secret_marks_for_hash_in_txn(vault, txn, &hash)?;
    if marks.is_empty() {
        return Ok(None);
    }
    // In the caller's snapshot, which may be a writer's: the stored spans
    // alone (FIX 8966 wires the known-value pass at the reads that own
    // their snapshot).
    project_repo_bytes_in_txn(vault, txn, &marks, body.to_vec(), None)
        .map(|projected| Some(projected.into_bytes()))
}

/// [`repo_asset_body_in_txn`] in its own snapshot, for a reader that holds
/// none; no snapshot is opened for a row that is no ASSET.
///
/// # Errors
/// As [`repo_asset_body_in_txn`].
pub(crate) fn repo_asset_body(
    vault: &Vault,
    id: &EntityId,
    entity_type: u8,
    body: &[u8],
) -> Result<Option<Vec<u8>>> {
    if entity_type != ENTITY_TYPE_ASSET {
        return Ok(None);
    }
    let txn = vault.store.env.read_txn()?;
    repo_asset_body_in_txn(vault, &txn, id, entity_type, body)
}

/// `body`, a hydrated row's, as a masked reader reads it: a repo ASSET's
/// projection when a mark covers its inline bytes, else `body` as read.
///
/// # Errors
/// As [`repo_asset_body_in_txn`].
pub(crate) fn masked_asset_body(
    vault: &Vault,
    id: &EntityId,
    entity_type: u8,
    body: Vec<u8>,
) -> Result<Vec<u8>> {
    Ok(repo_asset_body(vault, id, entity_type, &body)?.unwrap_or(body))
}

/// `bytes`, one stored file's, as a masked reader reads them, the marks
/// found in one walk: the stored bytes when no mark covers them.
///
/// # Errors
/// A store failure, or a mark that does not decode.
pub(crate) fn project_repo_file(vault: &Vault, bytes: Vec<u8>) -> Result<RepoBodyProjection> {
    vault.with_known_values(|known| {
        let txn = vault.store.env.read_txn()?;
        let marks =
            repo_secret_marks_for_hash_in_txn(vault, &txn, blake3::hash(&bytes).as_bytes())?;
        project_repo_bytes_in_txn(vault, &txn, &marks, bytes, known)
    })
}

/// The placeholder a masked reader reads for `bytes`, a code view's file
/// at `tested` (FIX 8967), when that document state grew from a marked
/// blob it no longer is; `None` when its own bytes decide, as before.
///
/// # Errors
/// A store failure, a mark that does not decode, or a stored document
/// state that does not check.
pub(crate) fn document_file_sourced_opaque(
    vault: &Vault,
    tested: &CodeDocumentFrontier,
    bytes: &[u8],
) -> Result<Option<RepoOpaqueFile>> {
    let txn = vault.store.env.read_txn()?;
    let facts = RepoMarkFacts::read_in_txn(vault, &txn, RepoSecretMarkLookup::ReadableClaims)?;
    sourced_opaque_in_txn(vault, &txn, &facts, bytes, || {
        vault.code_document_source_hashes_in_txn(&txn, tested)
    })
}

/// One code text as a view serves it (FIX 8967): the stored text, or a
/// projection a masked reader reads in its place.
pub(crate) struct ServedText {
    pub(crate) text: String,
    /// Whether `text` is a projection, not the stored text: what is shown
    /// of it is then never attributed to the operations that wrote it.
    pub(crate) projected: bool,
}

impl ServedText {
    fn stored(text: String) -> Self {
        Self {
            text,
            projected: false,
        }
    }

    fn projection(body: RepoBodyProjection) -> Self {
        let text = match body {
            RepoBodyProjection::Exact(bytes) => {
                return Self::stored(String::from_utf8(bytes).unwrap_or_else(|error| {
                    String::from_utf8_lossy(error.as_bytes()).into_owned()
                }));
            }
            RepoBodyProjection::Masked { bytes, .. } => String::from_utf8(bytes).ok(),
            RepoBodyProjection::Opaque(_) => None,
        };
        Self {
            text: text
                .unwrap_or_else(|| String::from_utf8_lossy(REPO_OPAQUE_FILE_BYTES).into_owned()),
            projected: true,
        }
    }
}

/// The repo marks one view's masked reader reads its file texts under,
/// found once for that view; none for a reader of stored bytes.
pub(crate) struct RepoReadMasks {
    facts: Option<RepoMarkFacts>,
}

impl RepoReadMasks {
    /// Whether this view's reader reads anything masked: a masked reader
    /// in a vault some readable mark is in.
    pub(crate) fn active(&self) -> bool {
        self.facts.as_ref().is_some_and(|facts| !facts.is_empty())
    }

    /// `text`, the stored text of the code document state `tested`, as this
    /// view's reader reads it (FIX 8967): a state that grew from a marked
    /// blob it no longer is reads as the placeholder; a state whose own
    /// bytes a mark covers reads as that blob's projection; any other, and
    /// every state for a reader of stored bytes, as stored.
    ///
    /// # Errors
    /// A store failure, or a stored document state that does not check.
    pub(crate) fn document(
        &self,
        vault: &Vault,
        tested: &CodeDocumentFrontier,
        text: String,
    ) -> Result<ServedText> {
        let Some(facts) = self.facts.as_ref().filter(|facts| !facts.is_empty()) else {
            return Ok(ServedText::stored(text));
        };
        let txn = vault.store.env.read_txn()?;
        if let Some(opaque) = sourced_opaque_in_txn(vault, &txn, facts, text.as_bytes(), || {
            vault.code_document_source_hashes_in_txn(&txn, tested)
        })? {
            return Ok(ServedText::projection(RepoBodyProjection::Opaque(opaque)));
        }
        let marks = facts.for_hash(blake3::hash(text.as_bytes()).as_bytes());
        if marks.is_empty() {
            return Ok(ServedText::stored(text));
        }
        drop(txn);
        vault
            .with_known_values(|known| {
                let txn = vault.store.env.read_txn()?;
                project_repo_bytes_in_txn(vault, &txn, &marks, text.into_bytes(), known)
            })
            .map(ServedText::projection)
    }

    /// `bytes`, a text made from the repo bytes whose BLAKE3 are `sources`
    /// (a proposal's candidate from the file at its base), as this view's
    /// reader reads it (FIX 8967): the placeholder when it grew from a
    /// marked blob it no longer is, else as [`Self::bytes`] reads it.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn sourced_bytes<'b>(
        &self,
        vault: &Vault,
        bytes: &'b [u8],
        sources: &[[u8; 32]],
    ) -> Result<Cow<'b, [u8]>> {
        if let Some(facts) = self.facts.as_ref() {
            let txn = vault.store.env.read_txn()?;
            if sourced_opaque_in_txn(vault, &txn, facts, bytes, || Ok(sources.to_vec()))?.is_some()
            {
                return Ok(Cow::Borrowed(REPO_OPAQUE_FILE_BYTES));
            }
        }
        self.bytes(vault, bytes)
    }

    /// `bytes`, one file's stored bytes, as this view's reader reads them:
    /// as they are when no mark covers them.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn bytes<'b>(&self, vault: &Vault, bytes: &'b [u8]) -> Result<Cow<'b, [u8]>> {
        let Some(facts) = &self.facts else {
            return Ok(Cow::Borrowed(bytes));
        };
        let marks = facts.for_hash(blake3::hash(bytes).as_bytes());
        if marks.is_empty() {
            return Ok(Cow::Borrowed(bytes));
        }
        vault
            .with_known_values(|known| {
                let txn = vault.store.env.read_txn()?;
                project_repo_bytes_in_txn(vault, &txn, &marks, bytes.to_vec(), known)
            })
            .map(|projected| Cow::Owned(projected.into_bytes()))
    }
}

impl Memory<'_> {
    /// Binds this handle to an MCP tool call (FIX 8961, GAP-A): its repo
    /// reads are masked whatever credential rides it, the owner's included.
    /// Mask-only and off by default; the host sets it once where it builds
    /// the MCP handle, and room or turn handles built from this one keep it.
    /// It never turns a recipient into a reveal, and never changes the
    /// actor, admission or anything but which repo bytes are returned.
    #[must_use]
    pub fn for_repo_tool_recipient(mut self) -> Self {
        self.repo_tool_recipient.mask();
        self
    }

    /// Whether this handle reads repo bytes masked: an MCP tool call, a
    /// credential other than the owner's, or a call a code run's host
    /// origin rides.
    pub(crate) fn repo_reads_masked(&self) -> MemoryResult<bool> {
        Ok(self.repo_tool_recipient.masked()
            || self.host_origin.is_some()
            || self.reads_lifted_keys_masked()?)
    }

    /// The marks this handle's view reads file texts under: found in one
    /// walk for a masked reader, none for a reader of stored bytes.
    pub(crate) fn repo_read_masks(&self) -> MemoryResult<RepoReadMasks> {
        if !self.repo_reads_masked()? {
            return Ok(RepoReadMasks { facts: None });
        }
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        let facts =
            RepoMarkFacts::read_in_txn(self.vault, &txn, RepoSecretMarkLookup::ReadableClaims)?;
        Ok(RepoReadMasks { facts: Some(facts) })
    }

    /// The body the read lane decodes for the admitted row `id`, in `txn`:
    /// a repo ASSET's projection for a masked reader, else `body` as read.
    pub(super) fn repo_lane_body_in_txn(
        &self,
        txn: &RoTxn<'_>,
        id: &EntityId,
        entity_type: u8,
        body: Vec<u8>,
    ) -> MemoryResult<Vec<u8>> {
        if entity_type != ENTITY_TYPE_ASSET
            || !(self.repo_tool_recipient.masked()
                || self.host_origin.is_some()
                || self.reads_lifted_keys_masked_in_txn(txn)?)
        {
            return Ok(body);
        }
        Ok(repo_asset_body_in_txn(self.vault, txn, id, entity_type, &body)?.unwrap_or(body))
    }
}
