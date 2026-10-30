//! One entity row as a peer gets it, and one incoming copy row as the
//! canonical store takes it.

use super::{BlobCopy, ItemCopy, SyncSecretProjection};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::origin::secret_projection::edit::{
    RepoProjectedFileCopy, RepoProjectionDiffResult, apply_repo_projection_diff,
};
use crate::origin::secret_projection::types::REPO_OPAQUE_FILE_BYTES;

/// What a stored row becomes on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CopyRow {
    /// Not a marked item: its stored bytes, as today.
    Keep,
    /// The copy: under `key` (the copy id for a marked snapshot ASSET, else
    /// the row's own id), with the copy's bytes behind the stored header.
    Copy { key: EntityId, row: Vec<u8> },
    /// A row a marked blob whose copy is unread this pass could mark: the
    /// sealed-file placeholder behind the stored header, under `key`. An
    /// export carries it; a window frame carrying it is withheld and owed.
    Sealed { key: EntityId, row: Vec<u8> },
}

impl CopyRow {
    /// The bytes and id the row leaves under: `raw` under `id` when it is no
    /// marked item.
    pub(crate) fn released(self, id: EntityId, raw: Vec<u8>) -> (EntityId, Vec<u8>) {
        match self {
            Self::Keep => (id, raw),
            Self::Copy { key, row } | Self::Sealed { key, row } => (key, row),
        }
    }
}

/// What an incoming row on a copy becomes canonically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InboundRow {
    /// Not a copy: the ordinary admission judges it as today.
    Ordinary,
    /// The copy translated to its source: the row the canonical store takes
    /// under `id`, with the stored bytes or the visible diff applied to them.
    Source { id: EntityId, row: Vec<u8> },
    /// A ruled hold: the edit never lands as masked or placeholder bytes and
    /// is never applied; its held record is all that is kept (FIX 10598).
    Held(HeldEdit),
}

/// One copy edit held on its ruled cause: the source it would land on, the
/// cause, and the `xxh3_64` of the row the peer wrote, never its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeldEdit {
    pub(crate) source: EntityId,
    pub(crate) cause: RepoProjectionDiffResult,
    pub(crate) edit: u64,
}

impl SyncSecretProjection {
    /// Row `raw`, stored under `id`, as a peer gets it ([`Self::item`]): a
    /// marked snapshot ASSET moves to its copy id, a mismatched body under
    /// that id reads as the sealed-file placeholder, a known copy id carries
    /// its source's current copy, and any other row whose body is a marked
    /// blob's whole bytes keeps its id. A row an unread copy could mark is
    /// [`CopyRow::Sealed`].
    pub(crate) fn project_row(&self, id: &EntityId, raw: &[u8]) -> CopyRow {
        if self.is_empty() || raw.len() < ENTITY_METADATA_HEADER_LEN {
            return CopyRow::Keep;
        }
        let (header, body) = raw.split_at(ENTITY_METADATA_HEADER_LEN);
        match self.item(id, body) {
            ItemCopy::Unmarked => CopyRow::Keep,
            ItemCopy::Copy { key, bytes } => CopyRow::Copy {
                key,
                row: [header, bytes].concat(),
            },
            ItemCopy::Unread { key } => CopyRow::Sealed {
                key,
                row: [header, REPO_OPAQUE_FILE_BYTES].concat(),
            },
        }
    }

    /// Row `submitted`, which a peer wrote under `key`, as the canonical
    /// store takes it. The copy's own bytes are the stored bytes; a changed
    /// body goes through the shipped visible diff against the pinned
    /// original, copy and spans. The submitted header is kept.
    ///
    /// # Errors
    /// The visible diff's own failure.
    pub(crate) fn source_row(&self, key: &EntityId, submitted: &[u8]) -> Result<InboundRow> {
        if self.is_empty() || submitted.len() < ENTITY_METADATA_HEADER_LEN {
            return Ok(InboundRow::Ordinary);
        }
        let (header, body) = submitted.split_at(ENTITY_METADATA_HEADER_LEN);
        let (id, blob) = match self.source_of_copy(key) {
            Some(source) => match self.blob_of_source(&source) {
                Some(blob) => (source, blob),
                // Its copy is unread this pass: the edit cannot be translated,
                // so it is not admitted and stays the peer's pending work.
                None => {
                    return Err(Error::InvariantViolation(
                        "a copy edit whose copy is unread this pass is not admitted",
                    ));
                }
            },
            // A row kept under its own id is a copy only when its body is a
            // copy this pass makes.
            None => match self
                .copy_bodies
                .get(blake3::hash(body).as_bytes())
                .and_then(|hash| self.blobs.get(hash))
            {
                Some(blob) if !self.sources.contains_key(key) => (*key, blob),
                _ => return Ok(InboundRow::Ordinary),
            },
        };
        // The vault no longer holds the source's bytes (an erased store's
        // copies, FIX 10274): no source row to land on, so the edit stays
        // the copy's own row, as any safe row does.
        let Some(stored) = &blob.stored else {
            return Ok(InboundRow::Ordinary);
        };
        Ok(match translate_body(blob, stored, body)? {
            Translated::Body(bytes) => InboundRow::Source {
                id,
                row: [header, bytes.as_slice()].concat(),
            },
            Translated::Held(cause) => InboundRow::Held(HeldEdit {
                source: id,
                cause,
                edit: crate::sync::quarantine::payload_hash(submitted),
            }),
        })
    }
}

enum Translated {
    Body(Vec<u8>),
    Held(RepoProjectionDiffResult),
}

/// `submitted`, a peer's body on `blob`'s copy, over its stored bytes.
fn translate_body(blob: &BlobCopy, stored: &[u8], submitted: &[u8]) -> Result<Translated> {
    if *submitted == *blob.copy {
        return Ok(Translated::Body(stored.to_vec()));
    }
    let copy = match &blob.places {
        Some(places) => RepoProjectedFileCopy::Masked {
            copy: &blob.copy[..],
            places,
        },
        None => RepoProjectedFileCopy::Opaque,
    };
    Ok(match apply_repo_projection_diff(stored, copy, submitted)? {
        RepoProjectionDiffResult::Unchanged => Translated::Body(stored.to_vec()),
        RepoProjectionDiffResult::Applied(bytes) => Translated::Body(bytes),
        held @ (RepoProjectionDiffResult::SealedFileEdited
        | RepoProjectionDiffResult::ProjectionEditConflict) => Translated::Held(held),
    })
}
