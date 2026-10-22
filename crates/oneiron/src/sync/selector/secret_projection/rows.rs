//! One entity row as a peer gets it, and one incoming copy row as the
//! canonical store takes it.

use super::{BlobCopy, SyncSecretProjection};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::Result;
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
}

/// What an incoming row on a copy becomes canonically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InboundRow {
    /// Not a copy: the ordinary admission judges it as today.
    Ordinary,
    /// The copy translated to its source: the row the canonical store takes
    /// under `id`, with the stored bytes or the visible diff applied to them.
    Source { id: EntityId, row: Vec<u8> },
    /// A ruled hold: the edit stays the peer's pending work, never lands as
    /// masked or placeholder bytes, and is never acknowledged as landed.
    Held {
        id: EntityId,
        cause: RepoProjectionDiffResult,
    },
}

impl SyncSecretProjection {
    /// Row `raw`, stored under `id`, as a peer gets it. A marked snapshot
    /// ASSET moves to its copy id; a mismatched body under that id (one the
    /// marks do not prove) reads as the sealed-file placeholder. Any other
    /// row whose body is a marked blob's whole bytes keeps its id.
    pub(crate) fn project_row(&self, id: &EntityId, raw: &[u8]) -> CopyRow {
        if self.is_empty() || raw.len() < ENTITY_METADATA_HEADER_LEN {
            return CopyRow::Keep;
        }
        let (header, body) = raw.split_at(ENTITY_METADATA_HEADER_LEN);
        let hash = *blake3::hash(body).as_bytes();
        if let Some(blob) = self.blob_of_source(id) {
            let copy: &[u8] = if self.sources.get(id) == Some(&hash) {
                &blob.copy
            } else {
                REPO_OPAQUE_FILE_BYTES
            };
            return CopyRow::Copy {
                key: blob.id.copy,
                row: [header, copy].concat(),
            };
        }
        match self.blobs.get(&hash) {
            Some(blob) => CopyRow::Copy {
                key: *id,
                row: [header, blob.copy.as_slice()].concat(),
            },
            None => CopyRow::Keep,
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
                None => return Ok(InboundRow::Ordinary),
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
            Translated::Held(cause) => InboundRow::Held { id, cause },
        })
    }
}

enum Translated {
    Body(Vec<u8>),
    Held(RepoProjectionDiffResult),
}

/// `submitted`, a peer's body on `blob`'s copy, over its stored bytes.
fn translate_body(blob: &BlobCopy, stored: &[u8], submitted: &[u8]) -> Result<Translated> {
    if submitted == blob.copy.as_slice() {
        return Ok(Translated::Body(stored.to_vec()));
    }
    let copy = match &blob.places {
        Some(places) => RepoProjectedFileCopy::Masked {
            copy: &blob.copy,
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
