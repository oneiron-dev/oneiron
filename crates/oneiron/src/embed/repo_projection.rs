//! What an embedder receives for an ASSET holding repo bytes (FIX 7608
//! slice 3, ASK 1): the masked copy, for a local embedder as for a remote
//! one or its fallback, never the stored bytes.
//!
//! An inline media envelope is projected by its INNER bytes, joined to a
//! marked blob by their own whole BLAKE3: never the envelope's hash, a
//! chunk's, or the hash string the envelope records. A text item reads its
//! copy. A masked image or audio item keeps its kind with its copied bytes;
//! an opaque one is the sealed-file placeholder, a text item for a space
//! that embeds text and no item for a space that embeds only media: no
//! placeholder bytes reach an image or audio decoder, and no vector of the
//! stored media is made. A stored record never becomes ineligible: every
//! text that embedded before still embeds, as its copy.
//!
//! A mask change drops the item's stale vectors in every space and queues
//! its text work again ([`requeue_repo_embedding_in_txn`]); the passes that
//! fill them read the copy anew.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

mod derived;
mod session;
pub use derived::{RepoDerivedIndexReport, RepoDerivedIndexTextAuthor};
pub(super) use derived::{
    RepoDerivedOwner, RepoDerivedReady, copy_in, delete_in_txn, is_storage_error, pending_in,
    put_pending_in_txn, put_ready_in_txn,
};
pub(crate) use derived::{
    finalize_repo_derived_index_copies_in_txn, repo_derived_batch, repo_derived_fields,
    repo_derived_index_text_in, retire_repo_derived_index_copies_in_txn,
};
pub(crate) use session::apply_ops_session_projected;

use super::PendingEmbeddingPayload;
use super::media::{MediaEmbedReport, PendingMedia, TEXT_MEDIA_TYPE, asset_document_in};
use super::space::{InputKind, delete_media_vectors_in_txn};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::origin::secret_projection::index::{
    RepoIndexMarks, masked_repo_index_input_in_txn, opaque_index_text,
};
use crate::ports::{EntityStoreRead, RetrievalIndexInventory};
use crate::registry::ENTITY_TYPE_ASSET;
use crate::store::ManifestDbs;

/// The payload an ASSET record embeds as: its text item's copy, read under
/// the marks `txn` reads now. `None` exactly when the stored record embeds
/// nothing.
///
/// # Errors
/// A store failure, or a mark that does not decode.
pub(super) fn asset_payload_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    body: &[u8],
) -> Result<Option<PendingEmbeddingPayload>> {
    // FIX 9949: an ASSET's bytes are the blob it holds by reference.
    let Some(text) = super::media::asset_text(body, |blob| {
        Ok(vault
            .store
            .port_entity_record(txn, blob)?
            .map(|blob| blob.body))
    })?
    else {
        return Ok(None);
    };
    let copy = masked_repo_index_input_in_txn(vault, txn, text.into_bytes())?.into_text();
    Ok(Some(PendingEmbeddingPayload::SummaryText(copy)))
}

/// [`super::embeddable_payload`] for the pending worker, ASSETs read as
/// their copy ([`asset_payload_in_txn`]).
///
/// # Errors
/// As [`asset_payload_in_txn`].
pub(super) fn pending_payload_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    entity_type: u8,
    body: &[u8],
) -> Result<Option<PendingEmbeddingPayload>> {
    if entity_type == ENTITY_TYPE_ASSET {
        return asset_payload_in_txn(vault, txn, body);
    }
    Ok(super::embeddable_payload(entity_type, body))
}

/// [`asset_document_in`] as a model receives it: the item's copy when its
/// inner bytes are a marked blob's.
///
/// # Errors
/// As [`asset_document_in`], or a mark that does not decode.
pub(super) fn asset_document_projected_in(
    vault: &Vault,
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: EntityId,
    kinds: &BTreeSet<InputKind>,
    report: &mut MediaEmbedReport,
) -> Result<Option<PendingMedia>> {
    let Some(document) = asset_document_in(store, txn, id, kinds, report)? else {
        return Ok(None);
    };
    let marks = RepoIndexMarks::read_in_txn(vault, txn)?;
    if marks.is_empty() {
        return Ok(Some(document));
    }
    let PendingMedia {
        id,
        kind,
        media_type,
        bytes,
        text_hash,
        learned_at,
        source_rows,
    } = document;
    let input = marks.input_in_txn(vault, txn, bytes)?;
    if !input.opaque() {
        return Ok(Some(PendingMedia {
            id,
            kind,
            media_type,
            bytes: input.into_bytes(),
            text_hash,
            learned_at,
            source_rows,
        }));
    }
    if kind == InputKind::Text || kinds.contains(&InputKind::Text) {
        return Ok(Some(PendingMedia {
            id,
            kind: InputKind::Text,
            media_type: TEXT_MEDIA_TYPE.to_owned(),
            bytes: opaque_index_text().into_bytes(),
            text_hash,
            learned_at,
            source_rows,
        }));
    }
    report.unbound += 1;
    Ok(None)
}

/// The image or audio item a media query names, as a model receives it
/// ([`super::space_probe`]'s query read, projected); `None` when it is gone,
/// holds neither, or its copy is the placeholder, which no media encoder
/// reads.
///
/// # Errors
/// As [`asset_document_projected_in`].
pub(super) fn media_query_projected_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: EntityId,
) -> Result<Option<PendingMedia>> {
    asset_document_projected_in(
        vault,
        &vault.store,
        txn,
        id,
        &BTreeSet::from([InputKind::Image, InputKind::Audio]),
        &mut MediaEmbedReport::default(),
    )
}

/// The whole BLAKE3 of exactly the bytes a model receives now for ASSET
/// `id`'s media item, as `store` reads it ([`asset_document_projected_in`]);
/// `None` when it holds none. A writer landing a media answer compares it
/// with the bytes it sent: an answer of an older copy does not land.
///
/// # Errors
/// A store failure, or a mark that does not decode.
pub(super) fn media_copy_hash_in(
    vault: &Vault,
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<[u8; 32]>> {
    let Some(row) = store.port_entity_record(txn, id)? else {
        return Ok(None);
    };
    // FIX 9949: an ASSET's bytes are the blob it holds by reference.
    let Some((_, bytes)) = crate::memory::asset_media_in(&row.body, |blob| {
        Ok(store.port_entity_record(txn, blob)?.map(|blob| blob.body))
    })?
    else {
        return Ok(None);
    };
    let input = masked_repo_index_input_in_txn(vault, txn, bytes)?;
    // A copy's stamp names exactly its bytes' hash; the placeholder text is
    // the placeholder's bytes.
    Ok(Some(match input.stamp() {
        Some(stamp) => stamp.copy_blake3,
        None => *blake3::hash(&input.into_bytes()).as_bytes(),
    }))
}

/// The media bytes an ASSET body names, the bytes a mark joins it by: the
/// blob it holds by reference (FIX 9949), `read` reading one stored row's
/// body by id in the caller's own snapshot. `None` for a body naming none.
///
/// # Errors
/// A failure of `read`.
pub(crate) fn repo_media_bytes(
    body: &[u8],
    read: impl FnOnce(&EntityId) -> Result<Option<Vec<u8>>>,
) -> Result<Option<Vec<u8>>> {
    Ok(crate::memory::asset_media_in(body, read)?.map(|(_, bytes)| bytes))
}

/// What a mask change on the blobs `sources` reaches beyond the records
/// `entities` that hold them (FIX 7608 S3F), in `wtxn`, the writer that
/// changed the marks, each with the same affected set: the texts a model
/// derived from them (FIX 10405), every room's cached media vectors of them
/// (FIX 10407), and the probe queries written from them (FIX 10408). Each
/// step fails only with `wtxn`'s storage error; any other is logged and
/// left to the next derivation, as the slice-3 invalidation is.
///
/// # Errors
/// A storage error of `wtxn`.
pub(crate) fn refresh_repo_derived_projection_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    marks: &RepoIndexMarks,
    sources: &BTreeSet<[u8; 32]>,
    entities: &BTreeSet<EntityId>,
) -> Result<()> {
    let derived = derived::refresh_repo_derived_index_copies_in_txn(vault, wtxn, marks, entities);
    let mut affected = kept(derived)?.unwrap_or_default();
    affected.extend(entities.iter().copied());
    let rooms =
        session::refresh_repo_session_index_projection_in_txn(vault, wtxn, sources, &affected);
    kept(rooms)?;
    let probes =
        super::space_probe::refresh_repo_probe_queries_in_txn(vault, wtxn, marks, &affected);
    kept(probes)?;
    Ok(())
}

/// `result`, a storage error passed on and any other logged.
fn kept<T>(result: Result<T>) -> Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if is_storage_error(&error) => Err(error),
        Err(error) => {
            tracing::warn!(error = %error, "repo index copies are left for their next derivation");
            Ok(None)
        }
    }
}

/// Every ASSET whose media bytes, the blob it holds read in `txn`, are by
/// their own whole BLAKE3 a blob in `sources`: the envelope copies a mask
/// change reaches.
///
/// # Errors
/// A store failure.
pub(crate) fn repo_envelope_copies_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    sources: &BTreeSet<[u8; 32]>,
) -> Result<Vec<EntityId>> {
    let mut copies = Vec::new();
    if sources.is_empty() {
        return Ok(copies);
    }
    for row in vault.store.port_entity_records(txn)? {
        let (id, row) = row?;
        if row.entity_type != ENTITY_TYPE_ASSET {
            continue;
        }
        let bytes = repo_media_bytes(&row.body, |blob| {
            Ok(vault
                .store
                .port_entity_record(txn, blob)?
                .map(|blob| blob.body))
        })?;
        if bytes.is_some_and(|bytes| sources.contains(blake3::hash(&bytes).as_bytes())) {
            copies.push(id);
        }
    }
    Ok(copies)
}

/// Drops record `entity`'s media vectors in every space, whose passes embed
/// its copy again, and, when it holds or is owed a text vector, queues its
/// text work anew: an answer leased before the change no longer lands.
///
/// # Errors
/// A store failure.
pub(crate) fn requeue_repo_embedding_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    delete_media_vectors_in_txn(&vault.store, wtxn, entity)?;
    let Some(record) = vault.store.port_entity_record(wtxn, entity)? else {
        return Ok(());
    };
    if !super::eligibility::is_embeddable_in_txn(vault, wtxn, record.entity_type, &record.body)? {
        return Ok(());
    }
    let owed = vault
        .store
        .has_current_pending_embedding_in_txn(wtxn, entity)?
        || vault
            .store
            .port_vector_with_raw(wtxn, entity, |_| Ok(()))?
            .is_some();
    if !owed {
        return Ok(());
    }
    vault
        .store
        .mark_pending_embedding(wtxn, entity, &record.body)?;
    #[cfg(feature = "sync")]
    {
        super::clear_pending_embedding_lease_if_any(vault, wtxn, entity)?;
        crate::sync::queue::delete_embed_job_in_txn(&vault.store, wtxn, entity)?;
        crate::sync::queue::push_embed_job_in_txn(
            &vault.store,
            wtxn,
            entity,
            super::EMBED_PRIORITY_BACKFILL,
        )?;
    }
    Ok(())
}
