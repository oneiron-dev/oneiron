//! A marked repo item's entity document as a sync peer gets it, a peer's
//! edit of it as the source text takes it, and the ids residence reads show
//! a peer (FIX 7608 slice 4, part C).
//!
//! **Copy lineage.** A marked snapshot ASSET whose text moved into an entity
//! document leaves this device only as its copy lineage: a separate document
//! under the copy id, kept here in that id's document rows, written by one
//! author derived from the source, and brought current with the copy of the
//! source's text before every release. A mask may change a text's units, so
//! the lineage never shares an operation with the source (C1 of the s4
//! soundness read). Its disclosure floor names the copy's stamp: a re-mask
//! reaches every peer as state, never as history holding an older copy (C3).
//!
//! **Inbound.** A peer's update sent under the copy id is imported on the
//! lineage. The lineage's new text goes through the shipped visible diff
//! against the source's text and lands as a source text edit, in the one
//! writer that admits it and keeps the peer's operations, before any
//! acknowledgement (C2, C5). A ruled hold (`sealed_file_edited`,
//! `projection_edit_conflict`) lands and keeps nothing, so the peer's
//! acknowledgement covers none of its operations and it keeps the edit
//! queued. An update sent under the source id takes today's path.
//!
//! **Residence.** A peer is shown a marked source by its copy id; a copy id
//! it names is judged as its source.

use std::collections::BTreeMap;

use heed::{RoTxn, RwTxn};
use loro::{ExportMode, LoroDoc, UpdateOptions, VersionVector};

use super::{GENERATION_CONTEXT, SyncSecretProjection, copy_id};
use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncEngineContext};
use crate::origin::secret_projection::edit::{
    RepoProjectedFileCopy, RepoProjectionDiffResult, apply_repo_projection_diff,
};
use crate::origin::secret_projection::index::{RepoIndexCopyKind, RepoIndexMarks};
use crate::origin::secret_projection::types::REPO_OPAQUE_FILE_BYTES;
use crate::ports::{DocumentRow, DocumentRowStore, DocumentSlot, EntityStoreRead};
use crate::secret_custody::KeyPlaces;
use crate::sync::documents::storage;

/// The text root of an entity document.
const BODY: &str = "body";
/// The domain the copy lineage's one author is derived in.
const AUTHOR_CONTEXT: &str = "oneiron.repo-sync-projection.document-author.v1";

/// A marked document's copy lineage, current with its source.
pub(crate) struct DocumentCopy {
    /// The lineage's own id, its rows' slot: the copy id of the document.
    pub(crate) id: EntityId,
    /// The id its frames go under: the copy id for a marked snapshot ASSET,
    /// else the document's own id, as [`super::CopyRow`] keys a row.
    pub(crate) key: EntityId,
    /// The lineage itself.
    pub(crate) doc: LoroDoc,
    /// The copy's stamp fingerprint.
    stamp: [u8; 32],
}

impl DocumentCopy {
    /// The disclosure floor key of this copy for `admission_key`: a new
    /// stamp is a new floor, so the copy reaches every peer as state.
    pub(crate) fn floor_key(&self, admission_key: &[u8]) -> Vec<u8> {
        format!(
            "{}:{}:{}",
            self.id.to_hex(),
            blake3::Hash::from(self.stamp).to_hex(),
            blake3::hash(admission_key).to_hex()
        )
        .into_bytes()
    }
}

/// The copy of one source text this pass makes.
struct TextCopy {
    /// The id its frames go under (see [`DocumentCopy::key`]).
    key: EntityId,
    /// Exactly the text a peer gets.
    copy: String,
    /// The spans `copy` overwrites; `None` for the sealed-file placeholder.
    places: Option<KeyPlaces>,
    /// The stamp fingerprint: source, marks, actual copy bytes, kind, rules.
    stamp: [u8; 32],
}

impl TextCopy {
    /// The sealed-file placeholder under `key`, for a document whose own
    /// copy is unread this pass (FIX 10793): never its stored text.
    fn sealed(key: EntityId) -> Self {
        Self {
            key,
            copy: String::from_utf8_lossy(REPO_OPAQUE_FILE_BYTES).into_owned(),
            places: None,
            stamp: super::UNREAD_STAMP,
        }
    }

    /// Whether this is [`Self::sealed`]: no edit of it can be translated.
    fn unread(&self) -> bool {
        self.stamp == super::UNREAD_STAMP
    }
}

/// The marked blob the document `id` names, and the bytes its copy is made
/// from: a marked snapshot ASSET's text; a known copy id's source blob, as
/// stored here (FIX 10795; none held: the placeholder); any other document
/// whose whole text is a marked blob (FIX 10796). `None` for an unmarked
/// document.
///
/// # Errors
/// A failed copy id derivation.
fn text_bound_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    marks: &RepoIndexMarks,
    id: &EntityId,
    text: &str,
) -> Result<Option<TextBound>> {
    if let Some(hash) = marks.source_of(id) {
        return Ok(Some(TextBound {
            key: copy_id(id)?,
            hash,
            bytes: text.as_bytes().to_vec(),
            own: true,
        }));
    }
    for (source, hash) in marks.marked_sources() {
        if copy_id(&source)? != *id {
            continue;
        }
        // Its exact bytes unread or not held here: the placeholder.
        let stored = vault
            .store
            .port_entity_raw(txn, &source)
            .ok()
            .flatten()
            .and_then(|raw| raw.get(ENTITY_METADATA_HEADER_LEN..).map(<[u8]>::to_vec))
            .filter(|body| blake3::hash(body).as_bytes() == &hash);
        return Ok(Some(TextBound {
            key: *id,
            hash,
            bytes: stored.unwrap_or_default(),
            own: false,
        }));
    }
    let hash = *blake3::hash(text.as_bytes()).as_bytes();
    Ok(marks.is_marked(&hash).then(|| TextBound {
        key: *id,
        hash,
        bytes: text.as_bytes().to_vec(),
        own: true,
    }))
}

/// What [`text_bound_in_txn`] found.
struct TextBound {
    key: EntityId,
    hash: [u8; 32],
    bytes: Vec<u8>,
    /// `bytes` are the document's own text, not its source blob's.
    own: bool,
}

/// The copy of `text`, the document text of `id`; `None` when `id` is no
/// marked repo item ([`text_bound_in_txn`]). Bytes that are not the marked
/// blob read as the sealed-file placeholder (an empty text has nothing to
/// mask). A failure making this document's own copy answers
/// [`TextCopy::sealed`], never its stored text (FIX 10793).
///
/// # Errors
/// A failed copy id derivation.
fn text_copy_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    marks: &RepoIndexMarks,
    id: &EntityId,
    text: &str,
) -> Result<Option<TextCopy>> {
    let Some(bound) = text_bound_in_txn(vault, txn, marks, id, text)? else {
        return Ok(None);
    };
    let key = bound.key;
    match project_text_in_txn(vault, txn, marks, bound) {
        Ok(copy) => Ok(copy),
        Err(error) => {
            tracing::warn!(
                %error,
                "sync: a marked document's copy is unreadable; it leaves sealed"
            );
            Ok(Some(TextCopy::sealed(key)))
        }
    }
}

fn project_text_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    marks: &RepoIndexMarks,
    bound: TextBound,
) -> Result<Option<TextCopy>> {
    let TextBound {
        key,
        hash,
        bytes,
        own,
    } = bound;
    let whole = blake3::hash(&bytes).as_bytes() == &hash;
    let empty = own && bytes.is_empty();
    let input = marks.source_input_in_txn(vault, txn, &hash, bytes)?;
    let Some(stamp) = input.stamp().cloned() else {
        return Ok(None);
    };
    let places = match (whole, stamp.kind) {
        (true, RepoIndexCopyKind::Masked) => marks.copy_places_in_txn(vault, txn, &hash)?,
        _ => None,
    };
    let fingerprint = stamp.fingerprint();
    let (copy, places) = if empty {
        (String::new(), None)
    } else {
        match String::from_utf8(input.into_bytes()) {
            Ok(copy) => (copy, places),
            // A mask that splits a character cannot be text: the placeholder.
            Err(_) => (
                String::from_utf8_lossy(REPO_OPAQUE_FILE_BYTES).into_owned(),
                None,
            ),
        }
    };
    Ok(Some(TextCopy {
        key,
        copy,
        places,
        stamp: fingerprint,
    }))
}

/// The one author of `source`'s copy lineage.
fn author(source: &EntityId) -> u64 {
    let mut material = Vec::with_capacity(2 + 16);
    material.extend_from_slice(&SyncSecretProjection::SCHEMA.to_be_bytes());
    material.extend_from_slice(source.as_bytes());
    let key = blake3::derive_key(AUTHOR_CONTEXT, &material);
    let mut head = [0u8; 8];
    head.copy_from_slice(&key[..8]);
    u64::from_be_bytes(head) >> 1
}

/// The copy lineage stored under `copy`; an empty one before its first
/// release.
fn load_lineage(vault: &Vault, txn: &RoTxn<'_>, copy: EntityId) -> Result<LoroDoc> {
    let doc = LoroDoc::new();
    if let Some(bytes) =
        vault
            .store
            .port_document_row(txn, DocumentSlot::of(copy), DocumentRow::Snapshot)?
    {
        storage::import_complete(&doc, &bytes)?;
    }
    Ok(doc)
}

fn save_lineage(vault: &Vault, txn: &mut RwTxn<'_>, copy: EntityId, doc: &LoroDoc) -> Result<()> {
    let slot = DocumentSlot::of(copy);
    let bytes = doc
        .export(ExportMode::Snapshot)
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportSnapshot, e))?;
    vault.store.port_document_snapshot_put(txn, slot, &bytes)?;
    vault
        .store
        .port_document_state_vector_put(txn, slot, &doc.oplog_vv().encode())
}

/// Bring `lineage`'s text to `copy` as its author; whether it changed.
fn bring_current(lineage: &LoroDoc, source: &EntityId, copy: &str) -> Result<bool> {
    let text = lineage.get_text(BODY);
    if text.to_string() == copy {
        return Ok(false);
    }
    lineage
        .set_peer_id(author(source))
        .map_err(|_| Error::InvariantViolation("document copy author"))?;
    text.update(copy, UpdateOptions::default())
        .map_err(|_| Error::InvariantViolation("document copy diff"))?;
    lineage.commit();
    Ok(true)
}

/// `doc`, the document of `source`, as every sync peer gets it, brought
/// current in `txn`; `None` when `source` is no marked repo item. Its
/// lineage is its own, under its copy id and author, whatever names it
/// ([`text_bound_in_txn`]).
///
/// # Errors
/// A store failure, or a mark that does not decode and names no blob.
/// Nothing falls back to the stored text.
pub(crate) fn document_copy_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    source: EntityId,
    doc: &LoroDoc,
) -> Result<Option<DocumentCopy>> {
    let marks = RepoIndexMarks::read_scoped_in_txn(vault, txn)?;
    if marks.is_empty() {
        return Ok(None);
    }
    let text = doc.get_text(BODY).to_string();
    let Some(copy) = text_copy_in_txn(vault, txn, &marks, &source, &text)? else {
        return Ok(None);
    };
    let id = copy_id(&source)?;
    let lineage = load_lineage(vault, txn, id)?;
    if bring_current(&lineage, &source, &copy.copy)? {
        save_lineage(vault, txn, id, &lineage)?;
    }
    Ok(Some(DocumentCopy {
        id,
        key: copy.key,
        doc: lineage,
        stamp: copy.stamp,
    }))
}

/// A peer's update `bytes` of the copy lineage of `source`'s document
/// (`resident`), landed in one writer: `admit` judges it first, the lineage
/// takes the peer's operations, and its changed text lands on the source
/// text through the visible diff. The source document to keep resident, or
/// `None` for a ruled hold (nothing persists).
///
/// # Errors
/// `admit`'s refusal, an update that does not import whole on the lineage,
/// a store failure, or the visible diff's own failure.
pub(crate) fn import_document_copy<F>(
    vault: &Vault,
    source: EntityId,
    resident: &LoroDoc,
    bytes: &[u8],
    admit: F,
) -> Result<Option<LoroDoc>>
where
    F: FnOnce(&mut RwTxn<'_>) -> Result<()>,
{
    vault.with_write_txn_grouped(|txn| {
        admit(txn)?;
        let marks = RepoIndexMarks::read_scoped_in_txn(vault, txn)?;
        let text = resident.get_text(BODY).to_string();
        let copy = text_copy_in_txn(vault, txn, &marks, &source, &text)?.ok_or(
            Error::InvariantViolation("copy edit of an unmarked document"),
        )?;
        // An unread copy cannot be diffed: the edit is not admitted and
        // stays the peer's pending work (FIX 10793).
        if copy.unread() {
            return Err(Error::InvariantViolation(
                "a copy edit whose copy is unread this pass is not admitted",
            ));
        }
        let id = copy_id(&source)?;
        let lineage = load_lineage(vault, txn, id)?;
        bring_current(&lineage, &source, &copy.copy)?;
        storage::import_complete(&lineage, bytes)?;
        let submitted = lineage.get_text(BODY).to_string();
        let result = if submitted == copy.copy {
            RepoProjectionDiffResult::Unchanged
        } else if copy.copy.is_empty() && text.is_empty() {
            // An empty text holds nothing to mask: the peer's text is the text.
            RepoProjectionDiffResult::Applied(submitted.into_bytes())
        } else {
            let projected = match &copy.places {
                Some(places) => RepoProjectedFileCopy::Masked {
                    copy: copy.copy.as_bytes(),
                    places,
                },
                None => RepoProjectedFileCopy::Opaque,
            };
            apply_repo_projection_diff(text.as_bytes(), projected, submitted.as_bytes())?
        };
        let landed = match result {
            RepoProjectionDiffResult::Unchanged => None,
            RepoProjectionDiffResult::Applied(bytes) => match String::from_utf8(bytes) {
                Ok(text) => Some(text),
                Err(_) => return held(source, &RepoProjectionDiffResult::ProjectionEditConflict),
            },
            cause @ (RepoProjectionDiffResult::SealedFileEdited
            | RepoProjectionDiffResult::ProjectionEditConflict) => return held(source, &cause),
        };
        let staged = LoroDoc::from_snapshot(
            &resident
                .export(ExportMode::Snapshot)
                .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportSnapshot, e))?,
        )
        .map_err(|_| Error::InvariantViolation("document copy source clone"))?;
        if let Some(text) = landed {
            let before = staged.oplog_vv();
            staged
                .get_text(BODY)
                .update(&text, UpdateOptions::default())
                .map_err(|_| Error::InvariantViolation("document copy landing diff"))?;
            staged.commit();
            let update = staged
                .export(ExportMode::updates(&before))
                .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportUpdates, e))?;
            storage::append(vault, txn, source, &update)?;
        }
        save_lineage(vault, txn, id, &lineage)?;
        Ok(Some(staged))
    })
}

fn held(source: EntityId, cause: &RepoProjectionDiffResult) -> Result<Option<LoroDoc>> {
    tracing::warn!(
        source = %source.to_hex(),
        ?cause,
        "sync: a document copy edit is held on its ruled cause; the peer keeps it queued"
    );
    Ok(None)
}

/// The version vector of `source`'s copy lineage: what a peer's update
/// under the copy id is acknowledged with. It proves copy delivery only.
///
/// # Errors
/// A store failure, or a mark that does not decode.
pub fn repo_document_copy_vector(vault: &Vault, source: EntityId) -> Result<Vec<u8>> {
    let txn = vault.store.env.read_txn()?;
    let slot = DocumentSlot::of(copy_id(&source)?);
    Ok(vault
        .store
        .port_document_row(&txn, slot, DocumentRow::StateVector)?
        .unwrap_or_else(|| VersionVector::new().encode()))
}

/// The document `id` names on this device: the marked source a copy id
/// stands for, when that source's row is held here; else `id`. An id held
/// here is no copy id, so it reads no mark (FIX 10793): a source-id update
/// takes today's path.
///
/// # Errors
/// A store failure, or a mark that does not decode and names no blob.
pub fn repo_document_source(vault: &Vault, id: EntityId) -> Result<EntityId> {
    if vault.entity_exists(&id)? {
        return Ok(id);
    }
    let source = RepoCopyAliases::read(vault)?.stored(&id);
    if source == id || !vault.entity_exists(&source)? {
        return Ok(id);
    }
    Ok(source)
}

/// One read's marked repo aliases: the copy id a peer knows each marked
/// source by, and back.
#[derive(Debug, Default)]
pub struct RepoCopyAliases {
    copies: BTreeMap<EntityId, EntityId>,
    sources: BTreeMap<EntityId, EntityId>,
}

impl RepoCopyAliases {
    /// The aliases this vault's marks name now, an unreadable mark's blob
    /// included (FIX 10793).
    ///
    /// # Errors
    /// A store failure, or a mark that does not decode and names no blob.
    pub fn read(vault: &Vault) -> Result<Self> {
        let txn = vault.store.env.read_txn()?;
        Self::read_in_txn(vault, &txn)
    }

    pub(crate) fn read_in_txn(vault: &Vault, txn: &RoTxn<'_>) -> Result<Self> {
        let mut aliases = Self::default();
        for (source, _) in RepoIndexMarks::read_scoped_in_txn(vault, txn)?.marked_sources() {
            let copy = copy_id(&source)?;
            aliases.copies.insert(source, copy);
            aliases.sources.insert(copy, source);
        }
        Ok(aliases)
    }

    /// The id a peer is shown for `id`: its copy id for a marked source.
    #[must_use]
    pub fn shown(&self, id: &EntityId) -> EntityId {
        self.copies.get(id).copied().unwrap_or(*id)
    }

    /// The stored id `id` stands for: a copy id's source, else `id`.
    #[must_use]
    pub fn stored(&self, id: &EntityId) -> EntityId {
        self.sources.get(id).copied().unwrap_or(*id)
    }
}

/// One residence index pass's marked repo copies.
pub(crate) struct IndexCopies(SyncSecretProjection);

impl IndexCopies {
    /// The copies this vault releases now.
    ///
    /// # Errors
    /// A store failure, or a mark that does not decode.
    pub(crate) fn read(vault: &Vault) -> Result<Self> {
        SyncSecretProjection::read(vault).map(Self)
    }

    /// The id row `id`, stored under `key`, is listed by: a marked source's
    /// copy id, else `key`.
    pub(crate) fn shown(&self, id: &EntityId, key: &str) -> String {
        self.0
            .copy_of(id)
            .map_or_else(|| key.to_owned(), |copy| copy.to_hex())
    }

    /// The title of `row`, stored under `id`, taken by `title` from the body
    /// a peer gets: the copy's for a marked item (none for the sealed-file
    /// placeholder), never the raw marked body.
    pub(crate) fn title<F>(&self, id: &EntityId, row: &[u8], title: F) -> Option<String>
    where
        F: Fn(&[u8]) -> Option<String>,
    {
        let (_, released) = self.0.project_row(id, row).released(*id, row.to_vec());
        released.get(ENTITY_METADATA_HEADER_LEN..).and_then(title)
    }
}

/// `frontier`, a residence selection witness, folded with the generation
/// of every marked repo copy this vault releases: a re-mask changes it, so
/// a retained index restarts on its existing revision change.
///
/// # Errors
/// A store failure, or a mark that does not decode.
pub(crate) fn with_copy_generation_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    frontier: [u8; 32],
) -> Result<[u8; 32]> {
    let projection = SyncSecretProjection::read_in_txn(vault, txn)?;
    if projection.is_empty() {
        return Ok(frontier);
    }
    let generation = projection.generation(projection.sources.keys().copied());
    let mut hasher = blake3::Hasher::new_derive_key(GENERATION_CONTEXT);
    hasher.update(&frontier);
    hasher.update(&generation);
    Ok(*hasher.finalize().as_bytes())
}

/// The stored item a residence request's `id` stands for: a copy id is
/// judged as its source. An id held here is no copy id, so it reads no
/// mark (FIX 10793).
///
/// # Errors
/// A store failure, or a mark that does not decode and names no blob.
pub(crate) fn stored_item_in_txn(vault: &Vault, txn: &RoTxn<'_>, id: EntityId) -> Result<EntityId> {
    if vault.store.port_entity_raw(txn, &id)?.is_some() {
        return Ok(id);
    }
    Ok(RepoCopyAliases::read_in_txn(vault, txn)?.stored(&id))
}
