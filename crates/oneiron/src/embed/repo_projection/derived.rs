//! What the index holds for a text a model derived from a marked repo blob
//! (FIX 7608 S3F, FIX 10405; CALL DERIVED-TEXT-COPY).
//!
//! A caption or transcript (ASSET_TEXT) any of whose sources a mark covers
//! ([`repo_derived_index_sources_in`]) is indexed only as a safe copy: the
//! sealed-file placeholder while its copy is pending, then the text a model
//! derives again from the sources' masked copies, and only while the proof
//! it was derived under is current. Its old words are never masked by
//! offsets and never a fallback. The caption itself, its document and its
//! history stay exact, and the owner reads them as before; only the text
//! index, its phonetic codes and its vector read the copy.
//!
//! The copy is made pending, and the index published again, in the writer
//! that changes the marks ([`refresh_repo_derived_index_copies_in_txn`]) and
//! in every batch that births a text, edges it to a source, or texts or
//! vectors it ([`finalize_repo_derived_index_copies_in_txn`]), so a text
//! written after the mark is found too. The pass in [`worker`] derives the
//! copy outside every writer and lands it only under the same proof.
//!
//! A text no edge links to a source, whose own words are a marked blob's
//! whole bytes, indexes that blob's copy, joined by its own BLAKE3 as every
//! other index input is; a mark change finds it by its content (FIX 10406).

mod storage;
mod worker;

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};

pub(crate) use self::storage::{
    RepoDerivedCopyState, RepoDerivedOwner, RepoDerivedReady, copy_in, delete_in_txn, pending_in,
    put_pending_in_txn, put_ready_in_txn,
};
pub use self::worker::{RepoDerivedIndexReport, RepoDerivedIndexTextAuthor};
use crate::Vault;
use crate::batch::{BatchOp, apply_ops};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::origin::secret_projection::index::{
    RepoIndexMarks, bind_envelope_sources_in_txn, opaque_index_text, repo_derived_dependents_in,
    repo_derived_index_sources_in,
};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead, RetrievalIndexInventory};
use crate::registry::ENTITY_TYPE_ASSET_TEXT;
use crate::store::{ManifestDbs, Store};

/// The field a derived text is born indexed under.
const DERIVED_TEXT_FIELD: &str = "text";

/// The text an index reads for record `entity`, as `view` holds it (CALL
/// DERIVED-TEXT-COPY): `None` when it is no text a model derived from a
/// marked blob, which indexes as it always has; the sealed-file placeholder
/// while its safe copy is pending or was derived under another proof; else
/// that safe copy.
///
/// # Errors
/// A store failure.
pub(crate) fn repo_derived_index_text_in(
    vault: &Vault,
    view: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    marks: &RepoIndexMarks,
    entity: &EntityId,
) -> Result<Option<String>> {
    let sources = match repo_derived_index_sources_in(vault, view, txn, marks, entity) {
        Ok(Some(sources)) => sources,
        Ok(None) => return Ok(None),
        Err(error) if is_storage_error(&error) => return Err(error),
        // A source's copy cannot be made: the text reads the placeholder,
        // never its words, until a pass can.
        Err(error) => {
            tracing::warn!(error = %error, "a derived text indexes the placeholder");
            return Ok(Some(opaque_index_text()));
        }
    };
    let proof = sources.proof();
    let ready = copy_in(&vault.store, txn, RepoDerivedOwner::Text(*entity))?
        .and_then(|row| row.ready_under(&proof).map(|ready| ready.safe_text.clone()));
    Ok(Some(ready.unwrap_or_else(opaque_index_text)))
}

/// `fields` as an index reads a derived text's, `text` its copy: the first
/// field holds the copy, every other the placeholder; a text indexed under
/// no field reads the copy under its born field. Every field stays.
pub(crate) fn repo_derived_fields(
    fields: Vec<(String, String)>,
    text: String,
) -> Vec<(String, String)> {
    if fields.is_empty() {
        return vec![(DERIVED_TEXT_FIELD.to_owned(), text)];
    }
    let mut text = Some(text);
    fields
        .into_iter()
        .map(|(name, _)| (name, text.take().unwrap_or_else(opaque_index_text)))
        .collect()
}

/// Every text a mask change on `roots` (the marked blobs' records) reaches
/// through `DerivedFrom` edges, each made pending unless its ready copy
/// still holds, and its index published again as its copy, in `wtxn`, the
/// writer that changed the marks. A root that is itself a text (one whose
/// own words are a marked blob's, FIX 10406) is published again too.
/// Returns every record reached, for the room and probe invalidators.
///
/// # Errors
/// A storage error of `wtxn`, or the batch door's.
pub(crate) fn refresh_repo_derived_index_copies_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    marks: &RepoIndexMarks,
    roots: &BTreeSet<EntityId>,
) -> Result<BTreeSet<EntityId>> {
    let dependents = repo_derived_dependents_in(&vault.store, wtxn, roots)?;
    for entity in roots.iter().chain(&dependents) {
        if is_derived_text(&vault.store, wtxn, entity)? {
            refresh_one_in_txn(vault, wtxn, Some(marks), entity, None)?;
        }
    }
    Ok(dependents)
}

/// What one batch may give a derived text's index: the ASSET_TEXTs it
/// puts, the text end of each `DerivedFrom` edge it writes, and the records
/// it texts (with the fields it texts each under) or vectors.
#[derive(Debug, Default)]
pub(crate) struct RepoDerivedBatch {
    texts: BTreeSet<EntityId>,
    fields: BTreeMap<EntityId, Vec<String>>,
    vectors: BTreeSet<EntityId>,
}

/// The records `ops` may give a derived text's index, read before the
/// batch applies them.
pub(crate) fn repo_derived_batch(ops: &[BatchOp]) -> RepoDerivedBatch {
    let mut batch = RepoDerivedBatch::default();
    for op in ops {
        match op {
            BatchOp::Put {
                id, entity_type, ..
            } if *entity_type == ENTITY_TYPE_ASSET_TEXT => {
                batch.texts.insert(*id);
            }
            BatchOp::Edge { src, kind, .. }
            | BatchOp::PublicEdgeWithCreatedAt { src, kind, .. }
            | BatchOp::EdgeWithCreatedAt { src, kind, .. }
                if *kind == EdgeKind::DerivedFrom =>
            {
                batch.texts.insert(*src);
            }
            BatchOp::Text { id, fields } => {
                batch
                    .fields
                    .insert(*id, fields.iter().map(|(name, _)| name.clone()).collect());
            }
            BatchOp::Vector { id, .. } => {
                batch.vectors.insert(*id);
            }
            _ => {}
        }
    }
    batch
}

/// After a batch applied in `wtxn` and before it commits: each derived text
/// it reached with a marked source is made pending (unless its ready copy
/// still holds), its text index published again as its copy, and a vector
/// the batch supplied for it dropped, before any of it is visible. A text
/// with no marked source keeps what the batch wrote. Never a refusal: a
/// mark that cannot be read leaves a text the batch edged to a source
/// pending, on the placeholder.
///
/// # Errors
/// A storage error of `wtxn`, or the batch door's.
pub(crate) fn finalize_repo_derived_index_copies_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    batch: RepoDerivedBatch,
) -> Result<()> {
    let RepoDerivedBatch {
        texts: born,
        fields,
        vectors,
    } = batch;
    let mut texts = BTreeSet::new();
    for id in born.iter().chain(fields.keys()).chain(&vectors) {
        if !texts.contains(id) && is_derived_text(&vault.store, wtxn, id)? {
            texts.insert(*id);
        }
    }
    if texts.is_empty() {
        return Ok(());
    }
    let marks = match RepoIndexMarks::read_scoped_in_txn(vault, wtxn) {
        Ok(marks) if marks.is_empty() => return Ok(()),
        Ok(marks) => Some(marks),
        Err(error) if is_storage_error(&error) => return Err(error),
        Err(error) => {
            tracing::warn!(error = %error, "derived texts index the placeholder");
            None
        }
    };
    for entity in &texts {
        let named = fields.get(entity).map(|names| {
            names
                .iter()
                .map(|name| (name.clone(), String::new()))
                .collect()
        });
        refresh_one_in_txn(vault, wtxn, marks.as_ref(), entity, named)?;
    }
    Ok(())
}

/// An erase of `id`, a cache cleanup only: its own copy goes, and each
/// ready copy derived from it is pending again, directly or through what
/// derives from it (FIX 10889: a caption of an ASSET derived from `id`),
/// read by its `DerivedFrom` edges before the erase takes them. No source
/// or text is deleted for a cache, and a restored copy is served only
/// under its current proof.
///
/// # Errors
/// A store failure.
pub(crate) fn retire_repo_derived_index_copies_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    delete_in_txn(store, wtxn, RepoDerivedOwner::Text(*id))?;
    let dependents = repo_derived_dependents_in(store, wtxn, &BTreeSet::from([*id]))?;
    for (owner, row) in storage::copies_in(store, wtxn)? {
        let reached = ready_reached(&row.state, id)
            || matches!(&owner, RepoDerivedOwner::Text(text) if dependents.contains(text));
        if reached && matches!(row.state, RepoDerivedCopyState::Ready(_)) {
            put_pending_in_txn(store, wtxn, owner, None)?;
        }
    }
    Ok(())
}

/// Whether a copy in `state` is ready with `id` among its direct sources.
fn ready_reached(state: &RepoDerivedCopyState, id: &EntityId) -> bool {
    matches!(state, RepoDerivedCopyState::Ready(ready) if ready.sources.contains(id.as_bytes()))
}

/// Text `entity`'s copy made pending (unless it is ready under its current
/// proof), and its index published again: under `marks`, or, when they
/// could not be read, on the placeholder if it is edged to any source. A
/// text with no marked source is published again only when its own words
/// are a marked blob's (FIX 10406).
fn refresh_one_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    marks: Option<&RepoIndexMarks>,
    entity: &EntityId,
    fields: Option<Vec<(String, String)>>,
) -> Result<()> {
    let owner = RepoDerivedOwner::Text(*entity);
    let Some(marks) = marks else {
        if vault
            .store
            .port_edge_peers(wtxn, entity, EdgeDirection::Out, EdgeKind::DerivedFrom)?
            .next()
            .is_none()
        {
            return Ok(());
        }
        put_pending_in_txn(&vault.store, wtxn, owner, None)?;
        let fields = repo_derived_fields(fields.unwrap_or_default(), opaque_index_text());
        return publish_text_in_txn(vault, wtxn, entity, fields);
    };
    match repo_derived_index_sources_in(vault, &vault.store, wtxn, marks, entity) {
        Ok(Some(sources)) => {
            bind_envelope_sources_in_txn(&vault.store, wtxn, &sources)?;
            put_pending_in_txn(&vault.store, wtxn, owner, Some(&sources.proof()))?;
        }
        Ok(None) if !own_words_marked(&vault.store, wtxn, marks, entity)? => return Ok(()),
        Ok(None) => {}
        Err(error) if is_storage_error(&error) => return Err(error),
        Err(_) => put_pending_in_txn(&vault.store, wtxn, owner, None)?,
    }
    republish_in_txn(vault, wtxn, marks, entity, fields)
}

/// Publishes derived text `entity`'s index again as it reads now: a record
/// with revision state through its revision door, which drops its vector
/// and owes a refill; any other as its fields (or its born field), its
/// vector dropped. A text with no marked source is indexed as its words
/// again, or as the copy of the marked blob they are (FIX 10406).
pub(super) fn republish_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    marks: &RepoIndexMarks,
    entity: &EntityId,
    fields: Option<Vec<(String, String)>>,
) -> Result<()> {
    if crate::vault::entity_revision::refresh_repo_revision_projection_in_txn(
        vault, wtxn, marks, entity,
    )? {
        return Ok(());
    }
    let fields = match repo_derived_index_text_in(vault, &vault.store, wtxn, marks, entity)? {
        Some(text) => repo_derived_fields(fields.unwrap_or_default(), text),
        None => {
            let Some(record) = vault.store.port_entity_record(wtxn, entity)? else {
                return Ok(());
            };
            let Some(text) = derived_text_words(&record.body) else {
                return Ok(());
            };
            let text = match marks.text_in_txn(vault, wtxn, text) {
                Ok(text) => text,
                Err(error) if is_storage_error(&error) => return Err(error),
                Err(error) => {
                    tracing::warn!(error = %error, "a derived text indexes the placeholder");
                    opaque_index_text()
                }
            };
            vec![(DERIVED_TEXT_FIELD.to_owned(), text)]
        }
    };
    publish_text_in_txn(vault, wtxn, entity, fields)
}

/// Indexes `fields` as record `entity`'s text through the batch door, a
/// vector it holds dropped first.
fn publish_text_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    entity: &EntityId,
    fields: Vec<(String, String)>,
) -> Result<()> {
    if vault
        .store
        .port_vector_with_raw(wtxn, entity, |_| Ok(()))?
        .is_some()
    {
        crate::vault::entity_revision::drop_vector_state(vault, wtxn, entity)?;
    }
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        wtxn,
        vec![BatchOp::Text {
            id: *entity,
            fields,
        }],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        false,
        false,
    )
}

/// The words a derived text's body holds: a map's `text`, else the body as
/// UTF-8.
pub(super) fn derived_text_words(body: &[u8]) -> Option<String> {
    if let Ok(rmpv::Value::Map(entries)) = rmpv::decode::read_value(&mut &body[..]) {
        return entries.iter().find_map(|(key, value)| {
            (key.as_str() == Some(DERIVED_TEXT_FIELD))
                .then(|| value.as_str().map(str::to_owned))
                .flatten()
        });
    }
    String::from_utf8(body.to_vec())
        .ok()
        .filter(|text| !text.trim().is_empty())
}

/// Whether derived text `entity`'s own words are a marked blob's whole
/// bytes (FIX 10406).
fn own_words_marked(
    store: &Store,
    txn: &RoTxn<'_>,
    marks: &RepoIndexMarks,
    entity: &EntityId,
) -> Result<bool> {
    let Some(record) = store.port_entity_record(txn, entity)? else {
        return Ok(false);
    };
    Ok(derived_text_words(&record.body)
        .is_some_and(|text| marks.is_marked(blake3::hash(text.as_bytes()).as_bytes())))
}

/// Whether record `id` is an ASSET_TEXT `store` holds.
fn is_derived_text(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
    Ok(store
        .port_entity_record(txn, id)?
        .is_some_and(|record| record.entity_type == ENTITY_TYPE_ASSET_TEXT))
}

/// Whether `error` is a transaction's own storage failure.
pub(crate) fn is_storage_error(error: &Error) -> bool {
    matches!(error, Error::Storage(_) | Error::Io(_) | Error::MapFull)
}
