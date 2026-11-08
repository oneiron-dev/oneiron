//! Reads retained revisions from their original generic or common document.

use heed::RoTxn;
use loro::{Frontiers, LoroDoc};

use super::frontier::{FrontierEntry, decode_frontier};
use super::{DOC, FRONTIER, RevisionRef, doc_raw, native, reference, text_fields, write_doc_row};
use crate::EntityId;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::error::{Error, Result};
use crate::store::ManifestDbs;

/// The document namespace that actually retains a selected revision.
pub(super) enum RevisionDocument {
    Common(crate::entity_doc::EntityDoc),
    Generic(LoroDoc),
    Note { doc: LoroDoc, row: RevisionRef },
}

/// The namespace proved for a forked retained revision.
#[derive(Clone, Copy)]
pub(in crate::vault::entity_revision) enum RevisionNamespace {
    Common,
    Generic,
    Note,
}

fn retains_frontier(doc: &LoroDoc, frontier: &Frontiers) -> bool {
    doc.frontiers_to_vv(frontier)
        .is_some_and(|vv| vv.includes_vv(&doc.shallow_since_vv().to_vv()))
}

/// Proves a generic binding without treating a failed fork as membership.
/// The private loaded document may be checked out; its operation log is unchanged.
pub(super) fn generic_binding(
    id: &EntityId,
    doc: &LoroDoc,
    revision: RevisionRef,
    encoded: &[u8],
) -> Result<bool> {
    let FrontierEntry::Document(encoded) = FrontierEntry::decode(encoded)? else {
        return Ok(false);
    };
    let frontier = decode_frontier(encoded)?;
    if !retains_frontier(doc, &frontier) {
        return Ok(false);
    }
    if reference(id, encoded) == revision {
        return Ok(true);
    }
    Ok(reference(id, &generic_raw_at(doc, &frontier)?) == revision)
}

/// A common binding in a mixed ledger is its actual retained causal frontier,
/// never an arbitrary alias or a hash without document membership.
pub(super) fn common_binding(
    id: &EntityId,
    doc: &crate::entity_doc::EntityDoc,
    revision: RevisionRef,
    encoded: &[u8],
) -> Result<bool> {
    let FrontierEntry::Document(encoded) = FrontierEntry::decode(encoded)? else {
        return Ok(false);
    };
    let frontier = decode_frontier(encoded)?;
    Ok(reference(id, encoded) == revision && retains_frontier(&doc.doc, &frontier))
}

pub(super) fn revision_document(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    revision: RevisionRef,
    encoded: &[u8],
) -> Result<RevisionDocument> {
    let document_frontier = match FrontierEntry::decode(encoded)? {
        entry @ FrontierEntry::Note { .. } => {
            let (slot, row, frontier) = entry
                .committed_note(id, revision, encoded)?
                .ok_or(Error::CorruptedIndex("NOTE revision binding"))?;
            // Prove the exact physical envelope too, even when only prose is read.
            physical_revision_raw(store, txn, id, row)?;
            let stored = crate::note::revision::stored_slot_in_txn(store, txn, *id, slot)?
                .ok_or(Error::EntityNotFound)?;
            return Ok(RevisionDocument::Note {
                doc: stored.at(frontier)?,
                row,
            });
        }
        FrontierEntry::PhysicalAlias => {
            let raw = physical_alias_raw(store, txn, id, revision)?;
            let doc = LoroDoc::new();
            write_doc_row(&doc, &raw)?;
            return Ok(RevisionDocument::Generic(doc));
        }
        FrontierEntry::Document(frontier) => frontier,
    };
    let common = crate::entity_doc::record_document(store, txn, id, None)?;
    let generic = DOC
        .get(store, txn, id)?
        .map(|bytes| {
            LoroDoc::from_snapshot(&bytes).map_err(|_| Error::CorruptedIndex("entity document"))
        })
        .transpose()?;
    let mixed = generic.is_some();
    if let Some(doc) = generic {
        if generic_binding(id, &doc, revision, encoded)? {
            return Ok(RevisionDocument::Generic(doc));
        }
        if common.is_none() {
            return Err(Error::CorruptedIndex("retained entity frontier"));
        }
    }
    let doc = common.ok_or(Error::CorruptedIndex("entity document missing"))?;
    // Only a birth without generic history creates lightweight common aliases.
    if mixed && reference(id, document_frontier) != revision {
        return Err(Error::CorruptedIndex("entity frontier reference mismatch"));
    }
    let frontier = decode_frontier(document_frontier)?;
    if !retains_frontier(&doc.doc, &frontier) {
        return Err(
            crate::error::ArtifactError::InvalidEditManifest("unknown or purged frontier").into(),
        );
    }
    let doc = if doc.doc.oplog_frontiers() == frontier {
        doc
    } else {
        doc.fork(document_frontier)?
    };
    Ok(RevisionDocument::Common(doc))
}

pub(in crate::vault::entity_revision) fn fork_revision_with_namespace(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    revision: RevisionRef,
) -> Result<(LoroDoc, RevisionNamespace)> {
    let raw = FRONTIER
        .get(store, txn, &(*id, revision.0))?
        .ok_or(Error::EntityNotFound)?;
    let loaded = match revision_document(store, txn, id, revision, &raw)? {
        RevisionDocument::Common(doc) => return Ok((doc.doc, RevisionNamespace::Common)),
        RevisionDocument::Note { doc, .. } => return Ok((doc, RevisionNamespace::Note)),
        RevisionDocument::Generic(doc) => doc,
    };
    let encoded = match FrontierEntry::decode(&raw)? {
        FrontierEntry::Document(frontier) => frontier,
        FrontierEntry::PhysicalAlias => return Ok((loaded, RevisionNamespace::Generic)),
        FrontierEntry::Note { .. } => unreachable!(),
    };
    let frontier = decode_frontier(encoded)?;
    // A revision at the live frontier is the loaded document itself: no
    // snapshot export and import (FIX 11647).
    let doc = if loaded.oplog_frontiers() == frontier {
        loaded
    } else {
        loaded
            .fork_at(&frontier)
            .map_err(|_| Error::CorruptedIndex("retained entity frontier"))?
    };
    if reference(id, encoded) != revision && reference(id, &doc_raw(&doc)?) != revision {
        return Err(Error::CorruptedIndex("entity frontier reference mismatch"));
    }
    Ok((doc, RevisionNamespace::Generic))
}

/// The record bytes of `id` at `revision`, read on its private loaded document:
/// at the live frontier as loaded, at an older one checked out there, so a read
/// exports and imports no snapshot (FIX 11647). A shallow document, whose
/// checkout may not reach a retained frontier, reads through the fork.
pub(super) fn revision_raw(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    revision: RevisionRef,
) -> Result<Vec<u8>> {
    let raw = FRONTIER
        .get(store, txn, &(*id, revision.0))?
        .ok_or(Error::EntityNotFound)?;
    match revision_document(store, txn, id, revision, &raw)? {
        RevisionDocument::Common(doc) => doc_raw(&doc.doc),
        RevisionDocument::Generic(doc) => generic_revision_raw(id, revision, &raw, &doc),
        RevisionDocument::Note { doc, row } => {
            let raw = physical_revision_raw(store, txn, id, row)?;
            crate::note::revision::row_with_markdown_in_txn(
                store,
                txn,
                &raw,
                doc.get_text("body").to_string(),
            )
        }
    }
}

pub(super) fn generic_revision_raw(
    id: &EntityId,
    revision: RevisionRef,
    encoded: &[u8],
    doc: &LoroDoc,
) -> Result<Vec<u8>> {
    let encoded = match FrontierEntry::decode(encoded)? {
        FrontierEntry::Document(frontier) => frontier,
        FrontierEntry::PhysicalAlias => {
            let raw = doc_raw(doc)?;
            if reference(id, &raw) != revision {
                return Err(Error::CorruptedIndex("NOTE physical alias mismatch"));
            }
            return Ok(raw);
        }
        FrontierEntry::Note { .. } => {
            return Err(Error::CorruptedIndex("generic document frontier kind"));
        }
    };
    let frontier = decode_frontier(encoded)?;
    let bytes = generic_raw_at(doc, &frontier)?;
    if reference(id, encoded) != revision && reference(id, &bytes) != revision {
        return Err(Error::CorruptedIndex("entity frontier reference mismatch"));
    }
    Ok(bytes)
}

/// Retained generic row bytes, lightweight common-document row aliases, and
/// the frontiers of the common document's own retained states. A mixed
/// ledger's non-generic states are document commitments, not row aliases.
/// The common states let a search find one the history walk does not follow,
/// such as an indexed state beside a concurrent head (FIX 10203).
pub(in crate::vault::entity_revision) fn retained_row_sources_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<RetainedRowSources> {
    let generic = DOC
        .get(store, txn, id)?
        .map(|bytes| {
            LoroDoc::from_snapshot(&bytes).map_err(|_| Error::CorruptedIndex("entity document"))
        })
        .transpose()?;
    let mut sources = RetainedRowSources::default();
    for row in FRONTIER.iter_from(store, txn, id.as_bytes())? {
        let ((_, revision), frontier) = row?;
        let revision = RevisionRef(revision);
        let document_frontier = match FrontierEntry::decode(&frontier)? {
            FrontierEntry::Note { .. } => continue,
            FrontierEntry::PhysicalAlias => {
                sources
                    .rows
                    .push(physical_alias_raw(store, txn, id, revision)?);
                continue;
            }
            FrontierEntry::Document(frontier) => frontier,
        };
        if let Some(doc) = generic.as_ref() {
            if generic_binding(id, doc, revision, &frontier)? {
                sources
                    .rows
                    .push(generic_revision_raw(id, revision, &frontier, doc)?);
            } else if reference(id, document_frontier) != revision {
                // A mixed common binding uses its frontier-derived reference.
                return Err(Error::CorruptedIndex("entity frontier reference mismatch"));
            } else {
                sources.common.push(document_frontier.to_vec());
            }
        } else if reference(id, document_frontier) != revision {
            sources.aliases.push((revision, document_frontier.to_vec()));
        } else {
            sources.common.push(document_frontier.to_vec());
        }
    }
    Ok(sources)
}

/// What [`retained_row_sources_in_txn`] finds for one entity.
#[derive(Default)]
pub(in crate::vault::entity_revision) struct RetainedRowSources {
    /// Retained generic rows, as stored.
    pub(in crate::vault::entity_revision) rows: Vec<Vec<u8>>,
    /// Lightweight common aliases: each row revision and the frontier it names.
    pub(in crate::vault::entity_revision) aliases: Vec<(RevisionRef, Vec<u8>)>,
    /// The common document's retained states, by frontier.
    pub(in crate::vault::entity_revision) common: Vec<Vec<u8>>,
}

/// How a retained revision of `id` binds the text it reads (FIX 10203):
/// `None` for a revision whose bytes are a row (no document, or the generic
/// history), else the common document's frontier and whether the revision is
/// a lightweight alias that frontier was born under.
pub(in crate::vault::entity_revision) fn common_binding_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    revision: RevisionRef,
) -> Result<Option<(Vec<u8>, bool)>> {
    if !crate::entity_doc::has_record_head(store, txn, id)? {
        return Ok(None);
    }
    let encoded = FRONTIER
        .get(store, txn, &(*id, revision.0))?
        .ok_or(Error::EntityNotFound)?;
    match revision_document(store, txn, id, revision, &encoded)? {
        RevisionDocument::Generic(_) | RevisionDocument::Note { .. } => Ok(None),
        RevisionDocument::Common(_) => {
            let FrontierEntry::Document(frontier) = FrontierEntry::decode(&encoded)? else {
                return Err(Error::CorruptedIndex("common document frontier kind"));
            };
            let alias = reference(id, frontier) != revision;
            Ok(Some((frontier.to_vec(), alias)))
        }
    }
}

fn generic_raw_at(doc: &LoroDoc, frontier: &Frontiers) -> Result<Vec<u8>> {
    if doc.state_frontiers() != *frontier {
        if doc.is_shallow() {
            let fork = doc
                .fork_at(frontier)
                .map_err(|_| Error::CorruptedIndex("retained entity frontier"))?;
            return doc_raw(&fork);
        }
        doc.checkout(frontier)
            .map_err(|_| Error::CorruptedIndex("retained entity frontier"))?;
    }
    doc_raw(doc)
}

fn physical_alias_raw(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    revision: RevisionRef,
) -> Result<Vec<u8>> {
    let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)?
        .ok_or(Error::EntityNotFound)?;
    if reference(id, &raw) != revision
        || crate::batch::EntityMetadataHeader::parse(&raw)
            .is_none_or(|header| header.entity_type != crate::registry::ENTITY_TYPE_NOTE)
    {
        return Err(Error::CorruptedIndex("NOTE physical alias mismatch"));
    }
    Ok(raw)
}

pub(super) fn physical_revision_raw(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    revision: RevisionRef,
) -> Result<Vec<u8>> {
    let encoded = FRONTIER
        .get(store, txn, &(*id, revision.0))?
        .ok_or(Error::EntityNotFound)?;
    match FrontierEntry::decode(&encoded)? {
        FrontierEntry::PhysicalAlias => physical_alias_raw(store, txn, id, revision),
        FrontierEntry::Document(_) => {
            let bytes = DOC
                .get(store, txn, id)?
                .ok_or(Error::CorruptedIndex("NOTE physical envelope missing"))?;
            let doc = LoroDoc::from_snapshot(&bytes)
                .map_err(|_| Error::CorruptedIndex("entity document"))?;
            generic_revision_raw(id, revision, &encoded, &doc)
        }
        FrontierEntry::Note { .. } => Err(Error::CorruptedIndex("NOTE physical envelope kind")),
    }
}

pub(in crate::vault::entity_revision) fn citation_live_doc(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    namespace: RevisionNamespace,
) -> Result<LoroDoc> {
    match namespace {
        RevisionNamespace::Common => crate::entity_doc::record_document(store, txn, id, None)?
            .map(|doc| doc.doc)
            .ok_or(Error::CorruptedIndex("common entity document missing")),
        RevisionNamespace::Note => {
            let current = super::state(store, txn, id)?.ok_or(Error::EntityNotFound)?;
            let encoded = super::native::active_note(store, txn, id, current.live)?
                .ok_or(Error::EntityNotFound)?;
            let RevisionDocument::Note { doc, .. } =
                revision_document(store, txn, id, current.live, &encoded)?
            else {
                return Err(Error::CorruptedIndex("NOTE revision namespace"));
            };
            Ok(doc)
        }
        RevisionNamespace::Generic => {
            let bytes = DOC
                .get(store, txn, id)?
                .ok_or(Error::CorruptedIndex("entity document missing"))?;
            LoroDoc::from_snapshot(&bytes).map_err(|_| Error::CorruptedIndex("entity document"))
        }
    }
}

pub(in crate::vault::entity_revision) fn revision_text_fields(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    revision: RevisionRef,
    body: &[u8],
) -> Result<Vec<(String, String)>> {
    if let Some(encoded) = native::active_note(store, txn, id, revision)? {
        let RevisionDocument::Note { doc, .. } =
            revision_document(store, txn, id, revision, &encoded)?
        else {
            return Err(Error::CorruptedIndex("NOTE revision document"));
        };
        return Ok(vec![(
            "markdown".to_owned(),
            doc.get_text("body").to_string(),
        )]);
    }
    if let Some(field) = crate::entity_doc::pointer_field_in(store, txn, id)? {
        let frontier = FRONTIER
            .get(store, txn, &(*id, revision.0))?
            .ok_or(Error::EntityNotFound)?;
        return match revision_document(store, txn, id, revision, &frontier)? {
            RevisionDocument::Common(doc) => crate::entity_doc::document_text_fields(&doc, &field),
            RevisionDocument::Note { doc, .. } => Ok(vec![(
                "markdown".to_owned(),
                doc.get_text("body").to_string(),
            )]),
            RevisionDocument::Generic(doc) => {
                let raw = generic_revision_raw(id, revision, &frontier, &doc)?;
                Ok(text_fields(
                    raw.get(ENTITY_METADATA_HEADER_LEN..)
                        .ok_or(Error::CorruptedIndex("entity revision header"))?,
                ))
            }
        };
    }
    Ok(text_fields(body))
}
