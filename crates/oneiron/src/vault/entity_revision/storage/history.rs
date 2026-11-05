//! Reads retained revisions from their original generic or common document.

use heed::RoTxn;
use loro::{Frontiers, LoroDoc};

use super::{DOC, FRONTIER, RevisionRef, doc_raw, reference};
use crate::EntityId;
use crate::error::{Error, Result};
use crate::store::ManifestDbs;

/// The document namespace that actually retains a selected revision.
pub(super) enum RevisionDocument {
    Common(crate::entity_doc::EntityDoc),
    Generic(LoroDoc),
}

/// The namespace proved for a forked retained revision.
pub(in crate::vault::entity_revision) enum RevisionNamespace {
    Common,
    Generic,
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
    let frontier =
        Frontiers::decode(encoded).map_err(|_| Error::CorruptedIndex("entity frontier"))?;
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
    let frontier =
        Frontiers::decode(encoded).map_err(|_| Error::CorruptedIndex("entity frontier"))?;
    Ok(reference(id, encoded) == revision && retains_frontier(&doc.doc, &frontier))
}

pub(super) fn revision_document(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    revision: RevisionRef,
    encoded: &[u8],
) -> Result<RevisionDocument> {
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
    if mixed && reference(id, encoded) != revision {
        return Err(Error::CorruptedIndex("entity frontier reference mismatch"));
    }
    let frontier =
        Frontiers::decode(encoded).map_err(|_| Error::CorruptedIndex("entity frontier"))?;
    if !retains_frontier(&doc.doc, &frontier) {
        return Err(
            crate::error::ArtifactError::InvalidEditManifest("unknown or purged frontier").into(),
        );
    }
    let doc = if doc.doc.oplog_frontiers() == frontier {
        doc
    } else {
        doc.fork(encoded)?
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
        RevisionDocument::Generic(doc) => doc,
    };
    let frontier = Frontiers::decode(&raw).map_err(|_| Error::CorruptedIndex("entity frontier"))?;
    // A revision at the live frontier is the loaded document itself: no
    // snapshot export and import (FIX 11647).
    let doc = if loaded.oplog_frontiers() == frontier {
        loaded
    } else {
        loaded
            .fork_at(&frontier)
            .map_err(|_| Error::CorruptedIndex("retained entity frontier"))?
    };
    if reference(id, &raw) != revision && reference(id, &doc_raw(&doc)?) != revision {
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
    }
}

pub(super) fn generic_revision_raw(
    id: &EntityId,
    revision: RevisionRef,
    encoded: &[u8],
    doc: &LoroDoc,
) -> Result<Vec<u8>> {
    let frontier =
        Frontiers::decode(encoded).map_err(|_| Error::CorruptedIndex("entity frontier"))?;
    let bytes = generic_raw_at(doc, &frontier)?;
    if reference(id, encoded) != revision && reference(id, &bytes) != revision {
        return Err(Error::CorruptedIndex("entity frontier reference mismatch"));
    }
    Ok(bytes)
}

/// Retained generic row bytes and lightweight common-document row aliases.
/// A mixed ledger's non-generic states are document commitments, not row aliases.
pub(in crate::vault::entity_revision) fn retained_row_sources_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<(Vec<Vec<u8>>, Vec<(RevisionRef, Vec<u8>)>)> {
    let generic = DOC
        .get(store, txn, id)?
        .map(|bytes| {
            LoroDoc::from_snapshot(&bytes).map_err(|_| Error::CorruptedIndex("entity document"))
        })
        .transpose()?;
    let mut rows = Vec::new();
    let mut aliases = Vec::new();
    for row in FRONTIER.iter_from(store, txn, id.as_bytes())? {
        let ((_, revision), frontier) = row?;
        let revision = RevisionRef(revision);
        if let Some(doc) = generic.as_ref() {
            if generic_binding(id, doc, revision, &frontier)? {
                rows.push(generic_revision_raw(id, revision, &frontier, doc)?);
            } else if reference(id, &frontier) != revision {
                // A mixed common binding uses its frontier-derived reference.
                return Err(Error::CorruptedIndex("entity frontier reference mismatch"));
            }
        } else if reference(id, &frontier) != revision {
            aliases.push((revision, frontier));
        }
    }
    Ok((rows, aliases))
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
