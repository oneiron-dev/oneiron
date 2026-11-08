//! A canonical restore's successor taking the place of the document held
//! here (FIX 3553, FIX 3464; Engine 11-06 20:16, A), on either plane that
//! carries one: a MESSAGE's window head (`carried`) and a record's sync text
//! (`sync`).
//!
//! The successor's history replaces the one held here. Operations held here
//! past the version it replaces stay as a pending rewrite of the successor
//! for the owner to land or drop, never lost ([`park_held_edits_in_txn`]).
//! Each pin binds to its twin: the successor's version with the same text,
//! at the same span and quote, as a restore binds it. A history the
//! successor would lose stands, as a restore and the purge door refuse to
//! drop it: one a hold keeps, on the record or its pad's world (deferred,
//! for a later merge), and one with a fork, receipt or purge receipt, a live
//! citation floor, a pin with no twin, or a purge floor the successor does
//! not keep.

use super::doc_actor::DocActor;
use super::document::BODY;
use super::forks::{
    ENTITY_DOC_FORK, ENTITY_DOC_FORK_SNAPSHOT, ENTITY_DOC_PROPOSAL_BUNDLE, ForkRecord,
    ProposalBundle,
};
use super::pins::{CitationPin, ENTITY_DOC_PIN, ENTITY_DOC_PURGE_RECEIPT};
use super::side_keys::HexPair;
use super::storage::Head;
use super::{EntityDoc, ForkStatus};
use crate::error::{ArtifactError, Error, Result};
use crate::ports::{DocumentRow, DocumentRowStore, DocumentSlot, EntityStoreRead};
use crate::side_table::HexId;
use crate::{EntityId, Vault};
use heed::RwTxn;
use loro::{Frontiers, ID, UpdateOptions, VersionVector};

/// Why a history held here stands against its successor.
pub(super) enum Stands {
    /// A hold keeps it; the successor waits for a later merge.
    Deferred(&'static str),
    /// The successor would drop what it holds.
    Refused(&'static str),
}

/// Whether `incoming`, the successor of the history `replaced` names, can
/// take the place of `old`, `entity`'s document here: each pin's twin in
/// it, or why the history here stands. Reads only.
pub(super) fn twins_in(
    vault: &Vault,
    txn: &RwTxn<'_>,
    entity: &EntityId,
    old: &EntityDoc,
    incoming: &EntityDoc,
    replaced: &VersionVector,
) -> Result<std::result::Result<Vec<CitationPin>, Stands>> {
    let store = &vault.store;
    let pad_held = match EntityStoreRead::port_entity_raw(store, txn, entity)? {
        Some(raw) => crate::world_keys::held_pad_world_in_txn(store, txn, &raw)?,
        None => false,
    };
    if pad_held || crate::store::legal_hold::held_in_txn(store, txn, entity.as_bytes())? {
        return Ok(Err(Stands::Deferred(
            "a hold or selected storage-only restriction keeps its history",
        )));
    }
    let rows = format!("{}:", entity.to_hex()).into_bytes();
    if !super::forks::all_forks(store, txn, entity)?.is_empty()
        || !super::forks::receipts(store, txn, entity)?.is_empty()
        || !ENTITY_DOC_PURGE_RECEIPT
            .scan_from(store, txn, &rows)?
            .is_empty()
        || super::citation_floor::has_live_citer(store, txn, entity)?
    {
        return Ok(Err(Stands::Refused(
            "the history here holds rows its successor does not carry",
        )));
    }
    if old.doc.is_shallow() && !incoming.doc.is_shallow() {
        return Ok(Err(Stands::Refused("a purge here is not the successor's")));
    }
    let mut pins = Vec::new();
    for (_, pin) in ENTITY_DOC_PIN.scan_from(store, txn, &rows)? {
        let Some(twin) = twin_in(entity, old, incoming, &pin, replaced)? else {
            return Ok(Err(Stands::Refused(
                "a pin here has no twin in its successor",
            )));
        };
        pins.push(twin);
    }
    Ok(Ok(pins))
}

/// Completes the place `incoming` took under `head`, its history persisted:
/// its purge floor row, the citation floors of citers gone with the old
/// history, each pin bound to its twin `pins`, the operations `old` held
/// past `replaced`, parked, and the sync plane's pending frames of the old
/// history, retired.
#[allow(
    clippy::too_many_arguments,
    reason = "one adoption's parts, read once by twins_in"
)]
pub(super) fn complete_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    head: &Head,
    old: &EntityDoc,
    incoming: &EntityDoc,
    replaced: &VersionVector,
    pins: &[CitationPin],
) -> Result<()> {
    let store = &vault.store;
    let slot = DocumentSlot::from_hex(&head.document)?;
    if incoming.doc.is_shallow() {
        store.port_document_shallow_since_put(
            txn,
            slot,
            &incoming.doc.shallow_since_vv().encode(),
        )?;
    } else {
        store.port_document_rows_delete(txn, slot, &[DocumentRow::ShallowSince])?;
    }
    super::citation_floor::erase_in_txn(store, txn, entity)?;
    for pin in pins {
        let citation = EntityId::from_hex(&pin.citation)?;
        ENTITY_DOC_PIN.put(store, txn, &HexPair(HexId(*entity), HexId(citation)), pin)?;
    }
    if !replaced.includes_vv(&old.doc.oplog_vv()) {
        park_held_edits_in_txn(vault, txn, entity, head, incoming, old)?;
    }
    // The sync plane's pending frames are of the history that went.
    #[cfg(feature = "sync")]
    crate::sync::documents::retire_journal_in_txn(vault, txn, *entity)?;
    Ok(())
}

/// `pin`, a pin of `old`, bound to its twin in `doc`, the successor of the
/// history `replaced` names (FIX 3464): the newest version of `doc` whose
/// text is the text of the version `pin` quotes, at the same span, where it
/// reads the same quote. None where `pin` quotes a version past `replaced`,
/// does not resolve, or `doc` holds no such version.
fn twin_in(
    entity: &EntityId,
    old: &EntityDoc,
    doc: &EntityDoc,
    pin: &CitationPin,
    replaced: &VersionVector,
) -> Result<Option<CitationPin>> {
    if !pin.within(replaced) {
        return Ok(None);
    }
    let Ok(origin) = old.fork(&pin.anchor.frontier) else {
        return Ok(None);
    };
    let Ok((start, end)) = super::verbs::resolve(&origin, *entity, &pin.anchor) else {
        return Ok(None);
    };
    let text = origin.text();
    let mut versions = vec![doc.doc.oplog_frontiers()];
    doc.doc
        .travel_change_ancestors(&doc.doc.oplog_frontiers().to_vec(), &mut |meta| {
            let last = i32::try_from(meta.len).map_or(meta.id.counter, |len| {
                meta.id.counter.saturating_add(len.saturating_sub(1))
            });
            versions.push(Frontiers::from_id(ID::new(meta.id.peer, last)));
            std::ops::ControlFlow::Continue(())
        })
        .map_err(|_| Error::CorruptedIndex("successor document history"))?;
    for version in versions {
        let Ok(candidate) = doc.fork(&version.encode()) else {
            continue;
        };
        if candidate.text() != text {
            continue;
        }
        let Ok(anchor) = super::verbs::make_anchor(&candidate, *entity, start, end) else {
            continue;
        };
        if anchor.quote == pin.anchor.quote && anchor.hash == pin.anchor.hash {
            return Ok(Some(CitationPin {
                anchor,
                ..pin.clone()
            }));
        }
    }
    Ok(None)
}

/// Parks `old`'s text and metadata, which hold operations past the version
/// the successor `doc` replaces, as a pending rewrite of `doc` at its head,
/// for the owner to land or drop (Engine 11-06 20:16): a proposal of its own
/// that names no one, as the edits' authors are in the history it replaced.
/// Nothing is parked where they leave the successor's value as it is.
fn park_held_edits_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    message: &EntityId,
    head: &Head,
    doc: &EntityDoc,
    old: &EntityDoc,
) -> Result<()> {
    let text = old.text();
    let metadata = old.metadata_bytes()?;
    if text == doc.text() && metadata == doc.metadata_bytes()? {
        return Ok(());
    }
    let base = doc.doc.oplog_frontiers().encode();
    let fork = doc.fork(&base)?;
    fork.doc
        .get_text(BODY)
        .update(&text, UpdateOptions::default())
        .map_err(|_| Error::Artifact(ArtifactError::InvalidEditManifest("held edits fork")))?;
    EntityDoc::replace_metadata(&fork.doc, &metadata)?;
    fork.doc.commit();
    let at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    let record = ForkRecord {
        fork: EntityId::now().to_hex(),
        proposal: EntityId::now().to_hex(),
        entity: message.to_hex(),
        parent_document: head.document.clone(),
        base: base.clone(),
        actor: DocActor::Erased,
        opened_at: at,
        rewrite: true,
        status: ForkStatus::Pending,
        read_refs: Vec::new(),
        keep: None,
        delta_receipt: None,
    };
    ENTITY_DOC_FORK.put(&vault.store, txn, &record.fork, &record)?;
    ENTITY_DOC_FORK_SNAPSHOT.put(
        &vault.store,
        txn,
        &record.fork,
        &fork.shallow_snapshot(&base)?,
    )?;
    let proposal = record.proposal.clone();
    ENTITY_DOC_PROPOSAL_BUNDLE.put(
        &vault.store,
        txn,
        &proposal,
        &ProposalBundle {
            proposal: proposal.clone(),
            author: DocActor::Erased,
            forks: vec![record],
            settled: false,
            opener_lineage: Vec::new(),
        },
    )?;
    Ok(())
}
