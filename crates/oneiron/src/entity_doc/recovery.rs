//! Canonical recovery for generic EntityDoc owners: the current value, and the
//! causal state its forks, pins, receipts and purges name, carried by value.

use std::collections::BTreeMap;

use super::document::{BODY, decode_frontier};
use super::forks::{
    ENTITY_DOC_FORK, ENTITY_DOC_FORK_SNAPSHOT, ENTITY_DOC_PROPOSAL_BUNDLE, ENTITY_DOC_RECEIPT,
    ForkRecord, ProposalBundle, TextReceipt,
};
use super::pins::{CitationPin, ENTITY_DOC_PIN, ENTITY_DOC_PURGE_RECEIPT, PurgeReceipt};
use super::side_keys::HexPair;
use super::{EntityDoc, ForkStatus, SettleVerb, storage};
use crate::error::{ArtifactError, Error};
use crate::ports::{DocumentRow, DocumentRowStore, DocumentSlot};
use crate::recovery::{
    CanonicalDocumentFork, CanonicalDocumentPin, CanonicalDocumentPurge, CanonicalDocumentReceipt,
    CanonicalEntityDocument, CanonicalEntityDocumentHistory, CanonicalForkStatus,
    CanonicalSettleVerb,
};
use crate::side_table::HexId;
use crate::store::Store;
use crate::{EntityId, Result, Vault};
use heed::{RoTxn, RwTxn};
use loro::{ExportMode, Frontiers, UpdateOptions, VersionVector};

fn invalid(reason: &'static str) -> crate::Error {
    ArtifactError::InvalidRecoveryArtifact(reason).into()
}

/// Meta key every replayed version writes, so a version whose text equals
/// its parent's still owns an operation and stays a version of its own.
const RECOVERED_VERSION: &str = "entity_doc_recovered_version";

fn raw(hex: &str) -> Result<[u8; 16]> {
    Ok(*EntityId::from_hex(hex)?.as_bytes())
}

fn hex(bytes: [u8; 16]) -> Result<String> {
    Ok(EntityId::from_bytes(bytes)?.to_hex())
}

fn prefix(entity: &EntityId) -> Vec<u8> {
    format!("{}:", entity.to_hex()).into_bytes()
}

pub(crate) fn capture(
    vault: &Vault,
    txn: &RoTxn<'_>,
    bytes: [u8; 16],
) -> Result<Option<CanonicalEntityDocument>> {
    let entity = EntityId::from_bytes(bytes)?;
    if !storage::has_record_head(&vault.store, txn, &entity)? {
        return Ok(None);
    }
    let head = storage::head(&vault.store, txn, &entity)?;
    let doc = storage::load(&vault.store, txn, &head)?;
    Ok(Some(CanonicalEntityDocument {
        entity_id: bytes,
        document_id: raw(&head.document)?,
        field: match head.field {
            storage::TextField::Utf8Body => None,
            storage::TextField::MapField(field) => Some(field),
        },
        text: doc.text(),
        metadata: doc.metadata_bytes()?,
        record_fields: doc.record_fields()?,
        birth_actor: raw(&doc.birth().actor)?,
        birth_at: doc.birth().at,
        history: history(&vault.store, txn, &entity, &doc)?,
    }))
}

/// The retained versions one capture names, one per version vector.
#[derive(Default)]
struct Versions {
    frontiers: Vec<Frontiers>,
    vvs: Vec<VersionVector>,
}

impl Versions {
    /// The version at `frontier`, or None where the document no longer
    /// retains it (a purge dropped it).
    fn find(&mut self, doc: &EntityDoc, frontier: &Frontiers) -> Option<usize> {
        let vv = doc.doc.frontiers_to_vv(frontier)?;
        if !vv.includes_vv(&doc.doc.shallow_since_vv().to_vv()) {
            return None;
        }
        if let Some(known) = self.vvs.iter().position(|known| known == &vv) {
            return Some(known);
        }
        self.frontiers.push(frontier.clone());
        self.vvs.push(vv);
        Some(self.vvs.len() - 1)
    }

    fn require(&mut self, doc: &EntityDoc, frontier: &[u8]) -> Result<usize> {
        self.find(doc, &decode_frontier(frontier)?).ok_or(invalid(
            "entity document names a version it no longer retains",
        ))
    }
}

/// A fork row before its versions take their canonical indices.
struct ForkAt {
    record: ForkRecord,
    base: Option<usize>,
    output: Option<(String, BTreeMap<String, Vec<u8>>)>,
    index: u16,
    len: u16,
    settled: bool,
}

/// The causal rows of `entity`, by value; None when it has none, so that
/// a plain document stays its current value alone.
fn history(
    store: &Store,
    txn: &RoTxn<'_>,
    entity: &EntityId,
    doc: &EntityDoc,
) -> Result<Option<CanonicalEntityDocumentHistory>> {
    let pins: Vec<CitationPin> = ENTITY_DOC_PIN
        .scan_from(store, txn, &prefix(entity))?
        .into_iter()
        .map(|(_, pin)| pin)
        .collect();
    let receipts = super::forks::receipts(store, txn, entity)?;
    let fork_rows = super::forks::all_forks(store, txn, entity)?;
    let purges: Vec<PurgeReceipt> = ENTITY_DOC_PURGE_RECEIPT
        .scan_from(store, txn, &prefix(entity))?
        .into_iter()
        .map(|(_, purge)| purge)
        .collect();
    let shallow = doc.doc.is_shallow();
    if !shallow
        && pins.is_empty()
        && receipts.is_empty()
        && fork_rows.is_empty()
        && purges.is_empty()
    {
        return Ok(None);
    }
    let mut versions = Versions::default();
    let head = versions
        .find(doc, &doc.doc.oplog_frontiers())
        .ok_or(Error::InvariantViolation(
            "live head outside retained history",
        ))?;
    if shallow {
        versions
            .find(doc, &doc.doc.shallow_since_frontiers())
            .ok_or(Error::InvariantViolation(
                "purge floor outside retained history",
            ))?;
    }
    let mut pin_rows = Vec::with_capacity(pins.len());
    for pin in pins {
        let at = versions.require(doc, &pin.anchor.frontier)?;
        let origin = doc.fork(&pin.anchor.frontier)?;
        let (start, end) = super::verbs::resolve(&origin, *entity, &pin.anchor)?;
        let quote: String = origin
            .text()
            .chars()
            .skip(start)
            .take(end - start)
            .collect();
        if quote != pin.anchor.quote {
            return Err(invalid("entity document pin no longer quotes its version"));
        }
        pin_rows.push((pin, at, start, end));
    }
    let mut receipt_rows = Vec::with_capacity(receipts.len());
    for receipt in receipts {
        let before = versions.require(doc, &receipt.before)?;
        let after = versions.require(doc, &receipt.after)?;
        receipt_rows.push((receipt, before, after));
    }
    let mut forks = Vec::with_capacity(fork_rows.len());
    for record in fork_rows {
        let pending = record.status == ForkStatus::Pending;
        // A pending fork's base is protected from purge; a settled one's may
        // have gone with the purged history.
        let base = if pending {
            Some(versions.require(doc, &record.base)?)
        } else {
            versions.find(doc, &decode_frontier(&record.base)?)
        };
        let output = if pending {
            let bytes = ENTITY_DOC_FORK_SNAPSHOT
                .get(store, txn, &record.fork)?
                .ok_or(invalid("entity document pending fork lost its output"))?;
            let fork = EntityDoc::from_snapshot(&bytes)?;
            Some((fork.text(), fork.metadata_bytes()?))
        } else {
            None
        };
        let bundle = super::forks::read_bundle(store, txn, &EntityId::from_hex(&record.proposal)?)?;
        let index = bundle
            .forks
            .iter()
            .position(|member| member.fork == record.fork)
            .ok_or(Error::CorruptedIndex("fork absent from proposal"))?;
        forks.push(ForkAt {
            record,
            base,
            output,
            index: u16::try_from(index).map_err(|_| invalid("entity document proposal size"))?,
            len: u16::try_from(bundle.forks.len())
                .map_err(|_| invalid("entity document proposal size"))?,
            settled: bundle.settled,
        });
    }
    let mut purge_rows = Vec::with_capacity(purges.len());
    for purge in purges {
        let requested = versions.require(doc, &purge.requested)?;
        let applied = versions.require(doc, &purge.applied)?;
        purge_rows.push((purge, requested, applied));
    }

    let mut texts = Vec::with_capacity(versions.frontiers.len());
    let mut metadata = Vec::with_capacity(versions.frontiers.len());
    for frontier in &versions.frontiers {
        let version = doc.fork(&frontier.encode())?;
        texts.push(version.text());
        metadata.push(version.metadata_bytes()?);
    }
    let parents = hasse(&versions.vvs);
    let order = canonical_order(&parents, &texts, &metadata)?;
    if order[head] != texts.len() - 1 {
        return Err(Error::InvariantViolation(
            "live head is not the last version",
        ));
    }
    let mut by_index = vec![0; order.len()];
    for (node, &index) in order.iter().enumerate() {
        by_index[index] = node;
    }
    let mut carried = Vec::with_capacity(by_index.len());
    for &node in &by_index {
        let mut mapped: Vec<u32> = parents[node].iter().map(|&p| order[p] as u32).collect();
        mapped.sort_unstable();
        let first = mapped
            .first()
            .map_or("", |&p| texts[by_index[p as usize]].as_str());
        let mut version = CanonicalEntityDocumentHistory::splice(first, &texts[node])?;
        version.parents = mapped;
        version.metadata = metadata[node].clone();
        carried.push(version);
    }
    let at = |node: usize| order[node] as u32;

    let mut pins: Vec<CanonicalDocumentPin> = pin_rows
        .into_iter()
        .map(|(pin, node, start, end)| {
            Ok(CanonicalDocumentPin {
                citation: raw(&pin.citation)?,
                document: raw(&pin.document)?,
                actor: raw(&pin.actor)?,
                version: at(node),
                start: u32::try_from(start).map_err(|_| invalid("entity document pin span"))?,
                end: u32::try_from(end).map_err(|_| invalid("entity document pin span"))?,
                quote: pin.anchor.quote,
                hash: pin.anchor.hash,
            })
        })
        .collect::<Result<_>>()?;
    pins.sort_by_key(|pin| pin.citation);
    let mut receipts: Vec<CanonicalDocumentReceipt> = receipt_rows
        .into_iter()
        .map(|(receipt, before, after)| {
            Ok(CanonicalDocumentReceipt {
                receipt: raw(&receipt.receipt)?,
                proposal: raw(&receipt.proposal)?,
                fork: raw(&receipt.fork)?,
                actor: raw(&receipt.actor)?,
                verb: match receipt.verb {
                    SettleVerb::Merge => CanonicalSettleVerb::Merge,
                    SettleVerb::Switch => CanonicalSettleVerb::Switch,
                    SettleVerb::Reject => CanonicalSettleVerb::Reject,
                },
                at: receipt.at,
                before: at(before),
                after: at(after),
            })
        })
        .collect::<Result<_>>()?;
    receipts.sort_by_key(|receipt| receipt.receipt);
    let mut forks: Vec<CanonicalDocumentFork> = forks
        .into_iter()
        .map(|fork| {
            Ok(CanonicalDocumentFork {
                fork: raw(&fork.record.fork)?,
                proposal: raw(&fork.record.proposal)?,
                parent_document: raw(&fork.record.parent_document)?,
                actor: raw(&fork.record.actor)?,
                opened_at: fork.record.opened_at,
                rewrite: fork.record.rewrite,
                status: match fork.record.status {
                    ForkStatus::Pending => CanonicalForkStatus::Pending,
                    ForkStatus::Merged => CanonicalForkStatus::Merged,
                    ForkStatus::Switched => CanonicalForkStatus::Switched,
                    ForkStatus::Rejected => CanonicalForkStatus::Rejected,
                },
                base: fork.base.map(at),
                output: fork.output.as_ref().map(|(text, _)| text.clone()),
                output_metadata: fork.output.map(|(_, metadata)| metadata),
                proposal_index: fork.index,
                proposal_len: fork.len,
                proposal_settled: fork.settled,
            })
        })
        .collect::<Result<_>>()?;
    forks.sort_by_key(|fork| fork.fork);
    let mut purges: Vec<CanonicalDocumentPurge> = purge_rows
        .into_iter()
        .map(|(purge, requested, applied)| {
            Ok(CanonicalDocumentPurge {
                receipt: raw(&purge.receipt)?,
                document: raw(&purge.document)?,
                actor: raw(&purge.actor)?,
                requested: at(requested),
                applied: at(applied),
                at: purge.at,
                live_text_hash: purge.live_text_hash,
            })
        })
        .collect::<Result<_>>()?;
    purges.sort_by_key(|purge| purge.receipt);
    Ok(Some(CanonicalEntityDocumentHistory {
        versions: carried,
        shallow,
        pins,
        receipts,
        forks,
        purges,
    }))
}

/// Each version's direct predecessors among the captured versions: the
/// maximal ones its version vector includes. A strictly later version holds
/// strictly more operations, so walking down by size meets every cover first.
fn hasse(vvs: &[VersionVector]) -> Vec<Vec<usize>> {
    let size = |vv: &VersionVector| vv.values().map(|&end| i64::from(end)).sum::<i64>();
    let mut by_size: Vec<usize> = (0..vvs.len()).collect();
    by_size.sort_by_key(|&node| size(&vvs[node]));
    let mut below = vec![vec![false; vvs.len()]; vvs.len()];
    let mut parents = vec![Vec::new(); vvs.len()];
    for (rank, &node) in by_size.iter().enumerate() {
        let mut covered = vec![false; vvs.len()];
        for &earlier in by_size[..rank].iter().rev() {
            if covered[earlier] || !vvs[node].includes_vv(&vvs[earlier]) {
                continue;
            }
            parents[node].push(earlier);
            covered[earlier] = true;
            for (other, &held) in below[earlier].iter().enumerate() {
                covered[other] |= held;
            }
        }
        let mut reach = vec![false; vvs.len()];
        for &parent in &parents[node] {
            reach[parent] = true;
            for (other, &held) in below[parent].iter().enumerate() {
                reach[other] |= held;
            }
        }
        below[node] = reach;
    }
    parents
}

/// The canonical index of every version: a topological order that takes,
/// among the ready versions, the least by (parent indices, text). The same
/// causal shape and texts give the same order on every capture, including
/// the recapture of a replayed document.
fn canonical_order(
    parents: &[Vec<usize>],
    texts: &[String],
    metadata: &[BTreeMap<String, Vec<u8>>],
) -> Result<Vec<usize>> {
    let mut order = vec![usize::MAX; parents.len()];
    for index in 0..parents.len() {
        let mut best: Option<(Vec<usize>, usize)> = None;
        let mut tied = false;
        for node in 0..parents.len() {
            if order[node] != usize::MAX || parents[node].iter().any(|&p| order[p] == usize::MAX) {
                continue;
            }
            let mut key: Vec<usize> = parents[node].iter().map(|&p| order[p]).collect();
            key.sort_unstable();
            let ordering = best.as_ref().map(|(known, other)| {
                (&key, &texts[node], &metadata[node]).cmp(&(
                    known,
                    &texts[*other],
                    &metadata[*other],
                ))
            });
            match ordering {
                None | Some(std::cmp::Ordering::Less) => {
                    best = Some((key, node));
                    tied = false;
                }
                Some(std::cmp::Ordering::Equal) => tied = true,
                Some(std::cmp::Ordering::Greater) => {}
            }
        }
        if tied {
            return Err(invalid("entity document versions are indistinguishable"));
        }
        let (_, node) = best.ok_or(Error::InvariantViolation("cyclic document versions"))?;
        order[node] = index;
    }
    Ok(order)
}

pub(crate) fn restore(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    row: &CanonicalEntityDocument,
) -> Result<()> {
    let store = &vault.store;
    let entity = EntityId::from_bytes(row.entity_id)?;
    let document_id = EntityId::from_bytes(row.document_id)?;
    let document = document_id.to_hex();
    // An existing head keeps its updates until `persist` below replaces them
    // with the recovered snapshot: it reads the intact document first, so
    // recovering the same state owes the turn no tag pass.
    let existing = storage::ENTITY_DOC_HEAD.get(store, txn, &HexId(entity))?;
    if let Some(old) = &existing {
        if old.document != document {
            return Err(invalid(
                "entity document recovery conflicts with existing head",
            ));
        }
        // A live document that already holds this state keeps its history
        // and incarnation untouched, so every frontier cited in it still
        // resolves.
        if holds(vault, txn, row)? {
            return Ok(());
        }
    }
    refuse_loss(store, txn, &entity, row)?;
    // The rebuild keeps no old operation and takes a fresh incarnation, and
    // `persist` replaces whatever history is stored, even without a head: a
    // live citer's frontier would no longer resolve. Refuse while one holds a
    // floor; the floors of citers gone, deleted or stale go with the history.
    if super::citation_floor::has_live_citer(store, txn, &entity)? {
        return Err(invalid("entity document recovery would drop cited history"));
    }
    super::citation_floor::erase_in_txn(store, txn, &entity)?;
    super::forks::erase_forks(store, txn, &entity)?;
    ENTITY_DOC_RECEIPT.delete_from(store, txn, &prefix(&entity))?;
    ENTITY_DOC_PIN.delete_from(store, txn, &prefix(&entity))?;
    ENTITY_DOC_PURGE_RECEIPT.delete_from(store, txn, &prefix(&entity))?;
    let birth_actor = EntityId::from_bytes(row.birth_actor)?;
    let mut head = storage::Head {
        entity: entity.to_hex(),
        incarnation: EntityId::now().to_hex(),
        document,
        field: field_of(row),
        generation: 0,
        pending: 0,
    };
    let slot = DocumentSlot::from_hex(&head.document)?;
    match &row.history {
        None => {
            let doc = EntityDoc::rebuild_value(entity, &row.text, birth_actor, row.birth_at)?;
            EntityDoc::replace_metadata(&doc.doc, &row.metadata)?;
            EntityDoc::set_record_fields(&doc.doc, &row.record_fields)?;
            doc.doc.commit();
            storage::persist(vault, txn, &entity, &mut head, &doc, None)?;
            store.port_document_rows_delete(txn, slot, &[DocumentRow::ShallowSince])?;
        }
        Some(history) => {
            let (doc, frontiers) = replay(entity, row, history)?;
            storage::persist(vault, txn, &entity, &mut head, &doc, None)?;
            if history.shallow {
                store.port_document_shallow_since_put(
                    txn,
                    slot,
                    &doc.doc.shallow_since_vv().encode(),
                )?;
            } else {
                store.port_document_rows_delete(txn, slot, &[DocumentRow::ShallowSince])?;
            }
            bind_rows(store, txn, &entity, history, &doc, &frontiers)?;
        }
    }
    // With no head the text could not be read, so a MESSAGE or TURN whose
    // text this restores owes its turn a tag pass (ARCH-0036), a vector
    // (ARCH-0004) and a sieve read.
    if existing.is_none()
        && let Some(entity_type) = crate::tagging::text_entity_type_in_txn(vault, txn, &entity)?
    {
        crate::tagging::mark_on_publication_in_txn(vault, txn, &entity, entity_type)?;
        crate::embed::mark_on_publication_in_txn(vault, txn, &entity, entity_type)?;
        crate::dreamer_wake::mark_on_publication_in_txn(&vault.store, txn, &entity)?;
    }
    Ok(())
}

/// Whether the live document already is `row`: its recapture is the row. A
/// document that does not load (corrupt) is not, and is rebuilt; a storage
/// failure is still an error.
fn holds(vault: &Vault, txn: &RoTxn<'_>, row: &CanonicalEntityDocument) -> Result<bool> {
    match capture(vault, txn, row.entity_id) {
        Ok(live) => Ok(live.as_ref() == Some(row)),
        Err(error @ (Error::Storage(_) | Error::MapFull)) => Err(error),
        Err(_) => Ok(false),
    }
}

/// A restore replaces the document's causal rows with the artifact's. It
/// never undoes an owner purge the artifact does not carry, which would bring
/// the purged history back, nor drops a citation pin it does not carry.
fn refuse_loss(
    store: &Store,
    txn: &RoTxn<'_>,
    entity: &EntityId,
    row: &CanonicalEntityDocument,
) -> Result<()> {
    let history = row.history.as_ref();
    for (_, purge) in ENTITY_DOC_PURGE_RECEIPT.scan_from(store, txn, &prefix(entity))? {
        let receipt = raw(&purge.receipt)?;
        if !history.is_some_and(|h| h.purges.iter().any(|carried| carried.receipt == receipt)) {
            return Err(invalid(
                "entity document recovery would undo an owner purge",
            ));
        }
    }
    for (_, pin) in ENTITY_DOC_PIN.scan_from(store, txn, &prefix(entity))? {
        let citation = raw(&pin.citation)?;
        if !history.is_some_and(|h| h.pins.iter().any(|carried| carried.citation == citation)) {
            return Err(invalid(
                "entity document recovery would drop a citation pin",
            ));
        }
    }
    Ok(())
}

/// Replays the carried versions into fresh history: an empty birth commit,
/// then each version as one commit on its parents, so the replayed causal
/// order is the carried one. A purged document is cut at version 0 again.
fn replay(
    entity: EntityId,
    row: &CanonicalEntityDocument,
    history: &CanonicalEntityDocumentHistory,
) -> Result<(EntityDoc, Vec<Frontiers>)> {
    let texts = history.texts()?;
    let doc = EntityDoc::rebuild_value(
        entity,
        "",
        EntityId::from_bytes(row.birth_actor)?,
        row.birth_at,
    )?;
    EntityDoc::set_record_fields(&doc.doc, &row.record_fields)?;
    doc.doc.commit();
    let root = doc.doc.oplog_frontiers();
    let mut frontiers: Vec<Frontiers> = Vec::with_capacity(texts.len());
    for (index, (version, text)) in history.versions.iter().zip(&texts).enumerate() {
        let base = if version.parents.is_empty() {
            root.clone()
        } else {
            let mut vv = VersionVector::default();
            for &parent in &version.parents {
                let frontier = frontiers
                    .get(parent as usize)
                    .ok_or(invalid("entity document version parent"))?;
                vv.merge(
                    &doc.doc
                        .frontiers_to_vv(frontier)
                        .ok_or(invalid("entity document version replay"))?,
                );
            }
            doc.doc.vv_to_frontiers(&vv)
        };
        let branch = doc
            .doc
            .fork_at(&base)
            .map_err(|_| invalid("entity document version replay"))?;
        branch
            .get_text(BODY)
            .update(text, UpdateOptions::default())
            .map_err(|_| invalid("entity document version replay"))?;
        EntityDoc::replace_metadata(&branch, &version.metadata)?;
        branch
            .get_map("meta")
            .insert(
                RECOVERED_VERSION,
                i64::try_from(index).map_err(|_| invalid("entity document version count"))?,
            )
            .map_err(|_| invalid("entity document version replay"))?;
        branch.commit();
        let known = doc.doc.oplog_vv();
        let updates = branch
            .export(ExportMode::updates(&known))
            .map_err(|_| invalid("entity document version replay"))?;
        let status = doc
            .doc
            .import(&updates)
            .map_err(|_| invalid("entity document version replay"))?;
        if status.pending.is_some() {
            return Err(invalid("entity document version replay"));
        }
        frontiers.push(branch.oplog_frontiers());
    }
    let head = frontiers
        .last()
        .ok_or(invalid("entity document history has no head"))?;
    if &doc.doc.oplog_frontiers() != head
        || doc.text() != row.text
        || doc.metadata_bytes()? != row.metadata
    {
        return Err(Error::InvariantViolation("replayed head differs"));
    }
    let doc = if history.shallow {
        let shallow = EntityDoc::from_snapshot(&doc.shallow_snapshot(&frontiers[0].encode())?)?;
        if shallow.text() != row.text {
            return Err(Error::InvariantViolation(
                "replayed purge changed live state",
            ));
        }
        shallow
    } else {
        doc
    };
    Ok((doc, frontiers))
}

/// Writes the carried pins, receipts, purges and forks, each bound to its
/// replayed version. Pins take fresh cursors on the same span of the same
/// version text, and refuse if the quote does not come back.
fn bind_rows(
    store: &Store,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    history: &CanonicalEntityDocumentHistory,
    doc: &EntityDoc,
    frontiers: &[Frontiers],
) -> Result<()> {
    let frontier = |index: u32| -> Result<Vec<u8>> {
        Ok(frontiers
            .get(index as usize)
            .ok_or(invalid("entity document version index"))?
            .encode())
    };
    for pin in &history.pins {
        let origin = doc.fork(&frontier(pin.version)?)?;
        let anchor =
            super::verbs::make_anchor(&origin, *entity, pin.start as usize, pin.end as usize)?;
        if anchor.quote != pin.quote || anchor.hash != pin.hash {
            return Err(invalid("entity document pin does not quote its version"));
        }
        let citation = EntityId::from_bytes(pin.citation)?;
        ENTITY_DOC_PIN.put(
            store,
            txn,
            &HexPair(HexId(*entity), HexId(citation)),
            &CitationPin {
                citation: citation.to_hex(),
                entity: entity.to_hex(),
                document: hex(pin.document)?,
                anchor,
                actor: hex(pin.actor)?,
            },
        )?;
    }
    for receipt in &history.receipts {
        let id = EntityId::from_bytes(receipt.receipt)?;
        ENTITY_DOC_RECEIPT.put(
            store,
            txn,
            &HexPair(HexId(*entity), HexId(id)),
            &TextReceipt {
                receipt: id.to_hex(),
                proposal: hex(receipt.proposal)?,
                fork: hex(receipt.fork)?,
                entity: entity.to_hex(),
                actor: hex(receipt.actor)?,
                verb: match receipt.verb {
                    CanonicalSettleVerb::Merge => SettleVerb::Merge,
                    CanonicalSettleVerb::Switch => SettleVerb::Switch,
                    CanonicalSettleVerb::Reject => SettleVerb::Reject,
                },
                at: receipt.at,
                before: frontier(receipt.before)?,
                after: frontier(receipt.after)?,
            },
        )?;
    }
    for purge in &history.purges {
        let id = EntityId::from_bytes(purge.receipt)?;
        ENTITY_DOC_PURGE_RECEIPT.put(
            store,
            txn,
            &HexPair(HexId(*entity), HexId(id)),
            &PurgeReceipt {
                receipt: id.to_hex(),
                entity: entity.to_hex(),
                document: hex(purge.document)?,
                actor: hex(purge.actor)?,
                requested: frontier(purge.requested)?,
                applied: frontier(purge.applied)?,
                at: purge.at,
                live_text_hash: purge.live_text_hash,
            },
        )?;
    }
    for fork in &history.forks {
        // A settled fork whose base was purged names the empty frontier,
        // which a purged document never retains.
        let base = match fork.base {
            Some(index) => frontier(index)?,
            None => Frontiers::default().encode(),
        };
        let record = ForkRecord {
            fork: hex(fork.fork)?,
            proposal: hex(fork.proposal)?,
            entity: entity.to_hex(),
            parent_document: hex(fork.parent_document)?,
            base: base.clone(),
            actor: hex(fork.actor)?,
            opened_at: fork.opened_at,
            rewrite: fork.rewrite,
            status: match fork.status {
                CanonicalForkStatus::Pending => ForkStatus::Pending,
                CanonicalForkStatus::Merged => ForkStatus::Merged,
                CanonicalForkStatus::Switched => ForkStatus::Switched,
                CanonicalForkStatus::Rejected => ForkStatus::Rejected,
            },
        };
        ENTITY_DOC_FORK.put(store, txn, &record.fork, &record)?;
        if let Some(output) = &fork.output {
            // The output diverges from the replayed base in its own ops, so
            // a later MERGE or SWITCH lands it as the original would.
            let branch = doc.fork(&base)?;
            branch
                .doc
                .get_text(BODY)
                .update(output, UpdateOptions::default())
                .map_err(|_| invalid("entity document fork replay"))?;
            EntityDoc::replace_metadata(
                &branch.doc,
                fork.output_metadata
                    .as_ref()
                    .ok_or(invalid("entity document fork metadata"))?,
            )?;
            branch.doc.commit();
            ENTITY_DOC_FORK_SNAPSHOT.put(
                store,
                txn,
                &record.fork,
                &branch.shallow_snapshot(&base)?,
            )?;
        }
    }
    Ok(())
}

/// Reassembles every proposal bundle the restored forks belong to, in its
/// carried member order. Runs once every row of the window is restored: a
/// bundle may span documents.
pub(crate) fn restore_proposals(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    rows: &[CanonicalEntityDocument],
) -> Result<()> {
    let store = &vault.store;
    let mut bundles: BTreeMap<[u8; 16], (bool, Vec<(u16, [u8; 16])>)> = BTreeMap::new();
    for fork in rows
        .iter()
        .filter_map(|row| row.history.as_ref())
        .flat_map(|history| &history.forks)
    {
        bundles
            .entry(fork.proposal)
            .or_insert((fork.proposal_settled, Vec::new()))
            .1
            .push((fork.proposal_index, fork.fork));
    }
    for (proposal, (settled, mut members)) in bundles {
        members.sort_unstable();
        let mut forks = Vec::with_capacity(members.len());
        for (_, fork) in members {
            forks.push(
                ENTITY_DOC_FORK
                    .get(store, txn, &hex(fork)?)?
                    .ok_or(Error::CorruptedIndex("recovered fork absent"))?,
            );
        }
        let author = forks
            .first()
            .map(|fork| fork.actor.clone())
            .ok_or(invalid("entity document proposal bundle"))?;
        let proposal = hex(proposal)?;
        ENTITY_DOC_PROPOSAL_BUNDLE.put(
            store,
            txn,
            &proposal,
            &ProposalBundle {
                proposal: proposal.clone(),
                author,
                forks,
                settled,
            },
        )?;
    }
    Ok(())
}

fn field_of(row: &CanonicalEntityDocument) -> storage::TextField {
    match &row.field {
        None => storage::TextField::Utf8Body,
        Some(field) => storage::TextField::MapField(field.clone()),
    }
}
