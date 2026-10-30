//! A reviewed claim's teaching copies go with it (FIX 9805).
//!
//! An inbox decision copies the reviewed value and its substitution text; a
//! mined preference claim, its cluster record and a mined skill edit copy
//! that substitution on. Each copy is bound to its source by the decision's
//! receipt id. A delete of the reviewed claim (the shared derived-row eraser,
//! at both delete doors) and an erase of the decision's actor or principal
//! (the table's declared scrub, replayed on restore) take the decision rows
//! and every downstream copy that cites one, in the erase's own transaction:
//! the skill edits, and each cluster whose mark, record or claim cites one,
//! found through the mint marks so a record outlives no claim. A row the
//! erase cannot parse is passed over with a WARN, never an abort.

use std::collections::BTreeSet;

use rmpv::Value;

use super::config::{MARK_KIND_PREFERENCE, MINED_EVIDENCE_RECEIPTS_KEY, MINED_EVIDENCE_ROW_LABEL};
use super::emission::{MINT_MARK, mined_evidence_record_id};
use super::feedback::DECISION;
use super::influence::is_mined_preference;
use super::model::{StoredMinedEvidence, SubstitutionCluster};
use super::store::{SKILL_EDIT, decode_row};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{EntityRecord, EntityStoreRead};
use crate::side_table::SideKey;
use crate::store::Store;

/// Which decision rows the erase of one entity reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// A deleted claim: the decisions on it.
    SourceClaim,
    /// An erased entity: the decisions on it as a claim, and those naming it
    /// as the generating actor or the deciding principal.
    Entity,
}

/// The shared derived-row eraser's entry: the delete of reviewed claim `id`
/// takes its decisions and every downstream copy of them. A no-op for any
/// other entity.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_source_claim_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let is_claim = record_in_txn(store, &*txn, id)?
        .is_some_and(|record| record.entity_type == crate::registry::ENTITY_TYPE_CLAIM);
    if !is_claim {
        return Ok(());
    }
    erase_teaching_copies_in_txn(store, txn, id, Reach::SourceClaim)
}

/// The decision table's declared scrub: an actor's erase, and a restored
/// image's replay of every erased id, claims included.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_principal_decision_entity_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    erase_teaching_copies_in_txn(&vault.store, txn, id, Reach::Entity)
}

/// Whether every receipt `cluster` cites still holds its decision, read in
/// the emitting writer: a pass that read a decision an erase has since taken
/// mints nothing from it.
pub(super) fn receipts_stand_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    cluster: &SubstitutionCluster,
) -> Result<bool> {
    for receipt in &cluster.receipt_refs {
        if !DECISION.contains(&vault.store, txn, receipt)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn erase_teaching_copies_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    reach: Reach,
) -> Result<()> {
    let mut receipts = BTreeSet::new();
    let mut actors = BTreeSet::new();
    for row in DECISION.iter_raw_from(store, &*txn, &[])? {
        let (key, bytes) = row?;
        let (Some(receipt), Ok(decision)) =
            (String::decode_key(&key), DECISION.decode_value(&bytes))
        else {
            tracing::warn!("a principal decision row does not decode: the erase passes it over");
            continue;
        };
        let reached = decision.claim == Some(*id)
            || (reach == Reach::Entity && (decision.actor == *id || decision.principal == *id));
        if reached {
            actors.insert(decision.actor);
            receipts.insert(receipt);
        }
    }
    if receipts.is_empty() {
        return Ok(());
    }
    // The decisions go first: a downstream claim's own delete re-enters the
    // derived-row eraser, and must find nothing left to follow.
    for receipt in &receipts {
        DECISION.delete(store, txn, receipt)?;
    }
    let edits = erase_skill_edits_in_txn(store, txn, &receipts)?;
    let mut copies = mined_claims_in_txn(store, &*txn, &actors, &receipts)?;
    let marks = cluster_copies_in_txn(store, &*txn, &receipts, &edits, &mut copies)?;
    for handle in &marks {
        MINT_MARK.delete(store, txn, handle)?;
    }
    for copy in copies {
        // A mined claim is MACHINE-signed: its history controls go with it.
        let (_, vector, graph, neighbors) =
            crate::batch::deindex_entity_with_machine_history(store, txn, &copy)?;
        crate::batch::stage_cascade_tombstone_in_txn(store, txn, &copy)?;
        crate::ppr::invalidate_ppr_for_delete(store, txn, &copy, &neighbors)?;
        if graph {
            crate::ppr::increment_graph_version(store, txn)?;
        }
        if vector {
            crate::hnsw::increment_vector_version(store, txn)?;
        }
    }
    Ok(())
}

/// Drops every mined skill edit, answered or open, that cites one of
/// `receipts`, returning their ids.
fn erase_skill_edits_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    receipts: &BTreeSet<String>,
) -> Result<BTreeSet<EntityId>> {
    let mut gone = BTreeSet::new();
    for row in SKILL_EDIT.iter_raw_from(store, &*txn, &[])? {
        let (key, bytes) = row?;
        let (Some(proposal), Ok(edit)) =
            (EntityId::decode_key(&key), SKILL_EDIT.decode_value(&bytes))
        else {
            tracing::warn!("a mined skill edit row does not decode: the erase passes it over");
            continue;
        };
        if edit
            .evidence_receipts
            .iter()
            .any(|receipt| receipts.contains(receipt))
        {
            gone.insert(proposal);
        }
    }
    for proposal in &gone {
        SKILL_EDIT.delete(store, txn, proposal)?;
    }
    Ok(gone)
}

/// The mined preference claims on `actors`, in any lifecycle state, that cite
/// one of `receipts`.
fn mined_claims_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    actors: &BTreeSet<EntityId>,
    receipts: &BTreeSet<String>,
) -> Result<BTreeSet<EntityId>> {
    let mut claims = BTreeSet::new();
    for actor in actors {
        let subjects = crate::ports::EdgeStoreRead::port_edges(
            store,
            txn,
            actor,
            crate::ports::EdgeDirection::In,
            Some(crate::edge::EdgeKind::ClaimOf),
            None,
        )?
        .map(|edge| edge.map(|edge| edge.target))
        .collect::<Result<Vec<_>>>()?;
        for claim in subjects {
            if mined_claim_cites(store, txn, &claim, receipts)? {
                claims.insert(claim);
            }
        }
    }
    Ok(claims)
}

/// Every mint mark whose cluster goes, found through the mark table so a
/// cluster record whose claim is already gone is still reached. A cluster
/// goes whole when its target is a removed skill edit or claim, or when its
/// record or its preference claim cites one of `receipts`: its record and
/// claim join `copies`, and its mark is returned for the caller to drop.
fn cluster_copies_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    receipts: &BTreeSet<String>,
    edits: &BTreeSet<EntityId>,
    copies: &mut BTreeSet<EntityId>,
) -> Result<Vec<[u8; 32]>> {
    let mut marks = Vec::new();
    for row in MINT_MARK.iter_raw_from(store, txn, &[])? {
        let (key, bytes) = row?;
        let (Some(handle), Ok(mark)) =
            (<[u8; 32]>::decode_key(&key), MINT_MARK.decode_value(&bytes))
        else {
            tracing::warn!("a mint mark row does not decode: the erase passes it over");
            continue;
        };
        let Ok(target) = EntityId::from_hex(&mark.reference) else {
            tracing::warn!("a mint mark names no entity: the erase passes it over");
            continue;
        };
        let record = mined_evidence_record_id(&handle)?;
        let claim_cites =
            mark.kind == MARK_KIND_PREFERENCE && mined_claim_cites(store, txn, &target, receipts)?;
        let record_cites = cluster_record_cites(store, txn, &record, receipts)?;
        if !(claim_cites || record_cites || edits.contains(&target) || copies.contains(&target)) {
            continue;
        }
        if mark.kind == MARK_KIND_PREFERENCE && record_in_txn(store, txn, &target)?.is_some() {
            copies.insert(target);
        }
        if record_in_txn(store, txn, &record)?
            .is_some_and(|row| row.entity_type == crate::registry::ENTITY_TYPE_ASSET)
        {
            copies.insert(record);
        }
        marks.push(handle);
    }
    Ok(marks)
}

/// Whether the claim at `id` is a mined preference whose candidate evidence
/// cites one of `receipts`.
fn mined_claim_cites(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    receipts: &BTreeSet<String>,
) -> Result<bool> {
    let Some(record) = record_in_txn(store, txn, id)? else {
        return Ok(false);
    };
    if record.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return Ok(false);
    }
    let Ok(body) = crate::claim::decode_claim_body(&record.body, true) else {
        tracing::warn!(id = %id.to_hex(), "a claim on a taught actor does not decode: the erase passes it over");
        return Ok(false);
    };
    if !is_mined_preference(&body.predicate) {
        return Ok(false);
    }
    let candidate = body.evidence.as_ref().and_then(|evidence| {
        map_value(
            evidence,
            crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY,
        )
    });
    let Some(candidate) = candidate else {
        tracing::warn!(id = %id.to_hex(), "a mined claim carries no candidate evidence: the erase passes it over");
        return Ok(false);
    };
    Ok(cites_any(
        map_value(candidate, MINED_EVIDENCE_RECEIPTS_KEY),
        receipts,
    ))
}

/// Whether the mined cluster record at `id` cites one of `receipts`.
fn cluster_record_cites(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    receipts: &BTreeSet<String>,
) -> Result<bool> {
    let Some(record) = record_in_txn(store, txn, id)? else {
        return Ok(false);
    };
    if record.entity_type != crate::registry::ENTITY_TYPE_ASSET {
        return Ok(false);
    }
    match decode_row::<StoredMinedEvidence>(&record.body, MINED_EVIDENCE_ROW_LABEL) {
        Ok(evidence) => Ok(evidence
            .receipt_refs
            .iter()
            .any(|receipt| receipts.contains(receipt))),
        Err(_) => {
            tracing::warn!(id = %id.to_hex(), "a mined cluster record does not decode: the erase passes it over");
            Ok(false)
        }
    }
}

/// The entity record at `id`; one whose header does not decode is passed
/// over with a WARN, and a storage failure still fails the erase.
fn record_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<EntityRecord>> {
    match store.port_entity_record(txn, id) {
        Err(Error::CorruptedIndex(_)) => {
            tracing::warn!(id = %id.to_hex(), "an entity record does not decode: the erase passes it over");
            Ok(None)
        }
        read => read,
    }
}

fn map_value<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    let Value::Map(entries) = value else {
        return None;
    };
    entries
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, value)| value)
}

fn cites_any(citations: Option<&Value>, receipts: &BTreeSet<String>) -> bool {
    let Some(Value::Array(citations)) = citations else {
        return false;
    };
    citations.iter().any(|citation| {
        citation
            .as_str()
            .is_some_and(|receipt| receipts.contains(receipt))
    })
}
