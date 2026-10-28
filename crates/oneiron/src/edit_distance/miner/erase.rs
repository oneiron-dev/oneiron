//! A reviewed claim's teaching copies go with it (FIX 9805).
//!
//! An inbox decision copies the reviewed value and its substitution text; a
//! mined preference claim, its cluster record and a mined skill edit copy
//! that substitution on. Each copy is bound to its source by the decision's
//! receipt id. A delete of the reviewed claim (the shared derived-row eraser,
//! at both delete doors) and an erase of the decision's actor or principal
//! (the table's declared scrub, replayed on restore) take the decision rows
//! and every downstream copy that cites one, in the erase's own transaction.
//! A row the erase cannot parse is passed over with a WARN, never an abort.

use std::collections::BTreeSet;

use rmpv::Value;

use super::config::{MINED_EVIDENCE_RECEIPTS_KEY, MINED_EVIDENCE_ROW_LABEL};
use super::feedback::DECISION;
use super::influence::is_mined_preference;
use super::model::{StoredMinedEvidence, SubstitutionCluster};
use super::store::{SKILL_EDIT, decode_row};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
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
    let is_claim = store
        .port_entity_record(&*txn, id)?
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
    erase_skill_edits_in_txn(store, txn, &receipts)?;
    let copies = mined_copies_in_txn(store, &*txn, &actors, &receipts)?;
    for copy in copies {
        let (_, vector, graph, neighbors) = crate::batch::deindex_entity(store, txn, &copy)?;
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
/// `receipts`.
fn erase_skill_edits_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    receipts: &BTreeSet<String>,
) -> Result<()> {
    let mut gone = Vec::new();
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
            gone.push(proposal);
        }
    }
    for proposal in gone {
        SKILL_EDIT.delete(store, txn, &proposal)?;
    }
    Ok(())
}

/// The mined preference claims on `actors`, in any lifecycle state, that cite
/// one of `receipts`, with each cluster record whose own citations do.
fn mined_copies_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    actors: &BTreeSet<EntityId>,
    receipts: &BTreeSet<String>,
) -> Result<BTreeSet<EntityId>> {
    let mut copies = BTreeSet::new();
    for actor in actors {
        let claims = crate::ports::EdgeStoreRead::port_edges(
            store,
            txn,
            actor,
            crate::ports::EdgeDirection::In,
            Some(crate::edge::EdgeKind::ClaimOf),
            None,
        )?
        .map(|edge| edge.map(|edge| edge.target))
        .collect::<Result<Vec<_>>>()?;
        for claim in claims {
            let Some(record) = store.port_entity_record(txn, &claim)? else {
                continue;
            };
            if record.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
                continue;
            }
            let Ok(body) = crate::claim::decode_claim_body(&record.body, true) else {
                tracing::warn!(id = %claim.to_hex(), "a claim on a taught actor does not decode: the erase passes it over");
                continue;
            };
            if !is_mined_preference(&body.predicate) {
                continue;
            }
            let Some(candidate) = body.evidence.as_ref().and_then(|evidence| {
                map_value(
                    evidence,
                    crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY,
                )
            }) else {
                continue;
            };
            if !cites_any(map_value(candidate, MINED_EVIDENCE_RECEIPTS_KEY), receipts) {
                continue;
            }
            copies.insert(claim);
            let records = crate::dreamer_consolidation::decode_consolidation_evidence(candidate)
                .ok()
                .flatten()
                .map(|envelope| envelope.refs)
                .unwrap_or_default();
            for record in records {
                if cluster_record_cites(store, txn, &record, receipts)? {
                    copies.insert(record);
                }
            }
        }
    }
    Ok(copies)
}

/// Whether the mined cluster record at `id` cites one of `receipts`.
fn cluster_record_cites(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    receipts: &BTreeSet<String>,
) -> Result<bool> {
    let Some(record) = store.port_entity_record(txn, id)? else {
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
