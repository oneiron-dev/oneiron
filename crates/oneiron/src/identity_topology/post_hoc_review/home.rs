//! FIX 7817: the topology-audit tables a home move carries, as one section
//! on L03's carrier C1 (`crate::sync::home_handoff`). Candidates, their
//! selections and their results are the Coach's local work, so they follow
//! the home, and the new home queues its own drain for every candidate it
//! adopts with no result.
//!
//! The rows travel as their content-free facts and each actor's content
//! apart (FIX 8875, [`partition`]): every subject or read record that is an
//! actor, a result's reviewer, and a decision receipt's principal and its
//! actor evidence versions go in the partition of the actor they name, which
//! the carrier seals under that actor's erasable key. Adoption rejoins each
//! row from its facts and only the pieces that opened here, as the live
//! actor scrub leaves it: an erased subject drops its candidate whole, an
//! erased reviewer leaves the result's outcome with no reviewer, and a
//! receipt naming an erased actor is dropped.
//!
//! A rejoined row lands where this node holds none under its key, and an
//! equal one is a no-op. A different one is a Conflict, since a selection is
//! kept first and a result is append-only, so two of either never combine.
//! On a node that froze its rows for an earlier move they are history, and
//! the carried state is the whole truth of the three tables: each carried
//! row replaces this node's, and every row here the carried state lacks
//! goes, a candidate with its selection and result. A candidate whose
//! decision or any subject is erased here lands nothing.

mod partition;

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use self::partition::{
    IntentFacts, Opened, Parts, ResultFacts, SelectionFacts, TopologyAuditActorContent,
};
use super::{INTENTS, RESULTS, SELECTIONS, TopologyAuditIntent, enqueue_drain_in_txn};
use crate::error::Result;
use crate::side_table::{self, Named, SideCodec, SideKey, SideTable, SideTableDecl};
use crate::sync::home_handoff::{
    HomeFence, HomeMove, HomeTable, ImageRows, Partitioned, TableAdopt,
};
use crate::vault::Vault;

/// Every candidate, selection and result here, as one section's facts.
#[derive(Serialize, Deserialize)]
pub(crate) struct CoachTopologyAuditRows {
    intents: Vec<IntentFacts>,
    selections: Vec<SelectionFacts>,
    results: Vec<ResultFacts>,
}

/// The three tables' declarations, the section's own first.
fn tables() -> [&'static SideTableDecl; 3] {
    [
        &side_table::COACH_TOPOLOGY_AUDIT_INTENT,
        &side_table::COACH_TOPOLOGY_AUDIT_SELECTION,
        &side_table::COACH_TOPOLOGY_AUDIT_RESULT,
    ]
}

/// Every stored key of `table`.
fn all_keys<K: SideKey, V, C: SideCodec<V>>(
    table: SideTable<K, V, C>,
    vault: &Vault,
    txn: &RoTxn<'_>,
) -> Result<Vec<Vec<u8>>> {
    Ok(table
        .scan_keys(&vault.store, txn, &[])?
        .iter()
        .map(|key| table.key_bytes(key))
        .collect())
}

/// Lands `row` under `key` where none is held; an equal row is a no-op. A
/// different one is a Conflict (`false`), unless this node's rows are
/// `history`, when the carried row replaces it.
fn land<V: PartialEq + Serialize + serde::de::DeserializeOwned>(
    table: SideTable<[u8; 32], V, Named>,
    (vault, history): (&Vault, bool),
    txn: &mut RwTxn<'_>,
    key: &[u8; 32],
    row: &V,
) -> Result<bool> {
    match table.get(&vault.store, &*txn, key)? {
        Some(held) if held == *row => Ok(true),
        Some(_) if !history => Ok(false),
        _ => {
            table.put(&vault.store, txn, key, row)?;
            Ok(true)
        }
    }
}

/// Deletes every row of `table` here whose key is not in `kept`.
fn retain<V: Serialize + serde::de::DeserializeOwned>(
    table: SideTable<[u8; 32], V, Named>,
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    kept: &BTreeSet<[u8; 32]>,
) -> Result<()> {
    for key in table.scan_keys(&vault.store, &*txn, &[])? {
        if !kept.contains(&key) {
            table.delete(&vault.store, txn, &key)?;
        }
    }
    Ok(())
}

/// Whether the candidate names a record erased here.
fn names_erased(vault: &Vault, txn: &RoTxn<'_>, intent: &TopologyAuditIntent) -> Result<bool> {
    for id in std::iter::once(&intent.event).chain(&intent.subjects) {
        if crate::ports::removed_in_txn(&vault.store, txn, id)? {
            return Ok(true);
        }
    }
    Ok(false)
}

impl HomeTable for CoachTopologyAuditRows {
    type Rows = Self;
    type Actor = TopologyAuditActorContent;
    const TABLE: &'static SideTableDecl = &side_table::COACH_TOPOLOGY_AUDIT_INTENT;
    const SCHEMA_VERSION: u16 = 1;

    /// Every write here is first-kept or append-only, so the rows freeze at
    /// any point: a review that lands here after the freeze is this node's
    /// history, and the new home reviews the candidate under the selection
    /// it carried.
    fn quiescent(_vault: &Vault, _txn: &RoTxn<'_>, _movement: &HomeMove) -> Result<bool> {
        Ok(true)
    }

    fn export(
        vault: &Vault,
        txn: &RoTxn<'_>,
        _fence: &HomeFence,
    ) -> Result<Partitioned<Self, TopologyAuditActorContent>> {
        let mut parts = Parts::new();
        let mut intents = Vec::new();
        for (_, row) in INTENTS.scan(&vault.store, txn)? {
            intents.push(partition::intent_facts(vault, txn, row, &mut parts)?);
        }
        let mut selections = Vec::new();
        for (_, row) in SELECTIONS.scan(&vault.store, txn)? {
            selections.push(partition::selection_facts(vault, txn, row, &mut parts)?);
        }
        let mut results = Vec::new();
        for (_, row) in RESULTS.scan(&vault.store, txn)? {
            results.push(partition::result_facts(vault, txn, row, &mut parts)?);
        }
        Ok(Partitioned {
            facts: Self {
                intents,
                selections,
                results,
            },
            actors: partition::partitions(parts),
        })
    }

    fn adopt(
        vault: &Vault,
        txn: &mut RwTxn<'_>,
        _fence: &HomeFence,
        rows: Partitioned<Self, TopologyAuditActorContent>,
    ) -> Result<TableAdopt> {
        let Partitioned { facts, actors } = rows;
        let opened = Opened::of(actors);
        let history = crate::sync::home_handoff::froze_home_state_in_txn(&vault.store, &*txn)?;
        let here = (vault, history);
        let mut selections: BTreeMap<[u8; 32], SelectionFacts> = facts
            .selections
            .into_iter()
            .map(|selection| (partition::selection_audit(&selection), selection))
            .collect();
        let mut results: BTreeMap<[u8; 32], ResultFacts> = facts
            .results
            .into_iter()
            .map(|result| (partition::result_audit(&result), result))
            .collect();
        let mut pending = false;
        // What landed, per table: on history, every other row here goes.
        let mut landed_intents = BTreeSet::new();
        let mut landed_selections = BTreeSet::new();
        let mut landed_results = BTreeSet::new();
        for intent in facts.intents {
            // A subject, or a record its review read, whose actor's piece is
            // not here went with that actor's erase: the candidate is
            // dropped whole, as the live scrub drops it.
            let Some(intent) = opened.intent(intent) else {
                continue;
            };
            let audit = intent.audit_id;
            let selection = selections
                .remove(&audit)
                .map(|selection| opened.selection(selection));
            let result = match results.remove(&audit) {
                Some(result) => match opened.result(result) {
                    Some(result) => Some(result),
                    None => continue,
                },
                None => None,
            };
            if names_erased(vault, &*txn, &intent)? {
                continue;
            }
            if !land(INTENTS, here, txn, &audit, &intent)? {
                return Ok(TableAdopt::Conflict);
            }
            landed_intents.insert(audit);
            if let Some(selection) = &selection {
                if !land(SELECTIONS, here, txn, &audit, selection)? {
                    return Ok(TableAdopt::Conflict);
                }
                landed_selections.insert(audit);
            }
            match &result {
                Some(result) => {
                    if !land(RESULTS, here, txn, &audit, result)? {
                        return Ok(TableAdopt::Conflict);
                    }
                    landed_results.insert(audit);
                }
                None => pending = true,
            }
        }
        // On history the carried state is the whole truth: a selection or
        // result this node kept after its freeze, for a candidate the move
        // carried without one, goes, and so does every row of a candidate
        // the move dropped (erased) or never carried.
        if history {
            retain(INTENTS, vault, txn, &landed_intents)?;
            retain(SELECTIONS, vault, txn, &landed_selections)?;
            retain(RESULTS, vault, txn, &landed_results)?;
        }
        // The new home reviews what the old one left pending.
        if pending {
            enqueue_drain_in_txn(vault, txn, vault.store.clock.now_recorded_at())?;
        }
        Ok(TableAdopt::Applied)
    }

    fn live_keys(vault: &Vault, txn: &RoTxn<'_>) -> Result<Vec<Vec<u8>>> {
        let mut keys = all_keys(INTENTS, vault, txn)?;
        keys.extend(all_keys(SELECTIONS, vault, txn)?);
        keys.extend(all_keys(RESULTS, vault, txn)?);
        Ok(keys)
    }

    fn manages(_vault: &Vault, _txn: &RoTxn<'_>, image: &ImageRows) -> Result<Vec<Vec<u8>>> {
        Ok(image
            .iter()
            .filter(|(key, _)| tables().iter().any(|table| key.starts_with(table.prefix)))
            .map(|(key, _)| key.clone())
            .collect())
    }
}
