//! FIX 7817: the topology-audit tables a home move carries, as one section
//! on L03's carrier C1 (`crate::sync::home_handoff`). Candidates, their
//! selections and their results are the Coach's local work, so they follow
//! the home, and the new home queues its own drain for every candidate it
//! adopts with no result. The rows hold ids, digests and engine codes and
//! name no actor, so a move carries them as facts with no actor partition.
//!
//! A carried row lands where this node holds none under its key, and an
//! equal one is a no-op. A different one is a Conflict, since a selection is
//! kept first and a result is append-only, so two of either never combine;
//! on a node that froze its rows for an earlier move they are history, and
//! the carried row replaces this node's. A candidate whose decision or any
//! subject is erased here lands nothing.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::{
    INTENTS, RESULTS, SELECTIONS, TopologyAuditIntent, TopologyAuditResult, TopologyAuditSelection,
    enqueue_drain_in_txn,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideCodec, SideKey, SideTable, SideTableDecl};
use crate::sync::home_handoff::{
    ActorContent, HomeFence, HomeMove, HomeTable, ImageRows, Partitioned, TableAdopt,
};
use crate::vault::Vault;

/// Every candidate, selection and result here, as one section.
#[derive(Serialize, Deserialize)]
pub(crate) struct CoachTopologyAuditRows {
    intents: Vec<TopologyAuditIntent>,
    selections: Vec<TopologyAuditSelection>,
    results: Vec<TopologyAuditResult>,
}

/// An actor's content among the rows: none ever, since no row names an
/// actor. The carrier's partition slot, typed.
#[derive(Serialize, Deserialize)]
pub(crate) struct TopologyAuditActorContent {
    actor: EntityId,
}

impl ActorContent for TopologyAuditActorContent {
    fn actor(&self) -> EntityId {
        self.actor
    }
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
        Ok(Partitioned {
            facts: Self {
                intents: INTENTS
                    .scan(&vault.store, txn)?
                    .into_iter()
                    .map(|(_, row)| row)
                    .collect(),
                selections: SELECTIONS
                    .scan(&vault.store, txn)?
                    .into_iter()
                    .map(|(_, row)| row)
                    .collect(),
                results: RESULTS
                    .scan(&vault.store, txn)?
                    .into_iter()
                    .map(|(_, row)| row)
                    .collect(),
            },
            actors: Vec::new(),
        })
    }

    fn adopt(
        vault: &Vault,
        txn: &mut RwTxn<'_>,
        _fence: &HomeFence,
        rows: Partitioned<Self, TopologyAuditActorContent>,
    ) -> Result<TableAdopt> {
        let rows = rows.facts;
        let history = crate::sync::home_handoff::froze_home_state_in_txn(&vault.store, &*txn)?;
        let here = (vault, history);
        let mut landed = std::collections::BTreeSet::new();
        for intent in &rows.intents {
            if names_erased(vault, &*txn, intent)? {
                continue;
            }
            if !land(INTENTS, here, txn, &intent.audit_id, intent)? {
                return Ok(TableAdopt::Conflict);
            }
            landed.insert(intent.audit_id);
        }
        for selection in &rows.selections {
            if landed.contains(&selection.audit_id)
                && !land(SELECTIONS, here, txn, &selection.audit_id, selection)?
            {
                return Ok(TableAdopt::Conflict);
            }
        }
        let mut reviewed = std::collections::BTreeSet::new();
        for result in &rows.results {
            if !landed.contains(&result.audit_id) {
                continue;
            }
            if !land(RESULTS, here, txn, &result.audit_id, result)? {
                return Ok(TableAdopt::Conflict);
            }
            reviewed.insert(result.audit_id);
        }
        // The new home reviews what the old one left pending.
        if landed.iter().any(|audit| !reviewed.contains(audit)) {
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
