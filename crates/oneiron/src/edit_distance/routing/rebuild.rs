//! CID-7 projection rebuild.

use std::collections::BTreeMap;

use super::keys::{AGGREGATE, AggregateKey, MEMBER, StoredAggregate, aggregate_key};
use super::scope::RoutingScopeKey;
use super::write::{apply_fold, fold_of};
use crate::Vault;
use crate::edit_distance::attribution::{AmendmentJudgment, amendment_judgments};
use crate::error::Result;

// ---------------------------------------------------------------------------
// The rebuild door (CID-7)
// ---------------------------------------------------------------------------

/// Recomputes every aggregate from ED-03's judgment ledger and the recorded
/// generation bindings, replacing what is stored.
///
/// This is the identity that makes the aggregates a PROJECTION rather than a
/// second source of truth: nothing here reads its own previous output. Two
/// things do change across a rebuild, and both are corrections rather than
/// drift — a re-judged receipt folds its new mass and class, and a receipt
/// whose judgment was WITHDRAWN loses its fold and its binding, because a run
/// nobody stands behind must not keep weighing on a generation.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`](crate::Error::CorruptedIndex) on an undecodable row.
pub fn rebuild_routing_projection(vault: &Vault) -> Result<()> {
    let judged: BTreeMap<String, AmendmentJudgment> = amendment_judgments(vault)?
        .into_iter()
        .map(|judgment| (judgment.receipt_id.clone(), judgment))
        .collect();

    let mut rebuilt: BTreeMap<AggregateKey, StoredAggregate> = BTreeMap::new();
    let mut stale_members = Vec::new();
    let mut stale_aggregates = Vec::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        for entry in MEMBER.iter_from(&vault.store, &rtxn, &[])? {
            let (receipt_id, row) = entry?;
            let Some(judgment) = judged.get(&receipt_id) else {
                stale_members.push(receipt_id);
                continue;
            };
            let scope = RoutingScopeKey::new(row.model_version, judgment.scope.clone());
            let fold = fold_of(judgment)?;
            apply_fold(rebuilt.entry(aggregate_key(&scope)?).or_default(), fold)?;
        }
        for entry in AGGREGATE.iter_from(&vault.store, &rtxn, &[])? {
            let (key, _) = entry?;
            if !rebuilt.contains_key(&key) {
                stale_aggregates.push(key);
            }
        }
    }

    vault.with_write_txn(|wtxn| {
        for key in &stale_members {
            MEMBER.delete(&vault.store, wtxn, key)?;
        }
        for key in &stale_aggregates {
            AGGREGATE.delete(&vault.store, wtxn, key)?;
        }
        for (key, aggregate) in &rebuilt {
            AGGREGATE.put(&vault.store, wtxn, key, aggregate)?;
        }
        Ok(())
    })
}
