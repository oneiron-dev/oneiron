//! CID-7 projection rebuild.

use std::collections::BTreeMap;

use super::keys::{
    AGGREGATE, AggregateKey, MEMBER, ROW_VERSION, StoredAggregate, StoredExecutor, aggregate_key,
};
use super::outcomes::run_outcome_in_txn;
use super::write::{apply_fold, fold_of, head_of};
use crate::Vault;
use crate::edit_distance::attribution::{AmendmentJudgment, amendment_judgments};
use crate::error::Result;

// ---------------------------------------------------------------------------
// The rebuild door (CID-7)
// ---------------------------------------------------------------------------

/// Recomputes every head from ED-03's judgment ledger, replacing what is
/// stored.
///
/// This is the identity that makes the aggregates a PROJECTION rather than a
/// second source of truth: nothing here reads its own previous output. Each
/// folded receipt lands on the executor, task type and measurement version
/// its own judgment carries — the stamp of the run that drafted it, never the
/// model serving now (FIX 9812) — paired with the anchored outcome of the TASK
/// its run worked, as the TASK stands now (FIX 7828). Three things do change
/// across a rebuild, and all are corrections rather than drift — a re-judged
/// receipt folds its new mass, labels and stamp, a TASK settled since the
/// fold adds its outcome, and a receipt whose judgment was WITHDRAWN loses its
/// fold and its binding, because a run nobody stands behind must not keep
/// weighing on an executor.
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
    let mut members = Vec::new();
    let mut stale_members = Vec::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        // The keys alone say which receipts were folded; the binding each one
        // gets is re-read from its judgment.
        for receipt_id in MEMBER.scan_keys(&vault.store, &rtxn, &[])? {
            let Some(judgment) = judged.get(&receipt_id) else {
                stale_members.push(receipt_id);
                continue;
            };
            let outcome = run_outcome_in_txn(vault, &rtxn, judgment)?;
            // A judgment that holds keeps its binding and folds nothing.
            if let Some(fold) = fold_of(judgment, outcome)? {
                let key = aggregate_key(&head_of(judgment))?;
                apply_fold(rebuilt.entry(key).or_default(), fold)?;
            }
            let member = StoredExecutor {
                v: ROW_VERSION,
                executor: judgment.executor_key().to_owned(),
            };
            members.push((receipt_id, member));
        }
    }

    vault.with_write_txn_grouped(|wtxn| {
        for key in &stale_members {
            MEMBER.delete(&vault.store, wtxn, key)?;
        }
        for (key, member) in &members {
            MEMBER.put(&vault.store, wtxn, key, member)?;
        }
        AGGREGATE.delete_from(&vault.store, wtxn, &[])?;
        for (key, aggregate) in &rebuilt {
            AGGREGATE.put(&vault.store, wtxn, key, aggregate)?;
        }
        Ok(())
    })
}
