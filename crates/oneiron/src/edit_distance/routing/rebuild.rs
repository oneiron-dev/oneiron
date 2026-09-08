//! CID-7 projection rebuild.

use std::collections::BTreeMap;

use super::keys::{
    AGGREGATE_KEY_PREFIX, AGGREGATE_ROW_LABEL, MEMBER_KEY_PREFIX, MEMBER_ROW_LABEL, ROW_VERSION,
    StoredAggregate, StoredModelVersion, aggregate_key, decode_row, encode_row, key_tail,
};
use super::scope::RoutingScopeKey;
use super::write::{apply_fold, fold_of};
use crate::Vault;
use crate::edit_distance::attribution::{AmendmentJudgment, amendment_judgments};
use crate::error::{Error, Result};

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
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn rebuild_routing_projection(vault: &Vault) -> Result<()> {
    let judged: BTreeMap<String, AmendmentJudgment> = amendment_judgments(vault)?
        .into_iter()
        .map(|judgment| (judgment.receipt_id.clone(), judgment))
        .collect();

    let mut rebuilt: BTreeMap<Vec<u8>, StoredAggregate> = BTreeMap::new();
    let mut stale_members = Vec::new();
    let mut stale_aggregates = Vec::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        for entry in vault
            .store
            .vault_meta
            .prefix_iter(&rtxn, MEMBER_KEY_PREFIX)?
        {
            let (key, raw) = entry?;
            let receipt_id = key_tail(&key, MEMBER_KEY_PREFIX, MEMBER_ROW_LABEL)?;
            let Some(judgment) = judged.get(&receipt_id) else {
                stale_members.push(key.to_vec());
                continue;
            };
            let row: StoredModelVersion = decode_row(&raw, MEMBER_ROW_LABEL)?;
            if row.v != ROW_VERSION {
                return Err(Error::CorruptedIndex(MEMBER_ROW_LABEL));
            }
            let scope = RoutingScopeKey::new(row.model_version, judgment.scope.clone());
            let fold = fold_of(judgment)?;
            apply_fold(rebuilt.entry(aggregate_key(&scope)?).or_default(), fold)?;
        }
        for entry in vault
            .store
            .vault_meta
            .prefix_iter(&rtxn, AGGREGATE_KEY_PREFIX)?
        {
            let (key, _) = entry?;
            if !rebuilt.contains_key(key.as_ref()) {
                stale_aggregates.push(key.into_owned());
            }
        }
    }

    vault.with_write_txn(|wtxn| {
        for key in stale_members.iter().chain(&stale_aggregates) {
            vault.store.vault_meta.delete(wtxn, key)?;
        }
        for (key, aggregate) in &rebuilt {
            let encoded = encode_row(aggregate, AGGREGATE_ROW_LABEL)?;
            vault.store.vault_meta.put(wtxn, key, &encoded)?;
        }
        Ok(())
    })
}
