//! Source-erasure teardown for retained hook payloads. Identity, ordering,
//! digests and terminal status stay; source-derived bytes and pending work
//! that could resurrect them do not.

use std::collections::BTreeSet;

use super::*;
use crate::runtime_hooks::verb::{HookVerbRunRecord, VERB_RUNS};

const ERASED_HISTORY_REASON: &str = "source history erased";

/// Whether a permanent erase, not a restorable soft delete, fences `id` in
/// this write's snapshot.
fn source_erased_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(vault.local_hard_delete_marker_exists_in_txn(txn, id)?
        || vault.archive_tombstone_in_txn(txn, id)?.is_some())
}

/// A body that ran across an erase may not commit the erased source's bytes
/// back into a memo or intent.
pub(super) fn dependencies_erased_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    dependencies: &[HookDependency],
) -> Result<bool> {
    for dependency in dependencies {
        if source_erased_in_txn(vault, txn, &dependency.id)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Retires every content-bearing field of a fact memo, preserving its stable
/// delivery identity, derivation digest, outcome token and commit position.
pub(super) fn scrub_memo_payload(memo: &mut HookRunRecord) {
    memo.input_json = None;
    memo.reads.clear();
    memo.verdicts.clear();
    memo.verdicts_complete = false;
    memo.outcome_json = None;
    memo.reason = Some(ERASED_HISTORY_REASON.to_owned());
}

/// The verb-record half of [`scrub_memo_payload`].
fn scrub_verb_payload(record: &mut HookVerbRunRecord) {
    record.input_json = None;
    record.reads.clear();
    record.outcome_json = None;
    record.reason = Some(ERASED_HISTORY_REASON.to_owned());
}

/// Retires an intent's payload. A pending one becomes explicitly refused so
/// no later drain can land it; an applied one's landed effect is untouched.
pub(super) fn scrub_intent_payload(intent: &mut HookIntent, at: u64) {
    intent.outcome_json.clear();
    intent.reason = Some(ERASED_HISTORY_REASON.to_owned());
    if intent.state == HookIntentState::Pending {
        intent.state = HookIntentState::Refused;
        intent.settled_at = Some(at);
    }
}

/// Removes free-text payload from a Hook receipt while keeping its truthful
/// outcome and identity fields.
pub(super) fn scrub_receipt_payload(receipt: &mut ReceiptRecord) {
    receipt
        .fields
        .insert("reason".to_owned(), ERASED_HISTORY_REASON.to_owned());
    receipt.fields.remove("note");
    receipt.policy_trace.clear();
}

/// Scrubs every retained hook carrier that depends on `id`, in the caller's
/// erase transaction. Complete scans avoid a second dependency index; every
/// matching row is retired before the erase or its sweep declares completion.
pub(crate) fn scrub_hook_source_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    at: u64,
) -> Result<()> {
    let mut affected_runs = BTreeSet::new();

    let mut memos = Vec::new();
    for row in MEMOS.iter_from(&vault.store, txn, &[])? {
        let (key, memo) = row?;
        if memo
            .derivation
            .dependencies
            .iter()
            .any(|dependency| dependency.id == *id)
        {
            memos.push((key, memo));
        }
    }
    for (key, mut memo) in memos {
        scrub_memo_payload(&mut memo);
        MEMOS.put(vault, txn, &key, &memo)?;
        affected_runs.insert(key);
    }

    let mut intents = Vec::new();
    for row in INTENTS.iter_from(&vault.store, txn, &[])? {
        let (key, intent) = row?;
        if intent
            .dependencies
            .iter()
            .any(|dependency| dependency.id == *id)
        {
            intents.push((key, intent));
        }
    }
    for (key, mut intent) in intents {
        scrub_intent_payload(&mut intent, at);
        INTENTS.put(vault, txn, &key, &intent)?;
        affected_runs.insert(key);
    }

    let mut verb_runs = Vec::new();
    for row in VERB_RUNS.iter_from(&vault.store, txn, &[])? {
        let (key, record) = row?;
        if record.dependencies.contains(id)
            || record
                .reads
                .iter()
                .any(|pin| pin.rows.iter().any(|row| row.id == *id))
        {
            verb_runs.push((key, record));
        }
    }
    for (key, mut record) in verb_runs {
        scrub_verb_payload(&mut record);
        VERB_RUNS.put(vault, txn, &key, &record)?;
        affected_runs.insert(key);
    }

    crate::runtime_hooks::block::scrub_blocks_in_txn(vault, txn, id, &affected_runs, at)?;

    let id_hex = id.to_hex();
    let mut receipts = Vec::new();
    for row in RECEIPTS.iter_from(&vault.store, txn, &[])? {
        let (key, receipt) = row?;
        if affected_runs.contains(&key) || receipt.trigger_ref.as_deref() == Some(id_hex.as_str())
        {
            receipts.push((key, receipt));
        }
    }
    for (key, mut receipt) in receipts {
        scrub_receipt_payload(&mut receipt);
        RECEIPTS.put(vault, txn, &key, &receipt)?;
    }
    Ok(())
}
