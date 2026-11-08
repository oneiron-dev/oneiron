//! Source-erasure teardown for retained hook payloads. Identity, ordering,
//! digests and terminal status stay; source-derived bytes and pending work
//! that could resurrect them do not. A fact memo whose input names an
//! erased actor names the erased marker instead, and a hook feed row that
//! names the erased id keeps only its position.

use std::collections::BTreeSet;

use super::*;
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::runtime_hooks::verb::{HookVerbRunRecord, VERB_RUNS};

const ERASED_HISTORY_REASON: &str = "source history erased";

/// Whether a permanent erase, not a restorable soft delete, fences `id` in
/// this write's snapshot.
fn source_erased_in_txn(vault: &Vault, txn: &heed::RoTxn, id: &EntityId) -> Result<bool> {
    Ok(vault.local_hard_delete_marker_exists_in_txn(txn, id)?
        || vault.archive_tombstone_in_txn(txn, id)?.is_some())
}

/// A body that ran across an erase may not commit the erased source's bytes
/// back into a memo or intent.
pub(in crate::runtime_hooks) fn dependencies_erased_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    dependencies: &[HookDependency],
) -> Result<bool> {
    Ok(!erased_dependency_ids_in_txn(vault, txn, dependencies)?.is_empty())
}

/// The permanently erased ids among a record's dependencies.
pub(in crate::runtime_hooks) fn erased_dependency_ids_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    dependencies: &[HookDependency],
) -> Result<BTreeSet<EntityId>> {
    let mut erased = BTreeSet::new();
    for dependency in dependencies {
        if source_erased_in_txn(vault, txn, &dependency.id)? {
            erased.insert(dependency.id);
        }
    }
    Ok(erased)
}

/// Retires every content-bearing field of a fact memo, preserving its stable
/// delivery identity, derivation digest, outcome token and commit position.
pub(in crate::runtime_hooks) fn scrub_memo_payload(memo: &mut HookRunRecord) {
    memo.input_json = None;
    memo.history_erased = true;
    memo.reads.clear();
    memo.verdicts.clear();
    memo.verdicts_complete = false;
    memo.outcome_json = None;
    memo.reason = Some(ERASED_HISTORY_REASON.to_owned());
}

/// Names the erased `actor_hex` in a fact memo's pinned input as
/// [`ERASED_CALL_IDENTITY`], the marker an erase leaves for an actor in the
/// records it keeps (FIX 812, FIX 22154). A fact's actor, a claim's writer
/// or a settlement's settler, is no run dependency: the run read the fact's
/// entity, not the actor, so its reads, verdicts and outcome stay, and its
/// digests stay as they are. An input that names `actor_hex` and does not
/// decode retires its payload whole. Returns whether `memo` changed.
fn erase_fact_actor(memo: &mut HookRunRecord, actor_hex: &str) -> bool {
    let Some(input) = memo.input_json.as_deref() else {
        return false;
    };
    if !input.contains(actor_hex) {
        return false;
    }
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(input) else {
        scrub_memo_payload(memo);
        return true;
    };
    let Some(principal) = value.pointer_mut("/fact/actor/principal") else {
        return false;
    };
    if principal.as_str() != Some(actor_hex) {
        return false;
    }
    *principal = serde_json::Value::from(ERASED_CALL_IDENTITY);
    match serde_json::to_string(&value) {
        Ok(input) => memo.input_json = Some(input),
        Err(_) => scrub_memo_payload(memo),
    }
    true
}

/// A fact run's commit write keeps out an `actor` that a permanent erase
/// fenced before it, as the erase's own scrub would have taken it from the
/// memo had the run committed first ([`erase_fact_actor`]).
pub(in crate::runtime_hooks) fn scrub_erased_actor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    memo: &mut HookRunRecord,
    actor: EntityId,
) -> Result<()> {
    if source_erased_in_txn(vault, txn, &actor)? {
        erase_fact_actor(memo, &actor.to_hex());
    }
    Ok(())
}

/// The verb-record half of [`scrub_memo_payload`].
pub(in crate::runtime_hooks) fn scrub_verb_payload(record: &mut HookVerbRunRecord) {
    record.input_json = None;
    record.landing_original = None;
    record.history_erased = true;
    record.reads.clear();
    record.outcome_json = None;
    record.reason = Some(ERASED_HISTORY_REASON.to_owned());
}

/// Retires an intent's payload. A pending one becomes explicitly refused so
/// no later drain can land it; an applied one's landed effect is untouched.
pub(in crate::runtime_hooks) fn scrub_intent_payload(intent: &mut HookIntent, at: u64) {
    intent.outcome_json.clear();
    intent.reason = Some(ERASED_HISTORY_REASON.to_owned());
    if intent.state == HookIntentState::Pending {
        intent.state = HookIntentState::Refused;
        intent.settled_at = Some(at);
    }
}

/// Removes free-text payload from a Hook receipt while keeping its truthful
/// outcome and identity fields.
pub(in crate::runtime_hooks) fn scrub_receipt_payload(receipt: &mut ReceiptRecord) {
    receipt
        .fields
        .insert("reason".to_owned(), ERASED_HISTORY_REASON.to_owned());
    receipt.fields.remove("note");
    receipt.policy_trace.clear();
}

/// Scrubs every retained hook carrier that depends on `id`, every fact
/// memo whose input names `id` as the fact's actor, and every settlement,
/// tick, due index and inbound row that names it, in the caller's erase
/// transaction. Complete scans avoid a second dependency index; every
/// matching row is retired before the erase or its sweep declares
/// completion.
pub(crate) fn scrub_hook_source_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    at: u64,
) -> Result<()> {
    let mut affected_runs = BTreeSet::new();
    let id_hex = id.to_hex();

    let mut memos = Vec::new();
    let mut actor_memos = Vec::new();
    for row in MEMOS.iter_from(&vault.store, txn, &[])? {
        let (key, mut memo) = row?;
        if memo
            .derivation
            .dependencies
            .iter()
            .any(|dependency| dependency.id == *id)
        {
            memos.push((key, memo));
        } else if erase_fact_actor(&mut memo, &id_hex) {
            actor_memos.push((key, memo));
        }
    }
    for (key, mut memo) in memos {
        scrub_memo_payload(&mut memo);
        MEMOS.put(vault, txn, &key, &memo)?;
        affected_runs.insert(key);
    }
    // The run stands on its entity, not on its actor: only the actor's id
    // leaves, and its intent, blocks and receipt stay.
    for (key, memo) in &actor_memos {
        MEMOS.put(vault, txn, key, memo)?;
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

    let mut receipts = Vec::new();
    for row in RECEIPTS.iter_from(&vault.store, txn, &[])? {
        let (key, receipt) = row?;
        if affected_runs.contains(&key) || receipt.trigger_ref.as_deref() == Some(id_hex.as_str()) {
            receipts.push((key, receipt));
        }
    }
    for (key, mut receipt) in receipts {
        scrub_receipt_payload(&mut receipt);
        RECEIPTS.put(vault, txn, &key, &receipt)?;
    }

    crate::runtime_hooks::source::scrub_hook_feeds_in_txn(vault, txn, id)
}
