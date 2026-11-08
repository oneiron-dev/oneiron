//! Source-erasure teardown for retained hook payloads. Identity, ordering,
//! digests and terminal status stay; source-derived bytes and pending work
//! that could resurrect them do not. A fact memo, verb run or Hook receipt
//! that names an erased actor names the erased marker instead, a hook
//! feed row that names the erased id keeps only its position, and hook
//! lineage names no erased entity ([`lineage::scrub_erased_in_txn`]).

use std::collections::BTreeSet;

use super::*;
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::runtime_hooks::lineage;
use crate::runtime_hooks::verb::{HookVerbRunRecord, VERB_RUNS};

const ERASED_HISTORY_REASON: &str = "source history erased";

/// Whether a permanent erase, not a restorable soft delete, fences `id` in
/// this write's snapshot.
pub(in crate::runtime_hooks) fn source_erased_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn,
    id: &EntityId,
) -> Result<bool> {
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

/// What naming an erased actor left of a pinned input
/// ([`erase_input_actor`]).
enum ErasedActorInput {
    /// The input names the actor in no field its record names an actor in.
    Unchanged,
    /// The input, each such field that named the actor naming
    /// [`ERASED_CALL_IDENTITY`] instead.
    Named(String),
    /// The input names the actor and does not decode or encode again: its
    /// record retires its payload whole.
    Retired,
}

/// Names the erased `actor_hex` in a pinned `input` as
/// [`ERASED_CALL_IDENTITY`], the marker an erase leaves for an actor in the
/// records it keeps (FIX 812, FIX 22154, FIX 22178): `name` rewrites, in
/// the decoded input, each field its record names an actor in
/// ([`name_erased`]) and says whether any named `actor_hex`. An actor is no
/// run dependency: the run read its entity or its call's rows, not the
/// actor, so its reads, verdicts and outcome stay, and its digests stay as
/// they are.
fn erase_input_actor(
    input: Option<&str>,
    actor_hex: &str,
    name: impl FnOnce(&mut serde_json::Value) -> bool,
) -> ErasedActorInput {
    let Some(input) = input.filter(|input| input.contains(actor_hex)) else {
        return ErasedActorInput::Unchanged;
    };
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(input) else {
        return ErasedActorInput::Retired;
    };
    if !name(&mut value) {
        return ErasedActorInput::Unchanged;
    }
    serde_json::to_string(&value).map_or(ErasedActorInput::Retired, ErasedActorInput::Named)
}

/// Names [`ERASED_CALL_IDENTITY`] in `field` where it names `actor_hex`;
/// whether it did.
fn name_erased(field: Option<&mut serde_json::Value>, actor_hex: &str) -> bool {
    match field {
        Some(field) if field.as_str() == Some(actor_hex) => {
            *field = serde_json::Value::from(ERASED_CALL_IDENTITY);
            true
        }
        _ => false,
    }
}

/// [`erase_input_actor`] on a fact memo: the fact's actor, a claim's
/// writer or a settlement's settler. Returns whether `memo` changed.
fn erase_fact_actor(memo: &mut HookRunRecord, actor_hex: &str) -> bool {
    match erase_input_actor(memo.input_json.as_deref(), actor_hex, |value| {
        name_erased(value.pointer_mut("/fact/actor/principal"), actor_hex)
    }) {
        ErasedActorInput::Unchanged => return false,
        ErasedActorInput::Named(input) => memo.input_json = Some(input),
        ErasedActorInput::Retired => scrub_memo_payload(memo),
    }
    true
}

/// [`erase_input_actor`] on a verb run's saved copy: its caller, and in
/// each receipt of the caller's tail its actor and whom it was made on
/// behalf of. Returns whether `record` changed.
fn erase_verb_actor(record: &mut HookVerbRunRecord, actor_hex: &str) -> bool {
    match erase_input_actor(record.input_json.as_deref(), actor_hex, |value| {
        let mut named = name_erased(value.get_mut("actor"), actor_hex);
        if let Some(tail) = value
            .get_mut("receipt_tail")
            .and_then(serde_json::Value::as_array_mut)
        {
            for receipt in tail {
                named |= name_erased(receipt.get_mut("actor_ref"), actor_hex);
                named |= name_erased(receipt.pointer_mut("/fields/on_behalf_of"), actor_hex);
            }
        }
        named
    }) {
        ErasedActorInput::Unchanged => return false,
        ErasedActorInput::Named(input) => record.input_json = Some(input),
        ErasedActorInput::Retired => scrub_verb_payload(record),
    }
    true
}

/// Names [`ERASED_CALL_IDENTITY`] for whom a verb run's Hook receipt was
/// made, its caller, where that is the erased `actor_hex` (FIX 812, FIX
/// 22178). Returns whether `receipt` changed.
fn erase_receipt_caller(receipt: &mut ReceiptRecord, actor_hex: &str) -> bool {
    if receipt.on_behalf_of.as_deref() != Some(actor_hex) {
        return false;
    }
    receipt.on_behalf_of = Some(ERASED_CALL_IDENTITY.to_owned());
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

/// A verb run's commit write keeps out a caller, `actor`, that a permanent
/// erase fenced before it, from its saved copy and its Hook receipt, as the
/// erase's own scrub would have had the run committed first
/// ([`erase_verb_actor`], [`erase_receipt_caller`]; FIX 22178).
pub(in crate::runtime_hooks) fn scrub_erased_verb_actor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &mut HookVerbRunRecord,
    receipt: &mut ReceiptRecord,
    actor: EntityId,
) -> Result<()> {
    if source_erased_in_txn(vault, txn, &actor)? {
        let actor_hex = actor.to_hex();
        erase_verb_actor(record, &actor_hex);
        erase_receipt_caller(receipt, &actor_hex);
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
/// memo whose input names `id` as the fact's actor, every verb run and Hook
/// receipt that names `id` as the call's caller, every chain, raised check
/// and intent lineage that names it as a link's entity, and every
/// settlement, tick, due index and inbound row that names it, in the
/// caller's erase transaction. Complete scans avoid a second dependency
/// index; every matching row is retired before the erase or its sweep
/// declares completion.
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
    let mut lineage_intents = Vec::new();
    for row in INTENTS.iter_from(&vault.store, txn, &[])? {
        let (key, mut intent) = row?;
        let named = lineage::erase_entity(&mut intent.lineage, id);
        if intent
            .dependencies
            .iter()
            .any(|dependency| dependency.id == *id)
        {
            intents.push((key, intent));
        } else if named {
            lineage_intents.push((key, intent));
        }
    }
    for (key, mut intent) in intents {
        scrub_intent_payload(&mut intent, at);
        INTENTS.put(vault, txn, &key, &intent)?;
        affected_runs.insert(key);
    }
    // An intent whose lineage alone names `id`, as a verb run's caller or
    // the entity of a run behind it, keeps its payload: only the id leaves,
    // so the row it lands later names none (FIX 22184).
    for (key, intent) in &lineage_intents {
        INTENTS.put(vault, txn, key, intent)?;
    }

    let mut verb_runs = Vec::new();
    let mut actor_verb_runs = Vec::new();
    for row in VERB_RUNS.iter_from(&vault.store, txn, &[])? {
        let (key, mut record) = row?;
        if record.dependencies.contains(id)
            || record
                .reads
                .iter()
                .any(|pin| pin.rows.iter().any(|row| row.id == *id))
        {
            verb_runs.push((key, record));
        } else if erase_verb_actor(&mut record, &id_hex) {
            actor_verb_runs.push((key, record));
        }
    }
    for (key, mut record) in verb_runs {
        scrub_verb_payload(&mut record);
        VERB_RUNS.put(vault, txn, &key, &record)?;
        affected_runs.insert(key);
    }
    // A verb run stands on its call's rows, not on its caller: only the
    // caller's id leaves, and its intents and blocks stay (FIX 22178).
    for (key, record) in &actor_verb_runs {
        VERB_RUNS.put(vault, txn, key, record)?;
    }

    crate::runtime_hooks::block::scrub_blocks_in_txn(vault, txn, id, &affected_runs, at)?;

    let mut receipts = Vec::new();
    for row in RECEIPTS.iter_from(&vault.store, txn, &[])? {
        let (key, mut receipt) = row?;
        let caller = erase_receipt_caller(&mut receipt, &id_hex);
        if affected_runs.contains(&key) || receipt.trigger_ref.as_deref() == Some(id_hex.as_str()) {
            scrub_receipt_payload(&mut receipt);
        } else if !caller {
            continue;
        }
        receipts.push((key, receipt));
    }
    for (key, receipt) in &receipts {
        RECEIPTS.put(vault, txn, key, receipt)?;
    }

    lineage::scrub_erased_in_txn(vault, txn, id)?;
    crate::runtime_hooks::source::scrub_hook_feeds_in_txn(vault, txn, id)
}
