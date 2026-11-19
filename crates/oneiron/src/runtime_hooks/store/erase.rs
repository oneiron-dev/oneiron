//! Source-erasure teardown for retained hook payloads. Identity, ordering,
//! digests and terminal status stay; source-derived bytes and pending work
//! that could resurrect them do not. A fact memo, verb run or Hook receipt
//! that names an erased actor names the erased marker instead; a fact memo
//! whose input names an erased row anywhere else, and a verb run whose
//! caller's own args or result name one, retires as one that depends on it;
//! a stopped or paced call whose saved args name one ends; a hook feed row
//! that names the erased id keeps only its position; and hook lineage names
//! no erased entity ([`lineage::scrub_erased_in_txn`]). A session-only
//! call's kept runs are reached in its session's own store ([`kept`]). An
//! id is scrubbed once ([`SCRUBBED`]): from that write on, each carrier's
//! writer keeps it out.

mod kept;

use std::collections::BTreeSet;

use serde_json::Value;

use super::*;
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::runtime_hooks::lineage;
use crate::runtime_hooks::verb::{self, HookVerbRunRecord, VERB_RUNS};

pub(crate) use kept::scrub_erased_in_session_stores;

const ERASED_HISTORY_REASON: &str = "source history erased";

/// Each permanently erased id whose hook carriers a scrub cleaned, with the
/// time of that write (Unix seconds). The hard-erase sweep scrubs only the
/// ids not here: from the marking write on, every carrier's writer keeps
/// the id out ([`source_erased_in_txn`]), so no carrier needs it scrubbed
/// again (FIX 22191).
const SCRUBBED: SideTable<EntityId, u64, Named> =
    SideTable::new(&side_table::HOOKS_SCRUBBED_SOURCE);

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
    for dependency in dependencies {
        if source_erased_in_txn(vault, txn, &dependency.id)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The permanently erased ids, in this snapshot, among `named` and those
/// `texts` can spell ([`spelled_ids_in`]); `None` when none is.
fn erased_among_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    mut named: BTreeSet<EntityId>,
    texts: &[&str],
) -> Result<Option<ErasedIds>> {
    for text in texts {
        spelled_ids_in(text, &mut named);
    }
    let mut erased = BTreeSet::new();
    for id in named {
        if source_erased_in_txn(vault, txn, &id)? {
            erased.insert(id);
        }
    }
    Ok((!erased.is_empty()).then(|| ErasedIds::new(erased)))
}

/// The erased ids the JSON `args` a stopped, paced or paused call keeps
/// name, in this snapshot: every id they spell is checked and the whole
/// value scanned ([`ErasedIds::named_by_json`]), never a fixed list of
/// fields. `None` when they name none. Such a call never runs on that row
/// or shows it (FIX 22240).
pub(in crate::runtime_hooks) fn erased_by_args_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    args: &str,
) -> Result<Option<ErasedIds>> {
    Ok(erased_among_in_txn(vault, txn, BTreeSet::new(), &[args])?
        .filter(|erased| erased.named_by_json(args)))
}

/// Whether [`erased_by_args_in_txn`] finds any, in a snapshot of its own.
pub(in crate::runtime_hooks) fn args_erased(vault: &Vault, args: &str) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(erased_by_args_in_txn(vault, &rtxn, args)?.is_some())
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

/// The ids one scrub or one write keeps out, with the hex ref a record
/// spells each by.
pub(in crate::runtime_hooks) struct ErasedIds {
    ids: BTreeSet<EntityId>,
    refs: BTreeSet<String>,
}

impl ErasedIds {
    fn new(ids: BTreeSet<EntityId>) -> Self {
        let refs = ids.iter().map(EntityId::to_hex).collect();
        Self { ids, refs }
    }

    fn holds(&self, id: &EntityId) -> bool {
        self.ids.contains(id)
    }

    /// Whether `text` holds the ref of one anywhere: the cheap test before
    /// a pinned input is decoded.
    pub(in crate::runtime_hooks) fn named_in(&self, text: &str) -> bool {
        self.refs
            .iter()
            .any(|reference| text.contains(reference.as_str()))
    }

    /// Whether `text` is the ref of one.
    fn is_ref(&self, text: &str) -> bool {
        self.refs.contains(text)
    }

    /// Whether `value` names one ([`named_ids`]).
    fn named_by(&self, value: &Value) -> bool {
        let mut named = BTreeSet::new();
        named_ids(value, &mut named);
        !named.is_disjoint(&self.ids)
    }

    /// Whether the JSON `text` names one; text that holds a ref and does not
    /// decode names it.
    pub(in crate::runtime_hooks) fn named_by_json(&self, text: &str) -> bool {
        self.named_in(text)
            && serde_json::from_str::<Value>(text)
                .ok()
                .is_none_or(|value| self.named_by(&value))
    }
}

/// Adds to `ids` each id `text` names: every run of exactly 32 lowercase
/// hex digits that reads as one, as a record spells an id. A longer run,
/// such as a digest, names none.
fn hex_ids_in(text: &str, ids: &mut BTreeSet<EntityId>) {
    for token in text.split(|digit: char| !matches!(digit, '0'..='9' | 'a'..='f')) {
        if token.len() == 32
            && let Ok(id) = EntityId::from_hex(token)
        {
            ids.insert(id);
        }
    }
}

/// The rows a verb run's caller named in its own args and result, and in
/// the args its landing was judged on ([`named_ids`]), read from the whole
/// input before the pin bound drops any of it (review #6817): a row named
/// there can carry its bytes into the run's outcome. Text that does not
/// decode names every id it spells.
pub(in crate::runtime_hooks) fn rows_named_by_call(
    input: &str,
    landing_original: Option<&str>,
) -> Vec<EntityId> {
    let mut rows = BTreeSet::new();
    match serde_json::from_str::<Value>(input) {
        Ok(value) => {
            for field in ["args", "result"] {
                if let Some(part) = value.get(field) {
                    named_ids(part, &mut rows);
                }
            }
        }
        Err(_) => spelled_ids_in(input, &mut rows),
    }
    if let Some(args) = landing_original {
        match serde_json::from_str::<Value>(args) {
            Ok(value) => named_ids(&value, &mut rows),
            Err(_) => spelled_ids_in(args, &mut rows),
        }
    }
    rows.into_iter().collect()
}

/// The rows a fact run's whole `input` names anywhere but as the fact's
/// actor (`/fact/actor/principal`), whose erase only renames it: read
/// before the pin bound drops the input, so an erase of one retires the
/// memo even when its input was not kept (FIX 22240). An input that does
/// not decode names every id it can spell.
pub(in crate::runtime_hooks) fn rows_named_by_fact(input: &str) -> Vec<EntityId> {
    let mut rows = BTreeSet::new();
    match serde_json::from_str::<Value>(input) {
        Ok(mut value) => {
            if let Some(actor) = value.pointer_mut("/fact/actor/principal") {
                *actor = Value::Null;
            }
            named_ids(&value, &mut rows);
        }
        Err(_) => spelled_ids_in(input, &mut rows),
    }
    rows.into_iter().collect()
}

/// Adds to `ids` each id the JSON `text` can spell in a string or key once
/// decoded ([`hex_ids_in`]): a run of 32 lowercase hex digits, or the last
/// 32 of a longer run, as an escape such as `\b` or `\u001f` lengthens a
/// run on its left. A superset, each one checked before it counts.
fn spelled_ids_in(text: &str, ids: &mut BTreeSet<EntityId>) {
    for token in text.split(|digit: char| !matches!(digit, '0'..='9' | 'a'..='f')) {
        if let Some(start) = token.len().checked_sub(32)
            && let Ok(id) = EntityId::from_hex(&token[start..])
        {
            ids.insert(id);
        }
    }
}

/// [`hex_ids_in`] over every string and key of `value`.
fn named_ids(value: &Value, ids: &mut BTreeSet<EntityId>) {
    match value {
        Value::String(text) => hex_ids_in(text, ids),
        Value::Array(items) => {
            for item in items {
                named_ids(item, ids);
            }
        }
        Value::Object(fields) => {
            for (key, field) in fields {
                hex_ids_in(key, ids);
                named_ids(field, ids);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Names [`ERASED_CALL_IDENTITY`] in `field` where it is the ref of an
/// erased actor; whether it did. The marker is the one an erase leaves for
/// an actor in the records it keeps (FIX 812, FIX 22154, FIX 22178).
fn name_erased(field: Option<&mut Value>, erased: &ErasedIds) -> bool {
    match field {
        Some(field) if field.as_str().is_some_and(|text| erased.is_ref(text)) => {
            *field = Value::from(ERASED_CALL_IDENTITY);
            true
        }
        _ => false,
    }
}

/// What an erase does to a run's saved copy ([`erase_fact_memo`],
/// [`erase_verb_run`]).
enum RunErase {
    /// Nothing in it names an erased id where a scrub looks.
    Unchanged,
    /// An erased actor in it names the erased marker in its place (FIX
    /// 22178); or its input names an erased id and does not decode, and
    /// lost its payload.
    Rewritten,
    /// It read or showed an erased row, or names one where that row's bytes
    /// can ride (a verb caller's own args or result, the args its landing
    /// was judged on, anywhere else in a fact's input): it retires as a run
    /// that depends on that row does (FIX 22191, FIX 22240).
    Depends,
}

/// What `erased` does to a fact memo that depends on no erased row,
/// rewritten in place for [`RunErase::Rewritten`]. The fact's actor (a
/// claim's writer, a settlement's settler) is no run dependency: the run
/// read its entity, not the actor, so only its id leaves, named as the
/// erased marker, and the run's reads, verdicts, outcome and digests stay.
/// Any other erased id the input names, anywhere in it, retires the memo
/// as a dependency's erase does, as the input can carry that row's bytes
/// (FIX 22240). An input that names an erased id and does not decode or
/// encode again loses its whole payload.
fn erase_fact_memo(memo: &mut HookRunRecord, erased: &ErasedIds) -> RunErase {
    // Read from the whole input, so an input past the pin bound is reached
    // too (review #6848).
    if memo.named_rows.iter().any(|row| erased.holds(row)) {
        return RunErase::Depends;
    }
    let Some(input) = memo
        .input_json
        .as_deref()
        .filter(|input| erased.named_in(input))
    else {
        return RunErase::Unchanged;
    };
    let Ok(mut value) = serde_json::from_str::<Value>(input) else {
        scrub_memo_payload(memo);
        return RunErase::Rewritten;
    };
    let renamed = name_erased(value.pointer_mut("/fact/actor/principal"), erased);
    if erased.named_by(&value) {
        return RunErase::Depends;
    }
    if !renamed {
        return RunErase::Unchanged;
    }
    match serde_json::to_string(&value) {
        Ok(input) => memo.input_json = Some(input),
        Err(_) => scrub_memo_payload(memo),
    }
    RunErase::Rewritten
}

/// What `erased` does to a verb run's saved copy, rewritten in place for
/// [`RunErase::Rewritten`]. A run that read or showed an erased row depends
/// on it. The args and result name the rows the call was about and can
/// carry their bytes (an update's new body, a write's echoed row), so an
/// erased row named there retires the payload whole. An actor is no row
/// the run stood on, so only its id leaves, and the run's reads, outcome
/// and digests stay.
fn erase_verb_run(record: &mut HookVerbRunRecord, erased: &ErasedIds) -> RunErase {
    if record
        .dependencies
        .iter()
        .chain(&record.named_rows)
        .any(|row| erased.holds(row))
        || record
            .reads
            .iter()
            .any(|pin| pin.rows.iter().any(|row| erased.holds(&row.id)))
    {
        return RunErase::Depends;
    }
    if record
        .landing_original
        .as_deref()
        .is_some_and(|args| erased.named_by_json(args))
    {
        return RunErase::Depends;
    }
    let Some(input) = record
        .input_json
        .as_deref()
        .filter(|input| erased.named_in(input))
    else {
        return RunErase::Unchanged;
    };
    let Ok(mut value) = serde_json::from_str::<Value>(input) else {
        scrub_verb_payload(record);
        return RunErase::Rewritten;
    };
    if ["args", "result"]
        .into_iter()
        .any(|field| value.get(field).is_some_and(|part| erased.named_by(part)))
    {
        return RunErase::Depends;
    }
    if !name_erased_verb_actors(&mut value, erased) {
        return RunErase::Unchanged;
    }
    match serde_json::to_string(&value) {
        Ok(input) => record.input_json = Some(input),
        Err(_) => scrub_verb_payload(record),
    }
    RunErase::Rewritten
}

/// Names the erased marker for each erased actor in a verb run's decoded
/// input: its caller, and in each receipt of the caller's tail its actor and
/// whom it was made on behalf of. Returns whether it named any.
fn name_erased_verb_actors(value: &mut Value, erased: &ErasedIds) -> bool {
    let mut named = name_erased(value.get_mut("actor"), erased);
    if let Some(tail) = value.get_mut("receipt_tail").and_then(Value::as_array_mut) {
        for receipt in tail {
            named |= name_erased(receipt.get_mut("actor_ref"), erased);
            named |= name_erased(receipt.pointer_mut("/fields/on_behalf_of"), erased);
        }
    }
    named
}

/// Names [`ERASED_CALL_IDENTITY`] for whom a verb run's Hook receipt was
/// made, its caller, where that is erased (FIX 812, FIX 22178). Returns
/// whether `receipt` changed.
fn erase_receipt_caller(receipt: &mut ReceiptRecord, erased: &ErasedIds) -> bool {
    if !receipt
        .on_behalf_of
        .as_deref()
        .is_some_and(|caller| erased.is_ref(caller))
    {
        return false;
    }
    receipt.on_behalf_of = Some(ERASED_CALL_IDENTITY.to_owned());
    true
}

/// A fact run's commit write keeps out what a permanent erase fenced before
/// it, as the erase's own scrub would have had the run committed first
/// ([`erase_fact_memo`]): an erased `actor` names the marker, and an input
/// that names any other erased id retires the memo. Every id the input
/// spells is checked. Returns whether the memo retires as one that depends
/// on an erased row: its intent, blocks and lineage then go as a
/// dependency's erase takes them.
pub(in crate::runtime_hooks) fn scrub_erased_memo_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    memo: &mut HookRunRecord,
    actor: EntityId,
) -> Result<bool> {
    let mut named = BTreeSet::from([actor]);
    named.extend(memo.named_rows.iter().copied());
    let input = memo.input_json.as_deref();
    let Some(erased) = erased_among_in_txn(vault, txn, named, input.as_slice())? else {
        return Ok(false);
    };
    Ok(matches!(erase_fact_memo(memo, &erased), RunErase::Depends))
}

/// A verb run's write keeps out what a permanent erase fenced before it,
/// as the erase's own scrub would have had the run landed first: an erased
/// caller or tail actor names the marker in its saved copy and its Hook
/// receipt (FIX 22178), and a run that read or showed an erased row, or
/// whose caller's own args or result name one, keeps no payload in either
/// (FIX 22191). Every id its saved copy and its receipt's caller spell is
/// checked, so a row erased while the chain ran is caught in this write,
/// not by a later sweep. A chain's commit and a session's keep of the runs
/// it held both land each run through it (FIX 22240). Returns whether the
/// payload retired: the run's blocks and intents retire with it.
pub(in crate::runtime_hooks) fn scrub_erased_verb_run_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &mut HookVerbRunRecord,
    receipt: &mut ReceiptRecord,
) -> Result<bool> {
    let named = record
        .dependencies
        .iter()
        .chain(&record.named_rows)
        .copied()
        .chain(
            record
                .reads
                .iter()
                .flat_map(|pin| pin.rows.iter().map(|row| row.id)),
        )
        .collect();
    let erased = {
        let texts: Vec<&str> = [
            receipt.on_behalf_of.as_deref(),
            record.input_json.as_deref(),
            record.landing_original.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect();
        erased_among_in_txn(vault, txn, named, &texts)?
    };
    let Some(erased) = erased else {
        return Ok(false);
    };
    erase_receipt_caller(receipt, &erased);
    if !matches!(erase_verb_run(record, &erased), RunErase::Depends) {
        return Ok(false);
    }
    scrub_verb_payload(record);
    scrub_receipt_payload(receipt);
    Ok(true)
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

/// Retires the vault's intent and blocks of each run in `retired`, a run a
/// session keeps whose payload an erase retired (FIX 22240): a session-only
/// call with no room overlay lands its hooks' intents and blocks in the
/// vault under each run's key, while the run stays in the session's store,
/// where the vault's scrub does not see it retire.
pub(in crate::runtime_hooks) fn retire_kept_runs_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    retired: &BTreeSet<RunKey>,
    at: u64,
) -> Result<()> {
    if retired.is_empty() {
        return Ok(());
    }
    for key in retired {
        if let Some(mut intent) = INTENTS.get(&vault.store, txn, key)? {
            scrub_intent_payload(&mut intent, at);
            INTENTS.put(vault, txn, key, &intent)?;
        }
    }
    crate::runtime_hooks::block::scrub_blocks_in_txn(vault, txn, &BTreeSet::new(), retired, at)
}

/// The erase door's hook scrub: [`scrub_hook_sources_in_txn`] for `id`
/// alone, in the caller's erase transaction.
pub(crate) fn scrub_hook_source_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    at: u64,
) -> Result<()> {
    scrub_hook_sources_in_txn(vault, txn, &BTreeSet::from([*id]), at)
}

/// The hard-erase sweep's hook scrub (FIX 10080): the ids of `erased` that
/// no scrub has cleaned yet ([`SCRUBBED`]) are scrubbed together in one
/// write, then in each session's own store ([`kept`]). An id cleaned before
/// costs one point read and no write, so a sweep with no newly erased id
/// writes nothing (FIX 22191).
pub(crate) fn scrub_erased_hook_sources(
    vault: &Vault,
    erased: &BTreeSet<EntityId>,
    at: u64,
) -> Result<()> {
    let unscrubbed = {
        let rtxn = vault.store.env.read_txn()?;
        let mut unscrubbed = BTreeSet::new();
        for id in erased {
            if !SCRUBBED.contains(&vault.store, &rtxn, id)? {
                unscrubbed.insert(*id);
            }
        }
        unscrubbed
    };
    if unscrubbed.is_empty() {
        return Ok(());
    }
    vault.with_write_txn_grouped(|txn| scrub_hook_sources_in_txn(vault, txn, &unscrubbed, at))?;
    let ids: Vec<EntityId> = unscrubbed.into_iter().collect();
    scrub_erased_in_session_stores(vault, &ids);
    Ok(())
}

/// Forgets that a scrub cleaned `id`, in the caller's write (FIX 22240):
/// a stale `dt:` marker's neutralization lifts the marker that scrub was
/// marked under, so a later real erase of the same id is scrubbed again.
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub(crate) fn forget_scrubbed_source_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    SCRUBBED.delete(&vault.store, txn, id).map(drop)
}

/// Scrubs every retained hook carrier that names one of `ids`, in one walk
/// of each carrier table for them all, in the caller's write: every memo,
/// intent and verb run that depends on one, every fact memo whose input
/// names one other than as the fact's actor, every verb run whose caller's
/// own args or result name one, and the blocks, intents and receipts of
/// those runs; every fact memo whose input names one as the fact's actor;
/// every verb run and Hook receipt that names one as the call's caller or a
/// tail receipt's actor; every chain, raised check and intent lineage that
/// names one as a link's entity; every settlement, tick, due index and
/// inbound row that names one; and every stopped or paced call whose saved
/// args name one. Complete scans avoid a second dependency index. Each id
/// whose permanent hard-delete marker stands in this write is then marked
/// scrubbed ([`SCRUBBED`]); any other is scrubbed again by the next sweep
/// that holds it.
fn scrub_hook_sources_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ids: &BTreeSet<EntityId>,
    at: u64,
) -> Result<()> {
    let erased = ErasedIds::new(ids.clone());
    let mut affected_runs = BTreeSet::new();

    let mut memos = Vec::new();
    let mut actor_memos = Vec::new();
    for row in MEMOS.iter_from(&vault.store, txn, &[])? {
        let (key, mut memo) = row?;
        if memo
            .derivation
            .dependencies
            .iter()
            .any(|dependency| erased.holds(&dependency.id))
        {
            memos.push((key, memo));
            continue;
        }
        match erase_fact_memo(&mut memo, &erased) {
            RunErase::Unchanged => {}
            RunErase::Rewritten => actor_memos.push((key, memo)),
            RunErase::Depends => memos.push((key, memo)),
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

    let mut verb_runs = Vec::new();
    let mut actor_verb_runs = Vec::new();
    for row in VERB_RUNS.iter_from(&vault.store, txn, &[])? {
        let (key, mut record) = row?;
        match erase_verb_run(&mut record, &erased) {
            RunErase::Unchanged => {}
            RunErase::Rewritten => actor_verb_runs.push((key, record)),
            RunErase::Depends => verb_runs.push((key, record)),
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

    let mut intents = Vec::new();
    let mut lineage_intents = Vec::new();
    for row in INTENTS.iter_from(&vault.store, txn, &[])? {
        let (key, mut intent) = row?;
        let named = lineage::erase_entities(&mut intent.lineage, |entity| erased.holds(entity));
        if affected_runs.contains(&key)
            || intent
                .dependencies
                .iter()
                .any(|dependency| erased.holds(&dependency.id))
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
    // An intent whose lineage alone names an erased id, as a verb run's
    // caller or the entity of a run behind it, keeps its payload: only the
    // id leaves, so the row it lands later names none (FIX 22184).
    for (key, intent) in &lineage_intents {
        INTENTS.put(vault, txn, key, intent)?;
    }

    crate::runtime_hooks::block::scrub_blocks_in_txn(vault, txn, ids, &affected_runs, at)?;

    let mut receipts = Vec::new();
    for row in RECEIPTS.iter_from(&vault.store, txn, &[])? {
        let (key, mut receipt) = row?;
        let caller = erase_receipt_caller(&mut receipt, &erased);
        if affected_runs.contains(&key)
            || receipt
                .trigger_ref
                .as_deref()
                .is_some_and(|trigger| erased.is_ref(trigger))
        {
            scrub_receipt_payload(&mut receipt);
        } else if !caller {
            continue;
        }
        receipts.push((key, receipt));
    }
    for (key, receipt) in &receipts {
        RECEIPTS.put(vault, txn, key, receipt)?;
    }

    lineage::scrub_erased_in_txn(vault, txn, ids)?;
    crate::runtime_hooks::source::scrub_hook_feeds_in_txn(vault, txn, ids)?;
    // A stopped or paced call whose saved args name an erased row ends, so
    // it never runs on that row or shows it (FIX 22240).
    verb::scrub_erased_asks_in_txn(vault, txn, &erased, at)?;
    verb::scrub_erased_paced_in_txn(vault, txn, &erased, at)?;
    // The mark rides the scrub's own write, and only for an id whose
    // permanent hard-delete marker stands in it: from here on each carrier's
    // writer keeps that id out ([`source_erased_in_txn`]), so no later sweep
    // scrubs it again. An archive's marker is lifted by its restore, so it
    // marks nothing.
    for id in ids {
        if vault.local_hard_delete_marker_exists_in_txn(txn, id)? {
            SCRUBBED.put(&vault.store, txn, id, &at)?;
        }
    }
    Ok(())
}
