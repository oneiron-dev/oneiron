//! Source-erasure teardown for retained hook payloads. Identity, ordering,
//! digests and terminal status stay; source-derived bytes and pending work
//! that could resurrect them do not. A fact memo, verb run or Hook receipt
//! that names an erased actor names the erased marker instead, a verb run
//! whose caller's own args or result name an erased row retires as one that
//! depends on it, a hook feed row that names the erased id keeps only its
//! position, and hook lineage names no erased entity
//! ([`lineage::scrub_erased_in_txn`]). An id is scrubbed once
//! ([`SCRUBBED`]): from that write on, each carrier's writer keeps it out.

use std::collections::BTreeSet;

use serde_json::Value;

use super::*;
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::runtime_hooks::lineage;
use crate::runtime_hooks::verb::{HookVerbRunRecord, VERB_RUNS};

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

/// The ids one scrub or one write keeps out, with the hex ref a record
/// spells each by.
struct ErasedIds {
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
    fn named_in(&self, text: &str) -> bool {
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
    fn named_by_json(&self, text: &str) -> bool {
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

/// Names the erased marker for a fact memo's erased actor in its pinned
/// input: the fact's actor, a claim's writer or a settlement's settler. An
/// actor is no run dependency: the run read its entity, not the actor, so
/// its reads, verdicts and outcome stay, and its digests stay as they are.
/// An input that names an erased id and does not decode or encode again
/// loses its whole payload. Returns whether `memo` changed.
fn erase_fact_actor(memo: &mut HookRunRecord, erased: &ErasedIds) -> bool {
    let Some(input) = memo
        .input_json
        .as_deref()
        .filter(|input| erased.named_in(input))
    else {
        return false;
    };
    let Ok(mut value) = serde_json::from_str::<Value>(input) else {
        scrub_memo_payload(memo);
        return true;
    };
    if !name_erased(value.pointer_mut("/fact/actor/principal"), erased) {
        return false;
    }
    match serde_json::to_string(&value) {
        Ok(input) => memo.input_json = Some(input),
        Err(_) => scrub_memo_payload(memo),
    }
    true
}

/// What an erase does to a verb run's saved copy that depends on no erased
/// row ([`erase_verb_run`]).
enum VerbRunErase {
    /// Nothing in it names an erased id where a scrub looks.
    Unchanged,
    /// Its caller, or a tail receipt's actor, names the erased marker in
    /// place of an erased actor (FIX 22178); or its input names an erased id
    /// and does not decode, and lost its payload.
    Rewritten,
    /// Its caller's own args or result, or the args its landing was judged
    /// on, name an erased row: it retires as a run that depends on that row
    /// does (FIX 22191).
    Depends,
}

/// What `erased` does to `record`, rewritten in place for
/// [`VerbRunErase::Rewritten`]. The args and result name the rows the call
/// was about and can carry their bytes (an update's new body, a write's
/// echoed row), so an erased row named there retires the payload whole. An
/// actor is no row the run stood on, so only its id leaves, and the run's
/// reads, outcome and digests stay.
fn erase_verb_run(record: &mut HookVerbRunRecord, erased: &ErasedIds) -> VerbRunErase {
    if record.named_rows.iter().any(|row| erased.holds(row)) {
        return VerbRunErase::Depends;
    }
    if record
        .landing_original
        .as_deref()
        .is_some_and(|args| erased.named_by_json(args))
    {
        return VerbRunErase::Depends;
    }
    let Some(input) = record
        .input_json
        .as_deref()
        .filter(|input| erased.named_in(input))
    else {
        return VerbRunErase::Unchanged;
    };
    let Ok(mut value) = serde_json::from_str::<Value>(input) else {
        scrub_verb_payload(record);
        return VerbRunErase::Rewritten;
    };
    if ["args", "result"]
        .into_iter()
        .any(|field| value.get(field).is_some_and(|part| erased.named_by(part)))
    {
        return VerbRunErase::Depends;
    }
    if !name_erased_verb_actors(&mut value, erased) {
        return VerbRunErase::Unchanged;
    }
    match serde_json::to_string(&value) {
        Ok(input) => record.input_json = Some(input),
        Err(_) => scrub_verb_payload(record),
    }
    VerbRunErase::Rewritten
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
        erase_fact_actor(memo, &ErasedIds::new(BTreeSet::from([actor])));
    }
    Ok(())
}

/// A verb run's commit write keeps out what a permanent erase fenced before
/// it, as the erase's own scrub would have had the run committed first: an
/// erased caller, `actor`, or tail actor names the marker in its saved copy
/// and its Hook receipt (FIX 22178), and a run whose caller's own args or
/// result name an erased row keeps no payload in either (FIX 22191). Every
/// id its saved copy spells is checked, so a row erased while the chain ran
/// is caught in this write, not by a later sweep. Returns whether the
/// payload retired: the run's blocks and intents retire with it.
pub(in crate::runtime_hooks) fn scrub_erased_verb_run_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &mut HookVerbRunRecord,
    receipt: &mut ReceiptRecord,
    actor: EntityId,
) -> Result<bool> {
    let mut named = BTreeSet::from([actor]);
    named.extend(record.named_rows.iter().copied());
    for text in [
        record.input_json.as_deref(),
        record.landing_original.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        spelled_ids_in(text, &mut named);
    }
    let mut erased = BTreeSet::new();
    for id in named {
        if source_erased_in_txn(vault, txn, &id)? {
            erased.insert(id);
        }
    }
    if erased.is_empty() {
        return Ok(false);
    }
    let erased = ErasedIds::new(erased);
    erase_receipt_caller(receipt, &erased);
    match erase_verb_run(record, &erased) {
        VerbRunErase::Depends => {
            scrub_verb_payload(record);
            scrub_receipt_payload(receipt);
            Ok(true)
        }
        VerbRunErase::Unchanged | VerbRunErase::Rewritten => Ok(false),
    }
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
/// write. An id cleaned before costs one point read and no write, so a
/// sweep with no newly erased id writes nothing (FIX 22191).
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
    vault.with_write_txn_grouped(|txn| scrub_hook_sources_in_txn(vault, txn, &unscrubbed, at))
}

/// Scrubs every retained hook carrier that names one of `ids`, in one walk
/// of each carrier table for them all, in the caller's write: every memo,
/// intent and verb run that depends on one, every verb run whose caller's
/// own args or result name one, and the blocks, intents and receipts of
/// those runs; every fact memo whose input names one as the fact's actor;
/// every verb run and Hook receipt that names one as the call's caller or a
/// tail receipt's actor; every chain, raised check and intent lineage that
/// names one as a link's entity; and every settlement, tick, due index and
/// inbound row that names one. Complete scans avoid a second dependency
/// index. Each id whose permanent hard-delete marker stands in this write is
/// then marked scrubbed ([`SCRUBBED`]); any other is scrubbed again by the
/// next sweep that holds it.
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
        } else if erase_fact_actor(&mut memo, &erased) {
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

    let mut verb_runs = Vec::new();
    let mut actor_verb_runs = Vec::new();
    for row in VERB_RUNS.iter_from(&vault.store, txn, &[])? {
        let (key, mut record) = row?;
        if record.dependencies.iter().any(|id| erased.holds(id))
            || record
                .reads
                .iter()
                .any(|pin| pin.rows.iter().any(|row| erased.holds(&row.id)))
        {
            verb_runs.push((key, record));
            continue;
        }
        match erase_verb_run(&mut record, &erased) {
            VerbRunErase::Unchanged => {}
            VerbRunErase::Rewritten => actor_verb_runs.push((key, record)),
            VerbRunErase::Depends => verb_runs.push((key, record)),
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
