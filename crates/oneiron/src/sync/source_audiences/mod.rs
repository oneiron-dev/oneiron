//! Source audiences on the owner's full-window lane (Engine A, 6 Nov 03:46;
//! SYNC-3). A window's `source_audiences` map carries, beside each bound row
//! it carries, the policy the row was born under and, for a thread policy,
//! its source policy: what the receiver needs to read the row as this vault
//! reads it.
//!
//! Keys, in canonical lowercase hex; values are Named MessagePack:
//!
//! - `record/<row>`: the policy id the row is bound to;
//! - `policy/<policy>/<revision>`: one revision of a policy, the revision
//!   spelled in sixteen hex digits and equal to the policy's own.
//!
//! Each revision a window holds stays beside the others, so the highest
//! wins however Loro orders them, and two unequal copies of one revision
//! are refused ([`crate::source_audience::merge_policy_in_txn`]). A binding
//! never moves. The lane is the authority: no signature is asked for. A
//! selector, a federation and every restricted lane carry none of this map,
//! and a foreign copy of it is refused at their input.

pub(in crate::sync) mod checkpoint;
mod erased;

use std::collections::{BTreeMap, BTreeSet};

use loro::{CommitOptions, LoroDoc, LoroMap, LoroValue, ValueOrContainer};

use super::bridge::BRIDGE_ORIGIN;
use super::loro_support::{map_delete, map_get_bytes, map_insert_bytes};
use super::types::WindowKey;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::source_audience::carried::{
    Carrier, CarrierKey, carrier, encode_binding, encode_policy, named, parse_key, policy_key,
    policy_prefix, record_key,
};
use crate::source_audience::{self, ReplicaMerge, SourceAudienceKind, SourceAudiencePolicy};

pub(crate) use erased::erase_carriers_in_txn;

/// The window map that carries source audiences.
pub(crate) const SOURCE_AUDIENCES_MAP: &str = "source_audiences";

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("source audience carrier refused: {reason}"))
}

/// Whether `doc` holds the map. Looking a root up by name creates it: look
/// first where nothing else would. Reading the whole value costs the whole
/// document, so a per-row path takes the map directly, as a loaded window's
/// observer already has.
fn holds_map(doc: &LoroDoc) -> bool {
    matches!(doc.get_value(), LoroValue::Map(roots) if roots.contains_key(SOURCE_AUDIENCES_MAP))
}

/// Every entry `map` holds: its key and its bytes, `None` for a value that
/// is not bytes or a nested container.
fn entries(map: &LoroMap) -> Vec<(String, Option<Vec<u8>>)> {
    let mut entries = Vec::new();
    map.for_each(|map_key, value| {
        let bytes = match value {
            ValueOrContainer::Value(LoroValue::Binary(bytes)) => Some(bytes.to_vec()),
            _ => None,
        };
        entries.push((map_key.to_owned(), bytes));
    });
    entries
}

/// The carried entries `map` holds that decode; the rest are left out.
fn carriers(map: &LoroMap) -> Vec<(String, Carrier)> {
    entries(map)
        .into_iter()
        .filter_map(|(map_key, bytes)| {
            let carried = carrier(&map_key, &bytes?).ok()?;
            Some((map_key, carried))
        })
        .collect()
}

/// The highest revision of `policy` `map` carries; `Err` when a copy of it
/// does not decode.
fn carried_head(map: &LoroMap, policy: &EntityId) -> Result<Option<SourceAudiencePolicy>> {
    let prefix = policy_prefix(policy);
    let mut head: Option<SourceAudiencePolicy> = None;
    for (map_key, bytes) in entries(map) {
        if !map_key.starts_with(&prefix) {
            continue;
        }
        let bytes = bytes.ok_or_else(|| refused("a policy that is not bytes"))?;
        let Carrier::Policy { policy, .. } = carrier(&map_key, &bytes)? else {
            return Err(refused("a policy key holding a binding"));
        };
        if head
            .as_ref()
            .is_none_or(|held| policy.revision > held.revision)
        {
            head = Some(policy);
        }
    }
    Ok(head)
}

// ---------------------------------------------------------------------------
// Admission: the full-window door validates every value an update can leave.
// ---------------------------------------------------------------------------

/// The bindings and policy revisions met across one admitted range: the
/// window's held map, a snapshot's latest map and shallow root, and every
/// retained insert. Two bindings of one row, or two unequal copies of one
/// policy revision, refuse the range, whichever Loro would keep.
#[derive(Debug, Default)]
pub(crate) struct AdmissionRows {
    bindings: BTreeMap<EntityId, EntityId>,
    versions: BTreeMap<(EntityId, u64), Vec<u8>>,
}

impl AdmissionRows {
    /// Notes what `doc`'s own map holds, admitted already.
    pub(crate) fn note_held(&mut self, doc: &LoroDoc) {
        if !holds_map(doc) {
            return;
        }
        for (map_key, bytes) in entries(&doc.get_map(SOURCE_AUDIENCES_MAP)) {
            let Some(bytes) = bytes else {
                continue;
            };
            match carrier(&map_key, &bytes) {
                Ok(Carrier::Record { row, policy }) => {
                    self.bindings.entry(row).or_insert(policy);
                }
                Ok(Carrier::Policy { id, policy }) => {
                    self.versions.entry((id, policy.revision)).or_insert(bytes);
                }
                Err(_) => {}
            }
        }
    }
}

/// Admits one value under `map_key` of the map: a canonical binding or
/// policy revision that contradicts nothing met in the range, nor, with
/// `vault`, the binding or the policy this vault holds.
///
/// # Errors
///
/// The refusal; storage failures.
pub(crate) fn admit_carrier(
    vault: Option<&Vault>,
    map_key: &str,
    value: &LoroValue,
    seen: &mut AdmissionRows,
) -> Result<()> {
    let LoroValue::Binary(bytes) = value else {
        return Err(refused("not bytes"));
    };
    let bytes: &[u8] = bytes;
    match carrier(map_key, bytes)? {
        Carrier::Record { row, policy } => {
            if seen
                .bindings
                .insert(row, policy)
                .is_some_and(|held| held != policy)
            {
                return Err(refused("two bindings of one row"));
            }
            if let Some(vault) = vault {
                let rtxn = vault.store.env.read_txn()?;
                if source_audience::binding_in(vault, &rtxn, &row)?
                    .is_some_and(|held| held != policy)
                {
                    return Err(refused("a row's binding moved"));
                }
            }
        }
        Carrier::Policy { id, policy } => {
            if seen
                .versions
                .insert((id, policy.revision), bytes.to_vec())
                .is_some_and(|held| held != bytes)
            {
                return Err(refused("two copies of one policy revision"));
            }
            if let Some(vault) = vault {
                let rtxn = vault.store.env.read_txn()?;
                if source_audience::policy_conflicts_in(vault, &rtxn, &id, &policy)? {
                    return Err(refused("a policy revision contradicts the one held"));
                }
            }
        }
    }
    Ok(())
}

/// [`admit_carrier`] over every value `map` holds; a nested container
/// refuses.
///
/// # Errors
///
/// The refusal; storage failures.
pub(crate) fn admit_map(
    vault: Option<&Vault>,
    map: &LoroMap,
    seen: &mut AdmissionRows,
) -> Result<()> {
    let mut values = Vec::new();
    let mut nested = false;
    map.for_each(|map_key, value| match value {
        ValueOrContainer::Value(value) => values.push((map_key.to_owned(), value)),
        ValueOrContainer::Container(_) => nested = true,
    });
    if nested {
        return Err(refused("nested container"));
    }
    for (map_key, value) in &values {
        admit_carrier(vault, map_key, value, seen)?;
    }
    Ok(())
}

/// Refuses a detached input that carries the map: a selector's or a
/// federation's copy never brings a policy assertion (L02 3, 6 Nov 06:24).
///
/// # Errors
///
/// The refusal.
pub(crate) fn refuse_foreign_map(doc: &LoroDoc) -> Result<()> {
    if holds_map(doc) && !doc.get_map(SOURCE_AUDIENCES_MAP).is_empty() {
        return Err(refused(
            "a source audience map off the owner's full-window lane",
        ));
    }
    Ok(())
}

/// The row a carried key's binding rides with: `record/<row>`'s row; a
/// policy key names no row.
pub(crate) fn record_owner(map_key: &str) -> Option<EntityId> {
    match parse_key(map_key)? {
        CarrierKey::Record(row) => Some(row),
        CarrierKey::Policy(..) => None,
    }
}

/// Whether `doc` carries a binding for `row`, materialized here or not: an
/// obligation a restricted lane honours (L02 2).
pub(crate) fn carries_record(doc: &LoroDoc, row: &EntityId) -> bool {
    map_get_bytes(&doc.get_map(SOURCE_AUDIENCES_MAP), &record_key(row)).is_some()
}

// ---------------------------------------------------------------------------
// Publication: a bound row rides with its binding and its policy closure.
// ---------------------------------------------------------------------------

/// Writes `value` under `map_key`; an equal carrier stands, and another one
/// is refused: neither a binding nor a policy revision ever changes.
fn write_immutable(map: &LoroMap, map_key: &str, value: &[u8]) -> Result<bool> {
    match map_get_bytes(map, map_key) {
        Some(held) if held == value => Ok(false),
        Some(_) => Err(refused("a carried binding or policy revision would change")),
        None => {
            map_insert_bytes(map, map_key, value)?;
            Ok(true)
        }
    }
}

/// One bound row as it is published: the row, its policy, and that
/// policy's closure.
type Published = (EntityId, EntityId, Vec<(EntityId, SourceAudiencePolicy)>);

/// The binding and the published closure of each bound row of `rows`,
/// read in one snapshot: a row whose closure does not resolve is left out.
fn published_of(vault: &Vault, rows: &BTreeSet<EntityId>) -> Result<Vec<Published>> {
    let rtxn = vault.store.env.read_txn()?;
    if !source_audience::any_policy_in(vault, &rtxn)? {
        return Ok(Vec::new());
    }
    let mut published = Vec::new();
    for row in rows {
        let Some(policy) = source_audience::binding_in(vault, &rtxn, row)? else {
            continue;
        };
        // A row whose closure does not publish keeps what the window holds;
        // its packing door keeps a new one home.
        if !source_audience::publishable_in(vault, &rtxn, &policy)? {
            continue;
        }
        if let Some(closure) = source_audience::policy_closure_in(vault, &rtxn, &policy)? {
            published.push((*row, policy, closure));
        }
    }
    Ok(published)
}

/// Writes into `map` each binding and policy revision `published` names.
fn write_published(map: &LoroMap, published: &[Published]) -> Result<bool> {
    let mut wrote = false;
    for (row, policy, closure) in published {
        wrote |= write_immutable(map, &record_key(row), &encode_binding(policy)?)?;
        for (id, held) in closure {
            wrote |= write_immutable(map, &policy_key(id, held.revision), &encode_policy(held)?)?;
        }
    }
    Ok(wrote)
}

/// Mirrors the binding of the row `id` and its policy closure into `doc`,
/// read in one snapshot, beside the row's carrier: the binding never moves,
/// and each policy goes under its own revision. A row bound nowhere, or
/// whose closure does not resolve, writes nothing (the packing door keeps
/// such a row home). Whether the map changed; the caller commits, in the
/// commit that carries the row.
///
/// # Errors
///
/// Storage and codec failures; a carried binding or revision that differs.
pub(crate) fn mirror_record(vault: &Vault, doc: &LoroDoc, id: &EntityId) -> Result<bool> {
    let published = published_of(vault, &BTreeSet::from([*id]))?;
    if published.is_empty() {
        return Ok(false);
    }
    write_published(&doc.get_map(SOURCE_AUDIENCES_MAP), &published)
}

/// The policies `map`'s bindings still reach, each thread's source
/// included, and the keys of every revision of any other policy.
fn unreferenced_policies(map: &LoroMap) -> Vec<String> {
    let carried = carriers(map);
    let bound: BTreeSet<EntityId> = carried
        .iter()
        .filter_map(|(_, carried)| match carried {
            Carrier::Record { policy, .. } => Some(*policy),
            Carrier::Policy { .. } => None,
        })
        .collect();
    let mut reached = bound.clone();
    for (_, carried) in &carried {
        if let Carrier::Policy {
            id,
            policy:
                SourceAudiencePolicy {
                    kind: SourceAudienceKind::Thread { source, .. },
                    ..
                },
        } = carried
            && bound.contains(id)
        {
            reached.insert(*source);
        }
    }
    let mut keys: Vec<String> = carried
        .into_iter()
        .filter_map(|(map_key, carried)| match carried {
            Carrier::Policy { id, .. } if !reached.contains(&id) => Some(map_key),
            _ => None,
        })
        .collect();
    // A key that spells nothing this map carries goes too.
    keys.extend(
        entries(map)
            .into_iter()
            .filter(|(map_key, bytes)| {
                bytes
                    .as_deref()
                    .is_none_or(|bytes| carrier(map_key, bytes).is_err())
            })
            .map(|(map_key, _)| map_key),
    );
    keys
}

/// Removes the binding of the row `id` from `doc`, and every policy no
/// binding left reaches; the canonical binding stands. Whether the map
/// changed. The caller pins history and commits.
///
/// # Errors
///
/// Map write failures.
pub(crate) fn remove_record(doc: &LoroDoc, id: &EntityId) -> Result<bool> {
    let map = doc.get_map(SOURCE_AUDIENCES_MAP);
    let key = record_key(id);
    if map_get_bytes(&map, &key).is_none() {
        return Ok(false);
    }
    map_delete(&map, &key)?;
    for map_key in unreferenced_policies(&map) {
        map_delete(&map, &map_key)?;
    }
    Ok(true)
}

/// The rows `doc`'s entity map carries, by their canonical keys.
fn carried_rows(doc: &LoroDoc) -> BTreeSet<EntityId> {
    let mut rows = BTreeSet::new();
    doc.get_map("entities").for_each(|map_key, _| {
        if let Some(id) = named(map_key) {
            rows.insert(id);
        }
    });
    rows
}

/// Brings `doc`'s map to this vault's current word before it is exported or
/// persisted, after every other removal scrub (L03 COORD 06:11): each bound
/// row it carries rides with its current binding and published closure; a
/// binding whose row it no longer carries goes, and with it each policy no
/// binding reaches; every policy revision naming an actor this vault erased
/// goes (its redacted successor rides under a revision of its own). A
/// carried higher revision this vault has not merged yet stays. `pin` names
/// the window pinned history-free before anything goes; the sweep, whose
/// shallow cut drops that history, passes `None`. Whether the map changed,
/// committed.
///
/// # Errors
///
/// Storage and codec failures; a carried binding or revision that differs.
pub(crate) fn refresh_and_scrub(
    vault: &Vault,
    doc: &LoroDoc,
    pin: Option<&WindowKey>,
) -> Result<bool> {
    let rows = carried_rows(doc);
    let published = published_of(vault, &rows)?;
    if published.is_empty() && !holds_map(doc) {
        return Ok(false);
    }
    let map = doc.get_map(SOURCE_AUDIENCES_MAP);
    let mut gone = Vec::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        for (map_key, carried) in carriers(&map) {
            match carried {
                Carrier::Record { row, .. } if !rows.contains(&row) => gone.push(map_key),
                Carrier::Policy { policy, .. }
                    if source_audience::names_erased_actor_in(vault, &rtxn, &policy)? =>
                {
                    gone.push(map_key);
                }
                Carrier::Record { .. } | Carrier::Policy { .. } => {}
            }
        }
    }
    let mut changed = write_published(&map, &published)?;
    if !gone.is_empty() {
        pin_history_free(vault, pin)?;
        for map_key in &gone {
            map_delete(&map, map_key)?;
        }
        changed = true;
    }
    let unreferenced = unreferenced_policies(&map);
    if !unreferenced.is_empty() {
        if gone.is_empty() {
            pin_history_free(vault, pin)?;
        }
        for map_key in &unreferenced {
            map_delete(&map, map_key)?;
        }
        changed = true;
    }
    if changed {
        doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    }
    Ok(changed)
}

/// Pins the window `pin` names history-free, before a carrier goes.
fn pin_history_free(vault: &Vault, pin: Option<&WindowKey>) -> Result<()> {
    if let Some(key) = pin {
        super::window::require_history_free_window(vault, key)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Ingest: the highest policy revision, an immutable binding, one savepoint.
// ---------------------------------------------------------------------------

/// Merges the highest revision of `policy` `map` carries, in `txn`.
fn merge_carried_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    map: &LoroMap,
    policy: &EntityId,
) -> Result<ReplicaMerge> {
    match carried_head(map, policy) {
        Ok(Some(head)) => source_audience::merge_policy_in_txn(vault, txn, policy, &head),
        Ok(None) => Ok(ReplicaMerge::Held),
        Err(_) => Ok(ReplicaMerge::Conflict),
    }
}

/// Lands the carried binding of the row `id` and its policy closure from
/// `doc`, in `txn`, the savepoint that admitted the row: the bound policy's
/// highest carried revision and, for a thread policy, its source's, merged;
/// then the binding, once the closure resolves. A closure that has not
/// arrived leaves the binding carried and the row unbound (its read
/// conjunct refuses it meanwhile). `Conflict` refuses the row with every
/// write the savepoint staged.
///
/// # Errors
///
/// Storage and codec failures.
pub(crate) fn apply_record_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    doc: &LoroDoc,
    id: &EntityId,
) -> Result<ReplicaMerge> {
    let map = doc.get_map(SOURCE_AUDIENCES_MAP);
    let Some(bytes) = map_get_bytes(&map, &record_key(id)) else {
        return Ok(ReplicaMerge::Held);
    };
    let Ok(Carrier::Record { policy, .. }) = carrier(&record_key(id), &bytes) else {
        return Ok(ReplicaMerge::Conflict);
    };
    if merge_carried_in_txn(vault, txn, &map, &policy)? == ReplicaMerge::Conflict {
        return Ok(ReplicaMerge::Conflict);
    }
    if let Some(source) = source_audience::thread_source_in(vault, txn, &policy)?
        && merge_carried_in_txn(vault, txn, &map, &source)? == ReplicaMerge::Conflict
    {
        return Ok(ReplicaMerge::Conflict);
    }
    source_audience::bind_replicated_in_txn(vault, txn, id, &policy)
}

/// The refusal a row takes whose carried binding or policy contradicts
/// what this vault holds.
pub(crate) fn conflict_error() -> Error {
    refused("the row's binding or policy contradicts the one held")
}

/// Merges every policy revision `doc`'s map carries into this vault's, the
/// highest of each policy, and lands each carried binding of a row already
/// admitted here, in one writer: a policy-only change, a source policy that
/// came after its thread's, and a binding that came after its row. A row not
/// admitted here keeps its binding carried for its own savepoint; a carrier
/// that went unbinds nothing. A conflict is logged and left: the held word
/// stands. The rows newly bound.
///
/// # Errors
///
/// Storage and codec failures.
pub(crate) fn apply_map(vault: &Vault, doc: &LoroDoc) -> Result<Vec<EntityId>> {
    if !holds_map(doc) {
        return Ok(Vec::new());
    }
    let mut heads: BTreeMap<EntityId, SourceAudiencePolicy> = BTreeMap::new();
    let mut records = Vec::new();
    for (_, carried) in carriers(&doc.get_map(SOURCE_AUDIENCES_MAP)) {
        match carried {
            Carrier::Record { row, policy } => records.push((row, policy)),
            Carrier::Policy { id, policy } => {
                if heads
                    .get(&id)
                    .is_none_or(|held| policy.revision > held.revision)
                {
                    heads.insert(id, policy);
                }
            }
        }
    }
    if heads.is_empty() && records.is_empty() {
        return Ok(Vec::new());
    }
    vault.with_write_txn_grouped(|txn| {
        for (id, head) in &heads {
            if source_audience::merge_policy_in_txn(vault, txn, id, head)? == ReplicaMerge::Conflict
            {
                tracing::warn!(
                    reason = "source_audience_policy_conflict",
                    policy = %id.to_hex(),
                    revision = head.revision,
                    "a carried source audience policy contradicts the one held; the held one stands"
                );
            }
        }
        let mut bound = Vec::new();
        for (row, policy) in &records {
            if !crate::vault::live_entity_row_in_txn(&vault.store, txn, row)?.is_live() {
                continue;
            }
            match source_audience::bind_replicated_in_txn(vault, txn, row, policy)? {
                ReplicaMerge::Written => bound.push(*row),
                ReplicaMerge::Conflict => tracing::warn!(
                    reason = "source_audience_binding_conflict",
                    row = %row.to_hex(),
                    "a carried binding contradicts the one held; the held one stands"
                ),
                ReplicaMerge::Held | ReplicaMerge::Pending => {}
            }
        }
        Ok(bound)
    })
}

/// Observer B for the map: what an import brought is merged from the whole
/// map, so a policy, its source or a late binding lands whatever arrived
/// first. On a local failure, each bound row the map carries keeps a replay
/// marker, and the next forward pass lands it.
pub(crate) fn materialize_from_delta(
    doc: &LoroDoc,
    _delta: &loro::event::MapDelta<'_>,
    vault: &Vault,
    window_key: &str,
    _lease_vault_id: u64,
) -> Option<Vec<EntityId>> {
    match apply_map(vault, doc) {
        Ok(bound) => Some(bound),
        Err(error) => {
            tracing::warn!(
                reason = "source_audience_materialize_failed",
                %error,
                window = window_key,
                "a carried source audience did not land; its rows replay on the next forward pass"
            );
            let rows: Vec<EntityId> = carriers(&doc.get_map(SOURCE_AUDIENCES_MAP))
                .into_iter()
                .filter_map(|(_, carried)| match carried {
                    Carrier::Record { row, .. } => Some(row),
                    Carrier::Policy { .. } => None,
                })
                .collect();
            let marked = vault.with_write_txn_grouped(|txn| {
                for row in &rows {
                    crate::sync::quarantine::set_replay_remat_marker_in_txn(
                        vault, txn, window_key, row,
                    )?;
                }
                Ok(())
            });
            if let Err(error) = marked {
                tracing::error!(
                    reason = "source_audience_replay_marker_failed",
                    %error,
                    window = window_key,
                    "a carried source audience did not land and its replay markers did not persist"
                );
            }
            None
        }
    }
}
