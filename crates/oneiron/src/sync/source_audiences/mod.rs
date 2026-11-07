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
//!   spelled in sixteen hex digits and equal to the policy's own;
//! - `withheld/<row>`: the row left the window after it travelled (its
//!   words joined a row bound otherwise), and the machine that withheld it.
//!   Every other holder of the row reads it to no one until its carrier
//!   comes back with no marker ([`source_audience::HeldBack::Withheld`]); a
//!   row whose carried binding waits for its policy is held the same way
//!   meanwhile ([`source_audience::HeldBack::Pending`]);
//! - `event/<policy>/<revision>`: the receipt of the change that made that
//!   revision of a carried policy (fix list row 17205), so a replica knows
//!   who shared a thread and lets its sharer withdraw the share there too. A
//!   receipt changes only by losing an actor to an erase; two copies that
//!   tell different changes are refused
//!   ([`crate::source_audience::merge_event_in_txn`]).
//!
//! Each revision a window holds stays beside the others, so the highest
//! wins however Loro orders them, and two unequal copies of one revision
//! are refused ([`crate::source_audience::merge_policy_in_txn`]). A binding
//! never moves. The lane is the authority: no signature is asked for. A
//! selector, a federation and every restricted lane carry none of this map,
//! and a foreign copy of it is refused at their input.

pub(in crate::sync) mod checkpoint;
mod erased;
mod wake;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use loro::{CommitOptions, LoroDoc, LoroMap, LoroValue, ValueOrContainer, VersionVector};

use super::bridge::BRIDGE_ORIGIN;
use super::loro_support::{map_delete, map_get_bytes, map_insert_bytes};
use super::types::WindowKey;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::source_audience::carried::{
    Carrier, CarrierKey, carrier, encode_binding, encode_event, encode_policy, encode_withheld,
    event_key, named, parse_key, policy_key, record_key, withheld_key,
};
use crate::source_audience::{
    self, HeldBack, ReplicaMerge, SourceAudienceKind, SourceAudiencePolicy,
};

pub(crate) use erased::{erase_carriers_in_txn, history_names_erased_actor_in};

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

/// The highest carried revision of each policy a map holds; `None` for a
/// policy one of whose copies does not decode.
type Heads = BTreeMap<EntityId, Option<SourceAudiencePolicy>>;

/// [`Heads`] of `map`, folded in one scan.
fn carried_heads(map: &LoroMap) -> Heads {
    let mut heads = Heads::new();
    for (map_key, bytes) in entries(map) {
        let Some(CarrierKey::Policy(id, _)) = parse_key(&map_key) else {
            continue;
        };
        let decoded = bytes.and_then(|bytes| match carrier(&map_key, &bytes) {
            Ok(Carrier::Policy { policy, .. }) => Some(policy),
            _ => None,
        });
        match (heads.get(&id), decoded) {
            (Some(None), _) => {}
            (_, None) => {
                heads.insert(id, None);
            }
            (Some(Some(held)), Some(policy)) if held.revision >= policy.revision => {}
            (_, Some(policy)) => {
                heads.insert(id, Some(policy));
            }
        }
    }
    heads
}

thread_local! {
    /// The heads of the window the row savepoints of one pass read, by
    /// window and version: the map is folded once a pass, not once a row.
    static PASS_HEADS: RefCell<Option<(String, VersionVector, Rc<Heads>)>> =
        const { RefCell::new(None) };
}

/// [`carried_heads`] of `doc`'s map, the window `window`, folded once for
/// each version of it a pass reads.
fn pass_heads(doc: &LoroDoc, window: &str) -> Rc<Heads> {
    let version = doc.oplog_vv();
    PASS_HEADS.with(|cell| {
        let mut cell = cell.borrow_mut();
        if let Some((held_window, held_version, heads)) = cell.as_ref()
            && held_window == window
            && *held_version == version
        {
            return Rc::clone(heads);
        }
        let heads = Rc::new(carried_heads(&doc.get_map(SOURCE_AUDIENCES_MAP)));
        *cell = Some((window.to_owned(), version, Rc::clone(&heads)));
        heads
    })
}

// ---------------------------------------------------------------------------
// Admission: the full-window door validates every value an update can leave.
// ---------------------------------------------------------------------------

/// The bindings, policy revisions and change receipts met across one
/// admitted range: the window's held map, a snapshot's latest map and
/// shallow root, and every retained insert. Two bindings of one row, two
/// unequal copies of one policy revision, or two receipts of one change that
/// tell different changes, refuse the range, whichever Loro would keep.
#[derive(Debug, Default)]
pub(crate) struct AdmissionRows {
    bindings: BTreeMap<EntityId, EntityId>,
    versions: BTreeMap<(EntityId, u64), Vec<u8>>,
    /// The join of the receipts met for each change: every actor any copy
    /// names, so a later copy naming another is refused.
    events: BTreeMap<(EntityId, u64), crate::source_audience::SourceAudienceEvent>,
    /// A policy revision or a change receipt the range carries names an
    /// actor this vault erased (fix list row 17238).
    names_erased: bool,
}

impl AdmissionRows {
    /// Whether a policy revision or a change receipt the admitted range
    /// carries, in any part of it, names an actor this vault erased: the
    /// window it lands in is pinned history-free, so no export ships that
    /// copy again (fix list row 17238).
    pub(crate) const fn names_erased(&self) -> bool {
        self.names_erased
    }

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
                Ok(Carrier::Event {
                    policy,
                    revision,
                    event,
                }) => {
                    let joined = match self.events.get(&(policy, revision)) {
                        Some(held) => source_audience::event_join(held, &event),
                        None => Some(event),
                    };
                    // A held map that contradicts itself keeps the first; the
                    // range's own copies are tested against it.
                    if let Some(joined) = joined {
                        self.events.insert((policy, revision), joined);
                    }
                }
                Ok(Carrier::Withheld { .. }) | Err(_) => {}
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
                seen.names_erased |= source_audience::names_erased_actor_in(vault, &rtxn, &policy)?;
            }
        }
        Carrier::Event {
            policy,
            revision,
            event,
        } => {
            let joined = match seen.events.get(&(policy, revision)) {
                Some(held) => source_audience::event_join(held, &event)
                    .ok_or_else(|| refused("two receipts of one change tell two changes"))?,
                None => event.clone(),
            };
            seen.events.insert((policy, revision), joined);
            if let Some(vault) = vault {
                let rtxn = vault.store.env.read_txn()?;
                if source_audience::event_conflicts_in(vault, &rtxn, &policy, revision, &event)? {
                    return Err(refused("a change receipt contradicts the one held"));
                }
                seen.names_erased |=
                    source_audience::event_names_erased_actor_in(vault, &rtxn, &event)?;
            }
        }
        // A marker asserts only that a row left: its holders read it to no
        // one, which no held word contradicts.
        Carrier::Withheld { .. } => {}
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

/// The row a carried key names: `record/<row>`'s and `withheld/<row>`'s
/// row; a policy key and a receipt key name no row.
pub(crate) fn record_owner(map_key: &str) -> Option<EntityId> {
    match parse_key(map_key)? {
        CarrierKey::Record(row) | CarrierKey::Withheld(row) => Some(row),
        CarrierKey::Policy(..) | CarrierKey::Event(..) => None,
    }
}

/// Files a withholding marker for each of `rows` in `doc`'s map, naming
/// `by`, the machine whose walk withheld them, so every other holder of a
/// row that already travelled reads it to no one (REVIEW-5911). The caller
/// removed the rows' carriers and commits.
///
/// # Errors
///
/// Codec and map write failures.
pub(crate) fn mark_withheld(doc: &LoroDoc, rows: &[EntityId], by: Option<&EntityId>) -> Result<()> {
    let map = doc.get_map(SOURCE_AUDIENCES_MAP);
    let value = encode_withheld(by)?;
    for row in rows {
        let map_key = withheld_key(row);
        if map_get_bytes(&map, &map_key).as_deref() != Some(value.as_slice()) {
            map_insert_bytes(&map, &map_key, &value)?;
        }
    }
    Ok(())
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

/// Writes this vault's current revision of each policy `map` carries a
/// revision of, unless it names an erased actor or its key already holds
/// other bytes (a contradiction admission refused stays as it is).
fn write_current_heads(vault: &Vault, map: &LoroMap) -> Result<bool> {
    let families: Vec<EntityId> = carried_heads(map).into_keys().collect();
    if families.is_empty() {
        return Ok(false);
    }
    let heads = {
        let rtxn = vault.store.env.read_txn()?;
        let mut heads = Vec::new();
        for id in families {
            if let Some(head) = source_audience::policy_in(vault, &rtxn, &id)?
                && !source_audience::names_erased_actor_in(vault, &rtxn, &head)?
            {
                heads.push((id, head));
            }
        }
        heads
    };
    let mut wrote = false;
    for (id, head) in heads {
        let map_key = policy_key(&id, head.revision);
        if map_get_bytes(map, &map_key).is_none() {
            map_insert_bytes(map, &map_key, &encode_policy(&head)?)?;
            wrote = true;
        }
    }
    Ok(wrote)
}

/// The binding and the published closure of each bound row of `rows`,
/// read in one snapshot. A bound row whose closure does not publish refuses:
/// the caller fails rather than ship the row without it.
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
        // The packing door releases a bound row only when its closure
        // publishes: one carried that does not is never exported bare.
        let closure = match source_audience::policy_closure_in(vault, &rtxn, &policy)? {
            Some(closure) if source_audience::publishable_in(vault, &rtxn, &policy)? => closure,
            _ => {
                return Err(refused(
                    "a carried bound row whose policy closure does not publish",
                ));
            }
        };
        published.push((*row, policy, closure));
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
    let map = doc.get_map(SOURCE_AUDIENCES_MAP);
    let mut wrote = write_published(&map, &published)?;
    let policies: BTreeSet<EntityId> = published
        .iter()
        .flat_map(|(_, _, closure)| closure.iter().map(|(policy, _)| *policy))
        .collect();
    wrote |= write_events(vault, &map, &policies)?;
    Ok(wrote)
}

/// Writes this vault's receipt of each change to each of `policies` that
/// `map` does not carry yet (fix list row 17205), none naming an actor this
/// vault erased. A key that holds other bytes stays as it is here: an
/// unredacted copy goes in the scrub ([`refresh_and_scrub`]) before this
/// writes, and the export or persist then puts this vault's narrower meet
/// in its place ([`reconcile_events`]). Whether the map changed.
fn write_events(vault: &Vault, map: &LoroMap, policies: &BTreeSet<EntityId>) -> Result<bool> {
    let mut wrote = false;
    for (map_key, event) in held_receipts(vault, policies)? {
        if map_get_bytes(map, &map_key).is_none() {
            map_insert_bytes(map, &map_key, &encode_event(&event)?)?;
            wrote = true;
        }
    }
    Ok(wrote)
}

/// Puts this vault's receipt of each change to each of `policies` in place
/// of a wider one `map` carries (fix list row 17203): the receipt this vault
/// holds is the meet of every copy it merged, an actor another replica erased
/// taken out. A carried copy that contradicts it stands, as admission left
/// it. The carried bytes stay in the window's history, so the window `pin`
/// names goes history-free first. Whether the map changed.
fn reconcile_events(
    vault: &Vault,
    map: &LoroMap,
    policies: &BTreeSet<EntityId>,
    pin: Option<&WindowKey>,
) -> Result<bool> {
    let mut wrote = false;
    for (map_key, event) in held_receipts(vault, policies)? {
        let Some(bytes) = map_get_bytes(map, &map_key) else {
            continue;
        };
        let narrower = match carrier(&map_key, &bytes) {
            Ok(Carrier::Event { event: carried, .. }) => {
                carried != event && narrows(&event, &carried)
            }
            _ => false,
        };
        if narrower {
            pin_history_free(vault, pin)?;
            map_insert_bytes(map, &map_key, &encode_event(&event)?)?;
            wrote = true;
        }
    }
    Ok(wrote)
}

/// Whether `held` is `carried` with some of its actors taken out, and
/// nothing else changed.
fn narrows(
    held: &source_audience::SourceAudienceEvent,
    carried: &source_audience::SourceAudienceEvent,
) -> bool {
    held.op == carried.op
        && held.at == carried.at
        && (held.person.is_none() || held.person == carried.person)
        && (held.by.is_none() || held.by == carried.by)
}

/// This vault's receipt of each change to each of `policies`, by its map
/// key, but for one naming an actor this vault erased.
fn held_receipts(
    vault: &Vault,
    policies: &BTreeSet<EntityId>,
) -> Result<Vec<(String, source_audience::SourceAudienceEvent)>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut receipts = Vec::new();
    for policy in policies {
        for (revision, event) in source_audience::events_of_in(vault, &rtxn, policy)? {
            if !source_audience::event_names_erased_actor_in(vault, &rtxn, &event)? {
                receipts.push((event_key(policy, revision), event));
            }
        }
    }
    Ok(receipts)
}

/// The policies `map`'s bindings still reach, each thread's source
/// included, and the keys of every revision and receipt of any other policy.
fn unreferenced_policies(map: &LoroMap) -> Vec<String> {
    let carried = carriers(map);
    let bound: BTreeSet<EntityId> = carried
        .iter()
        .filter_map(|(_, carried)| match carried {
            Carrier::Record { policy, .. } => Some(*policy),
            Carrier::Policy { .. } | Carrier::Withheld { .. } | Carrier::Event { .. } => None,
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
            Carrier::Policy { id, .. } | Carrier::Event { policy: id, .. }
                if !reached.contains(&id) =>
            {
                Some(map_key)
            }
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

/// Removes the binding of the row `id` from `doc`; the canonical binding
/// stands. Each policy no binding reaches any longer goes at the window's
/// next export or persist ([`refresh_and_scrub`]), once for a whole batch.
/// Whether the map changed. The caller pins history and commits.
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
    // The carried higher revisions settle first, in a writer of their own,
    // so the head published is never below one the window carries and a
    // redaction rides before the revision it replaces goes.
    apply_map(vault, doc)?;
    // A carried row the full window would not pack now leaves it first: a
    // DerivedFrom edge can join a row to one bound otherwise after its birth.
    super::window::withhold_audience_carriers(vault, doc, pin)?;
    let rows = carried_rows(doc);
    let published = published_of(vault, &rows)?;
    if published.is_empty() && !holds_map(doc) {
        return Ok(false);
    }
    let map = doc.get_map(SOURCE_AUDIENCES_MAP);
    let mut gone = Vec::new();
    let mut lifted = Vec::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        let me = crate::identity::read_machine_id_in_txn(vault, &rtxn)?;
        for (map_key, carried) in carriers(&map) {
            match carried {
                Carrier::Record { row, .. } if !rows.contains(&row) => gone.push(map_key),
                Carrier::Policy { policy, .. }
                    if source_audience::names_erased_actor_in(vault, &rtxn, &policy)? =>
                {
                    gone.push(map_key);
                }
                // Its redaction rides under the same key once it went.
                Carrier::Event { event, .. }
                    if source_audience::event_names_erased_actor_in(vault, &rtxn, &event)? =>
                {
                    gone.push(map_key);
                }
                // This machine's own marker lifts once the row rides again
                // (its holders lift their hold as its carrier lands), or once
                // the row is gone here. It names no actor: no pin.
                Carrier::Withheld { row, by }
                    if by == me
                        && (rows.contains(&row)
                            || !crate::vault::live_entity_row_in_txn(
                                &vault.store,
                                &rtxn,
                                &row,
                            )?
                            .is_live()) =>
                {
                    lifted.push(map_key);
                }
                Carrier::Record { .. }
                | Carrier::Policy { .. }
                | Carrier::Withheld { .. }
                | Carrier::Event { .. } => {}
            }
        }
    }
    let mut changed = write_published(&map, &published)?;
    changed |= write_current_heads(vault, &map)?;
    for map_key in &lifted {
        map_delete(&map, map_key)?;
        changed = true;
    }
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
    // Last: the receipts of the policies the map still carries, so a
    // redaction rides where its unredacted copy went.
    let carried: BTreeSet<EntityId> = carried_heads(&map).into_keys().collect();
    changed |= write_events(vault, &map, &carried)?;
    changed |= reconcile_events(vault, &map, &carried, pin)?;
    if changed {
        doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    }
    // The window is filed under each policy it rides, so a change of one
    // wakes it (fix list row 17203).
    if let Some(key) = pin {
        let revisions = carried_heads(&map)
            .into_iter()
            .map(|(policy, head)| (policy, head.map(|head| head.revision)))
            .collect();
        source_audience::note_policy_windows(vault, key.as_str(), &revisions)?;
    }
    Ok(changed)
}

/// Whether `doc`'s map carries a revision of `policy`: what the policy wake
/// reads of a window it persisted again (fix list row 17203).
fn carries_policy(doc: &LoroDoc, policy: &EntityId) -> bool {
    carried_revision(doc, policy).is_some()
}

/// The revision of `policy` `doc`'s map carries as its head (`Some(None)`
/// for a head that conflicts), or `None` when it carries none.
fn carried_revision(doc: &LoroDoc, policy: &EntityId) -> Option<Option<u64>> {
    if !holds_map(doc) {
        return None;
    }
    carried_heads(&doc.get_map(SOURCE_AUDIENCES_MAP))
        .remove(policy)
        .map(|head| head.map(|head| head.revision))
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

/// Merges the highest revision of `policy` `heads` holds, in `txn`.
fn merge_head_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    heads: &Heads,
    policy: &EntityId,
) -> Result<ReplicaMerge> {
    match heads.get(policy) {
        Some(Some(head)) => source_audience::merge_policy_in_txn(vault, txn, policy, head),
        Some(None) => Ok(ReplicaMerge::Conflict),
        None => Ok(ReplicaMerge::Held),
    }
}

/// Lands the carried binding of the row `id` and its policy closure from
/// `doc`, the window `window`, in `txn`, the savepoint that admitted the
/// row: the bound policy's highest carried revision and, for a thread
/// policy, its source's, merged; then the binding, once the closure
/// resolves. A closure that has not arrived leaves the binding carried and
/// the row unbound (its read conjunct refuses it meanwhile). `Conflict`
/// refuses the row with every write the savepoint staged. The map is folded
/// once a pass ([`pass_heads`]).
///
/// # Errors
///
/// Storage and codec failures.
pub(crate) fn apply_record_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    doc: &LoroDoc,
    window: &str,
    id: &EntityId,
) -> Result<ReplicaMerge> {
    let map = doc.get_map(SOURCE_AUDIENCES_MAP);
    settle_withheld_in_txn(vault, txn, &map, id)?;
    let key = record_key(id);
    let Some(bytes) = map_get_bytes(&map, &key) else {
        return Ok(ReplicaMerge::Held);
    };
    let Ok(Carrier::Record { policy, .. }) = carrier(&key, &bytes) else {
        return Ok(ReplicaMerge::Conflict);
    };
    let heads = pass_heads(doc, window);
    if merge_head_in_txn(vault, txn, &heads, &policy)? == ReplicaMerge::Conflict {
        return Ok(ReplicaMerge::Conflict);
    }
    if let Some(source) = source_audience::thread_source_in(vault, txn, &policy)?
        && merge_head_in_txn(vault, txn, &heads, &source)? == ReplicaMerge::Conflict
    {
        return Ok(ReplicaMerge::Conflict);
    }
    let merge = source_audience::bind_replicated_in_txn(vault, txn, id, &policy)?;
    if matches!(merge, ReplicaMerge::Written | ReplicaMerge::Held) {
        source_audience::lift_hold_in_txn(vault, txn, id, HeldBack::Pending)?;
    }
    Ok(merge)
}

/// Holds the row `id`, whose carrier `map`'s window carries, back while
/// another machine's marker says that machine withheld it; lifts that hold
/// once the carrier rides with no such marker. Whether the hold changed.
fn settle_withheld_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    map: &LoroMap,
    id: &EntityId,
) -> Result<bool> {
    let map_key = withheld_key(id);
    let marked = match map_get_bytes(map, &map_key) {
        Some(bytes) => match carrier(&map_key, &bytes) {
            Ok(Carrier::Withheld { by, .. }) => Some(by),
            // A marker that does not decode holds the row: it never reads
            // wider for a malformed word.
            _ => Some(None),
        },
        None => None,
    };
    let me = crate::identity::read_machine_id_in_txn(vault, txn)?;
    match marked {
        Some(by) if by != me => {
            source_audience::hold_back_in_txn(vault, txn, id, HeldBack::Withheld)
        }
        _ => source_audience::lift_hold_in_txn(vault, txn, id, HeldBack::Withheld),
    }
}

/// The refusal a row takes whose carried binding names a policy closure
/// that has not arrived: it waits for it, pending, never landing unbound.
pub(crate) fn pending_error() -> Error {
    refused("the row's source audience policy has not arrived")
}

/// The refusal a row takes whose carried binding or policy contradicts
/// what this vault holds.
pub(crate) fn conflict_error() -> Error {
    refused("the row's binding or policy contradicts the one held")
}

/// Merges every policy revision `doc`'s map carries into this vault's, the
/// highest of each policy, and lands each carried binding of a row the doc
/// carries and this vault already admitted, in one writer: a policy-only
/// change, a source policy that came after its thread's, and a binding that
/// came after its row. A row not admitted here keeps its binding carried for
/// its own savepoint; a carrier that went unbinds nothing. A policy whose
/// carried revision conflicts is logged and left, the held word standing,
/// and no binding lands under it or under a thread of it. The rows bound
/// now, or whose policy or its source changed.
///
/// # Errors
///
/// Storage and codec failures.
pub(crate) fn apply_map(vault: &Vault, doc: &LoroDoc) -> Result<Vec<EntityId>> {
    if !holds_map(doc) {
        return Ok(Vec::new());
    }
    let map = doc.get_map(SOURCE_AUDIENCES_MAP);
    let heads = carried_heads(&map);
    let carried = carriers(&map);
    let records: Vec<(EntityId, EntityId)> = carried
        .iter()
        .filter_map(|(_, carried)| match carried {
            Carrier::Record { row, policy } => Some((*row, *policy)),
            Carrier::Policy { .. } | Carrier::Withheld { .. } | Carrier::Event { .. } => None,
        })
        .collect();
    let mut markers: Vec<(EntityId, Option<EntityId>)> = Vec::new();
    let mut receipts = Vec::new();
    for (_, carried) in carried {
        match carried {
            Carrier::Withheld { row, by } => markers.push((row, by)),
            Carrier::Event {
                policy,
                revision,
                event,
            } => receipts.push((policy, revision, event)),
            Carrier::Record { .. } | Carrier::Policy { .. } => {}
        }
    }
    if heads.is_empty() && records.is_empty() && markers.is_empty() && receipts.is_empty() {
        return Ok(Vec::new());
    }
    let rows = carried_rows(doc);
    vault.with_write_txn_grouped(|txn| {
        let mut refused_policies = BTreeSet::new();
        let mut changed = BTreeSet::new();
        for (id, head) in &heads {
            let merge = match head {
                Some(head) => source_audience::merge_policy_in_txn(vault, txn, id, head)?,
                None => ReplicaMerge::Conflict,
            };
            match merge {
                ReplicaMerge::Conflict => {
                    tracing::warn!(
                        reason = "source_audience_policy_conflict",
                        policy = %id.to_hex(),
                        "a carried source audience policy contradicts the one held; the held one stands"
                    );
                    refused_policies.insert(*id);
                }
                ReplicaMerge::Written => {
                    changed.insert(*id);
                }
                ReplicaMerge::Held | ReplicaMerge::Pending => {}
            }
        }
        merge_receipts_in_txn(vault, txn, &receipts, &refused_policies)?;
        let mut affected = Vec::new();
        // A row another machine withheld after it travelled reads to no one
        // here (REVIEW-5911): its holders are told, not left reading it
        // under the binding it travelled with.
        let me = crate::identity::read_machine_id_in_txn(vault, txn)?;
        for (row, by) in &markers {
            if *by != me
                && crate::vault::live_entity_row_in_txn(&vault.store, txn, row)?.is_live()
                && source_audience::hold_back_in_txn(vault, txn, row, HeldBack::Withheld)?
            {
                affected.push(*row);
            }
        }
        // A withheld row whose carrier rides here again with no other
        // machine's marker lifts, as its own savepoint would lift it.
        for (row, why) in source_audience::held_rows_in(vault, txn)? {
            if why == HeldBack::Withheld
                && rows.contains(&row)
                && !markers.iter().any(|(marked, by)| *marked == row && *by != me)
                && source_audience::lift_hold_in_txn(vault, txn, &row, HeldBack::Withheld)?
            {
                affected.push(row);
            }
        }
        for (row, policy) in &records {
            if !rows.contains(row) {
                continue;
            }
            let source = source_audience::thread_source_in(vault, txn, policy)?;
            let reaches = |set: &BTreeSet<EntityId>| {
                set.contains(policy) || source.is_some_and(|source| set.contains(&source))
            };
            if reaches(&refused_policies) {
                continue;
            }
            // Only a row this doc's own carrier stands for: the admitted
            // bytes are the bytes carried. Any other lands with its row's
            // savepoint at the next forward pass.
            if !crate::vault::live_entity_row_in_txn(&vault.store, txn, row)?.is_live()
                || stored_bytes_in(vault, txn, row)?.as_deref() != carried_bytes(doc, row).as_deref()
            {
                continue;
            }
            match source_audience::bind_replicated_in_txn(vault, txn, row, policy)? {
                ReplicaMerge::Written => {
                    source_audience::lift_hold_in_txn(vault, txn, row, HeldBack::Pending)?;
                    affected.push(*row);
                }
                ReplicaMerge::Held => {
                    if source_audience::lift_hold_in_txn(vault, txn, row, HeldBack::Pending)?
                        || reaches(&changed)
                    {
                        affected.push(*row);
                    }
                }
                ReplicaMerge::Conflict => tracing::warn!(
                    reason = "source_audience_binding_conflict",
                    row = %row.to_hex(),
                    "a carried binding contradicts the one held; the held one stands"
                ),
                // An admitted row whose carried binding waits for its policy
                // reads to no one until the binding lands (REVIEW-5918),
                // never as the unbound row it is meanwhile.
                ReplicaMerge::Pending => {
                    if source_audience::hold_back_in_txn(vault, txn, row, HeldBack::Pending)? {
                        affected.push(*row);
                    }
                }
            }
        }
        Ok(affected)
    })
}

/// Merges each carried change receipt of a policy this vault holds whose
/// carried revision did not conflict, in `txn` (fix list row 17205): a
/// receipt waits beside the window for its policy, never filed without it.
/// A receipt that tells another change than the one held is logged and
/// left, the held one standing.
fn merge_receipts_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    receipts: &[(EntityId, u64, source_audience::SourceAudienceEvent)],
    refused_policies: &BTreeSet<EntityId>,
) -> Result<()> {
    for (policy, revision, event) in receipts {
        if refused_policies.contains(policy)
            || source_audience::policy_in(vault, txn, policy)?
                .is_none_or(|held| held.revision < *revision)
        {
            continue;
        }
        if source_audience::merge_event_in_txn(vault, txn, policy, *revision, event)?
            == ReplicaMerge::Conflict
        {
            tracing::warn!(
                reason = "source_audience_receipt_conflict",
                policy = %policy.to_hex(),
                revision,
                "a carried change receipt contradicts the one held; the held one stands"
            );
        }
    }
    Ok(())
}

/// The bytes this vault stores for `row`, in `txn`.
fn stored_bytes_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &EntityId,
) -> Result<Option<Vec<u8>>> {
    crate::ports::EntityStoreRead::port_entity_raw(&vault.store.read(), txn, row)
}

/// The bytes `doc` carries for `row`.
fn carried_bytes(doc: &LoroDoc, row: &EntityId) -> Option<Vec<u8>> {
    map_get_bytes(&doc.get_map("entities"), &row.to_hex())
}

/// Observer B for the map: what an import brought is merged from the whole
/// map, so a policy, its source or a late binding lands whatever arrived
/// first. A local failure is logged: the window's next export or persist
/// ([`refresh_and_scrub`]) and its next forward pass merge the whole map
/// again, so no replay marker is left that no write would discharge.
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
                "a carried source audience did not land; the next export or forward pass merges it again"
            );
            None
        }
    }
}
