//! FIX 12470: a typed body's rows on the window plane.
//!
//! A typed body's operations ride its entity's document frame to the owner's
//! other machines (FIX 2458), but each commit's receipt row stayed on the
//! machine that wrote it, so every carried commit read as unreceipted there
//! and a fold of the body's provenance failed; and each fork stayed on the
//! machine that opened it, so a proposal carried there named a fork it could
//! not review or settle. Those rows now ride the base window's
//! `typed_body_rows` map beside their body, as an office proposal rides
//! `office_proposals`. Only the owner's machines take the map: a federated
//! or guest window copies none of it. Each family of rows files under a key
//! prefix of its own: a commit receipt's is `r/`, a fork's `f/`, and a part
//! of a fork's snapshot `part/`.
//!
//! - A receipt rides as its exact row under its body and its commit peer,
//!   `r/<body>/<peer as 16 lowercase hex>`, with the birth of the body it was
//!   made on.
//! - Reverse rematerialization mirrors each receipt of a body the window
//!   carries, and the live mirror does once a commit or an actor's erase
//!   queues the body. A copy is written only where the window holds none, or
//!   where this machine's holds all of the window's: no machine's copy
//!   overwrites another's.
//! - Forward rematerialization, Observer B and the live mirror merge each
//!   carried receipt into this vault's
//!   (`typed_body::merge_carried_receipt_in_txn`): a receipt this vault lacks
//!   is written, an erased copy beats a live one made at the same time, and
//!   two copies that differ otherwise are quarantined, one row per divergence
//!   under the receipt's key and a digest of both copies, and both stand. The
//!   merge writes the row only: no peer is bound, no MadeBy is recorded.
//! - A receipt whose body has not landed here waits in the window; the live
//!   mirror merges it as the body lands. One of another body birth stands
//!   apart.
//! - A fork rides as its row, `f/<body>/<fork>`, with the body's birth, the
//!   schema owner's record of the fork (a deck fork's office record) and an
//!   open fork's snapshot. A row that would outgrow a part rides its
//!   snapshot as linked parts (`carrier_parts`), so no size is skipped.
//! - Reverse rematerialization mirrors each fork of a body the window
//!   carries after its pass commits, a row and each part to a commit of its
//!   own, and the live mirror does once a fork's write queues the body. A
//!   copy is written on the receipt's rule: only where the window holds
//!   none, or where this machine's holds all of the window's.
//! - Forward rematerialization, Observer B and the live mirror merge each
//!   carried fork into this vault's (`typed_body::merge_carried_fork_in_txn`)
//!   once its parts have landed: the decision already made is stored, and
//!   nothing lands, settles or is authored. Copies that diverge are
//!   quarantined as receipts are, and the one held here stands.
//! - Admission refuses every insert into the map that is not a whole receipt
//!   or fork filed under its own key, or a part filed under its digest, in
//!   the latest state, at a snapshot's root and in every retained operation.
//! - Every export, and the erase sweep, drop each row of a body this vault
//!   removed or the window does not carry, and each part no fork lists. A
//!   copy naming an actor this vault erased takes its erased form, and an
//!   open fork whose opener this vault erased goes.

pub(super) mod checkpoint;

use std::collections::BTreeSet;

use heed::RoTxn;
use loro::event::MapDelta;
use loro::{CommitOptions, LoroDoc, LoroMap, LoroValue, ValueOrContainer};

use super::bridge::BRIDGE_ORIGIN;
use super::carrier_parts::{
    PART_BYTES, Parts, admit_part, is_part_key, join_parts, split_parts, unreferenced_parts,
    write_parts,
};
use super::loro_support::{map_contains_binary, map_delete, map_get_bytes, map_insert_bytes};
use super::quarantine::{QuarantineContainer, quarantine_once_in_txn};
use super::types::WindowKey;
use super::window_rows::HISTORY_FREE_WINDOW;
use crate::Vault;
use crate::entity_doc::DocumentMerge;
use crate::entity_doc::office::OFFICE_BODY_OWNER;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::typed_body::{
    CarriedFork, CarriedReceipt, ForkSnapshot, carried_forks_in_txn, carried_receipts_in_txn,
    merge_carried_fork_in_txn, merge_carried_receipt_in_txn,
};

/// The base window root map that carries a typed body's rows.
pub(crate) const TYPED_BODY_ROWS_MAP: &str = "typed_body_rows";

/// The key prefix of a commit receipt's row.
const RECEIPT_KEY_PREFIX: &str = "r/";

/// The key prefix of a fork's row.
const FORK_KEY_PREFIX: &str = "f/";

/// The context a divergence's digest is derived in.
const DIVERGENCE_CONTEXT: &str = "oneiron.typed_body_rows.divergence.v1";

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("typed body row refused: {reason}"))
}

fn encode_receipt(record: &CarriedReceipt) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(record).map_err(|_| refused("does not encode"))
}

/// Decodes a carried receipt. A receipt has one spelling.
fn decode_receipt(bytes: &[u8]) -> Result<CarriedReceipt> {
    let record: CarriedReceipt =
        rmp_serde::from_slice(bytes).map_err(|_| refused("not a receipt"))?;
    if encode_receipt(&record)? != bytes {
        return Err(refused("not in its one spelling"));
    }
    Ok(record)
}

/// The key `record` rides under: its body's entity, then its commit peer.
fn receipt_key(record: &CarriedReceipt) -> String {
    format!(
        "{RECEIPT_KEY_PREFIX}{}/{:016x}",
        record.entity.to_hex(),
        record.peer
    )
}

/// The body's entity and the commit peer `map_key` names, when it is a
/// receipt's key with both in their one spelling.
fn receipt_of(map_key: &str) -> Option<(EntityId, u64)> {
    let (entity, peer) = map_key.strip_prefix(RECEIPT_KEY_PREFIX)?.split_once('/')?;
    let entity = EntityId::from_hex(entity)
        .ok()
        .filter(|id| id.to_hex() == entity)?;
    let peer = u64::from_str_radix(peer, 16)
        .ok()
        .filter(|id| format!("{id:016x}") == peer)?;
    Some((entity, peer))
}

fn encode_fork(carried: &CarriedFork) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(carried).map_err(|_| refused("does not encode"))
}

/// Decodes a carried fork: a whole one, in its one spelling.
fn decode_fork(bytes: &[u8]) -> Result<CarriedFork> {
    let carried: CarriedFork = rmp_serde::from_slice(bytes).map_err(|_| refused("not a fork"))?;
    if encode_fork(&carried)? != bytes {
        return Err(refused("not in its one spelling"));
    }
    if !carried.well_formed() {
        return Err(refused("not a whole fork"));
    }
    Ok(carried)
}

/// The key `carried` rides under: its body's entity, then its fork.
fn fork_key(carried: &CarriedFork) -> String {
    format!(
        "{FORK_KEY_PREFIX}{}/{}",
        carried.entity.to_hex(),
        carried.fork.to_hex()
    )
}

/// The body's entity and the fork `map_key` names, when it is a fork's key
/// with both in their one spelling.
fn fork_of(map_key: &str) -> Option<(EntityId, EntityId)> {
    let (entity, fork) = map_key.strip_prefix(FORK_KEY_PREFIX)?.split_once('/')?;
    let named = |hex: &str| EntityId::from_hex(hex).ok().filter(|id| id.to_hex() == hex);
    Some((named(entity)?, named(fork)?))
}

/// The parts a carried fork's snapshot rides in, when it rides in parts.
fn snapshot_parts(carried: &CarriedFork) -> Option<&Parts> {
    match &carried.snapshot {
        Some(ForkSnapshot::Parts(parts)) => Some(parts),
        _ => None,
    }
}

/// One row of the map, by its family.
enum Row {
    Receipt(CarriedReceipt),
    Fork(CarriedFork),
}

impl Row {
    /// The body's entity the row rides beside.
    fn entity(&self) -> EntityId {
        match self {
            Self::Receipt(record) => record.entity,
            Self::Fork(carried) => carried.entity,
        }
    }
}

/// Decodes the row filed under `map_key`, by the family its key names: a
/// whole row in its one spelling, filed under its own key.
fn decode_row(map_key: &str, bytes: &[u8]) -> Result<Row> {
    if map_key.starts_with(RECEIPT_KEY_PREFIX) {
        let record = decode_receipt(bytes)?;
        if receipt_key(&record) != map_key {
            return Err(refused("filed under another key"));
        }
        return Ok(Row::Receipt(record));
    }
    if map_key.starts_with(FORK_KEY_PREFIX) {
        let carried = decode_fork(bytes)?;
        if fork_key(&carried) != map_key {
            return Err(refused("filed under another key"));
        }
        return Ok(Row::Fork(carried));
    }
    Err(refused("filed under no row's key"))
}

/// The body's entity `map_key` names, when it is a row's key in its one
/// spelling.
fn entity_of(map_key: &str) -> Option<EntityId> {
    receipt_of(map_key)
        .map(|(entity, _)| entity)
        .or_else(|| fork_of(map_key).map(|(entity, _)| entity))
}

/// Admits one insert into a window's `typed_body_rows` map: a whole receipt
/// or fork of a base window filed under its own key, or a part filed under
/// its digest.
pub(crate) fn admit_typed_body_row_carrier(
    key: Option<&WindowKey>,
    map_key: &str,
    value: &LoroValue,
) -> Result<()> {
    if key.is_some_and(|key| key.world().is_some()) {
        return Err(refused("in a world window"));
    }
    if is_part_key(map_key) {
        return admit_part(map_key, value);
    }
    let LoroValue::Binary(bytes) = value else {
        return Err(refused("not bytes"));
    };
    decode_row(map_key, bytes).map(|_| ())
}

/// [`admit_typed_body_row_carrier`] over every row `map` holds.
pub(crate) fn admit_typed_body_row_map(key: Option<&WindowKey>, map: &LoroMap) -> Result<()> {
    let mut rows = Vec::new();
    let mut nested = false;
    map.for_each(|map_key, value| match value {
        ValueOrContainer::Value(value) => rows.push((map_key.to_owned(), value)),
        ValueOrContainer::Container(_) => nested = true,
    });
    if nested {
        return Err(refused("nested container"));
    }
    for (map_key, value) in &rows {
        admit_typed_body_row_carrier(key, map_key, value)?;
    }
    Ok(())
}

/// Writes into `doc`, window `window`'s document, each receipt of `entity`'s
/// body this vault holds that adds to the window's copy: one the window
/// lacks, or one that holds all of the window's copy and more. A window copy
/// that holds what this vault's lacks stands, merged here as it lands. The
/// window is pinned history-free before a copy naming an actor this vault
/// erased changes. Returns whether it wrote; the caller commits.
pub(crate) fn mirror_typed_body_rows(
    vault: &Vault,
    doc: &LoroDoc,
    window: &WindowKey,
    entity: &EntityId,
) -> Result<bool> {
    let (writes, pin) = {
        let rtxn = vault.store.env.read_txn()?;
        let held = carried_receipts_in_txn(vault, &rtxn, entity)?;
        if held.is_empty() {
            return Ok(false);
        }
        let map = doc.get_map(TYPED_BODY_ROWS_MAP);
        let mut writes = Vec::new();
        let mut pin = false;
        for record in &held {
            let key = receipt_key(record);
            let bytes = encode_receipt(record)?;
            let carried = map_get_bytes(&map, &key);
            if carried.as_deref() == Some(bytes.as_slice()) {
                continue;
            }
            if let Some(carried) = carried.and_then(|carried| decode_receipt(&carried).ok()) {
                if !record.covers(&carried) {
                    continue;
                }
                pin |= carried.clone().carried_here(vault, &rtxn)? != carried;
            }
            writes.push((key, bytes));
        }
        (writes, pin)
    };
    if writes.is_empty() {
        return Ok(false);
    }
    if pin {
        super::window::require_history_free_window(vault, window)?;
    }
    let map = doc.get_map(TYPED_BODY_ROWS_MAP);
    for (key, bytes) in &writes {
        map_insert_bytes(&map, key, bytes)?;
    }
    Ok(true)
}

/// Writes into `doc`, window `window`'s document, each fork of the typed
/// bodies among `entities` this vault holds that adds to the window's copy:
/// one the window lacks, or one that holds all of the window's copy and more
/// (`CarriedFork::covers`). A window copy that holds what this vault's lacks
/// stands, merged here as it lands. The window is pinned history-free before
/// a copy naming an actor this vault erased changes. Each fork's row commits
/// on its own, after this pass's other writes, and each part of a snapshot
/// too large to ride in its row after it, so no one update holds more than a
/// part. Returns whether it wrote.
pub(crate) fn mirror_typed_body_forks(
    vault: &Vault,
    doc: &LoroDoc,
    window: &WindowKey,
    entities: &[EntityId],
) -> Result<bool> {
    if window.world().is_some() {
        return Ok(false);
    }
    let bodies = {
        let rtxn = vault.store.env.read_txn()?;
        let mut bodies = Vec::new();
        for entity in entities {
            if crate::typed_body::sync_frame::has_typed_body_in_txn(&vault.store, &rtxn, entity)? {
                bodies.push(*entity);
            }
        }
        bodies
    };
    let mut wrote = false;
    for entity in &bodies {
        wrote |= mirror_body_forks(vault, doc, window, entity)?;
    }
    Ok(wrote)
}

/// [`mirror_typed_body_forks`] for the forks of `entity`'s body.
fn mirror_body_forks(
    vault: &Vault,
    doc: &LoroDoc,
    window: &WindowKey,
    entity: &EntityId,
) -> Result<bool> {
    let owner = &OFFICE_BODY_OWNER;
    let (writes, pin) = {
        let rtxn = vault.store.env.read_txn()?;
        let held = carried_forks_in_txn(vault, &rtxn, entity, owner)?;
        if held.is_empty() {
            return Ok(false);
        }
        let map = doc.get_map(TYPED_BODY_ROWS_MAP);
        let mut writes = Vec::new();
        let mut pin = false;
        for carried in held {
            let key = fork_key(&carried);
            let copy = map_get_bytes(&map, &key).and_then(|bytes| decode_fork(&bytes).ok());
            if let Some(copy) = &copy {
                // The same row: its snapshot may ride whole or in parts. A
                // row whose parts have not all landed in the window (a mirror
                // cut off after its manifest committed) is written again,
                // which writes only the parts the window lacks; otherwise no
                // receiver could ever join its snapshot.
                if copy.birth == carried.birth
                    && copy.record == carried.record
                    && copy.companion == carried.companion
                {
                    if snapshot_parts(copy).is_none_or(|parts| {
                        parts.keys().all(|part| map_contains_binary(&map, &part))
                    }) {
                        continue;
                    }
                    writes.push((key, carried, None));
                    continue;
                }
                match copy.clone().carried_here(vault, &rtxn, owner)? {
                    Some(here) => {
                        if !carried.covers(&here, owner)? {
                            continue;
                        }
                        pin |= here != *copy;
                    }
                    None => pin = true,
                }
            }
            writes.push((key, carried, copy));
        }
        (writes, pin)
    };
    if writes.is_empty() {
        return Ok(false);
    }
    if pin {
        super::window::require_history_free_window(vault, window)?;
    }
    let map = doc.get_map(TYPED_BODY_ROWS_MAP);
    for (key, carried, replaced) in &writes {
        write_fork(doc, &map, key, carried, replaced.as_ref())?;
    }
    Ok(true)
}

fn commit(doc: &LoroDoc) {
    doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
}

/// Writes `carried` under `key`: its snapshot in its row while the row fits
/// a part, else in linked parts written after the row, each committing on
/// its own. Each part of `replaced`, the copy it replaces, that no fork row
/// lists now goes.
fn write_fork(
    doc: &LoroDoc,
    map: &LoroMap,
    key: &str,
    carried: &CarriedFork,
    replaced: Option<&CarriedFork>,
) -> Result<()> {
    let whole = encode_fork(carried)?;
    match &carried.snapshot {
        Some(ForkSnapshot::Whole(snapshot)) if whole.len() > PART_BYTES => {
            let (parts, pieces) = split_parts(snapshot)?;
            let row = CarriedFork {
                snapshot: Some(ForkSnapshot::Parts(parts)),
                ..carried.clone()
            };
            map_insert_bytes(map, key, &encode_fork(&row)?)?;
            commit(doc);
            write_parts(map, &pieces, || commit(doc))?;
        }
        _ => {
            map_insert_bytes(map, key, &whole)?;
            commit(doc);
        }
    }
    if let Some(old) = replaced.and_then(snapshot_parts) {
        let listed = listed_parts(map);
        let mut gone = false;
        for part in old.keys() {
            if !listed.contains(&part) && map_contains_binary(map, &part) {
                map_delete(map, &part)?;
                gone = true;
            }
        }
        if gone {
            commit(doc);
        }
    }
    Ok(())
}

/// The key of each part a fork row `map` holds lists.
fn listed_parts(map: &LoroMap) -> BTreeSet<String> {
    let mut listed = BTreeSet::new();
    for (_, bytes) in row_values(map, |map_key| map_key.starts_with(FORK_KEY_PREFIX)) {
        if let Ok(carried) = decode_fork(&bytes)
            && let Some(parts) = snapshot_parts(&carried)
        {
            listed.extend(parts.keys());
        }
    }
    listed
}

/// Merges every row window `key`'s document carries into this vault's, as a
/// window open does. A row that fails is logged and left; it never stops the
/// open.
pub(crate) fn apply_typed_body_rows_map(vault: &Vault, doc: &LoroDoc, key: &WindowKey) {
    if key.world().is_some() || !holds_typed_body_rows_map(doc) {
        return;
    }
    let map = doc.get_map(TYPED_BODY_ROWS_MAP);
    let rows = row_values(&map, |_| true);
    merge_rows(vault, &map, key.as_str(), rows);
}

/// Observer B for the typed body row map: each row an import brought, and
/// each fork one of whose snapshot's parts it brought, since a fork waits
/// for its parts.
pub(crate) fn materialize_typed_body_rows_from_delta(
    doc: &LoroDoc,
    delta: &MapDelta<'_>,
    vault: &Vault,
    window_key: &str,
    _lease_vault_id: u64,
) -> Option<Vec<EntityId>> {
    let mut rows = Vec::new();
    let mut parts = BTreeSet::new();
    let mut deleted = false;
    for (map_key, value) in &delta.updated {
        match value {
            Some(ValueOrContainer::Value(LoroValue::Binary(bytes))) => {
                let map_key = map_key.to_string();
                if is_part_key(&map_key) {
                    parts.insert(map_key);
                } else {
                    rows.push((map_key, bytes.to_vec()));
                }
            }
            None => deleted |= !is_part_key(&map_key.to_string()),
            Some(_) => {}
        }
    }
    // A row the import deleted (a removed body's, or an open fork whose
    // opener was erased) still stands in the window's history with the
    // actors it named: the window is pinned history-free before any export
    // of it can ship that history.
    if deleted
        && let Err(error) =
            vault.with_write_txn_grouped(|txn| pin_history_free_in_txn(vault, txn, window_key))
    {
        tracing::warn!(window = window_key, error = %error, "typed body row window not pinned");
    }
    let map = doc.get_map(TYPED_BODY_ROWS_MAP);
    if !parts.is_empty() {
        let updated: BTreeSet<String> = rows.iter().map(|(map_key, _)| map_key.clone()).collect();
        let waiting = row_values(&map, |map_key| {
            map_key.starts_with(FORK_KEY_PREFIX) && !updated.contains(map_key)
        });
        rows.extend(waiting.into_iter().filter(|(_, bytes)| {
            decode_fork(bytes).is_ok_and(|carried| {
                snapshot_parts(&carried)
                    .is_some_and(|listed| listed.keys().any(|part| parts.contains(&part)))
            })
        }));
    }
    merge_rows(vault, &map, window_key, rows);
    Some(Vec::new())
}

/// Merges the rows window `key`'s document carries for the bodies among
/// `rows`, just committed here: a receipt or fork that waited for its body
/// finds it.
pub(crate) fn merge_committed_typed_body_rows(
    vault: &Vault,
    doc: &LoroDoc,
    key: &WindowKey,
    rows: &BTreeSet<EntityId>,
) {
    if key.world().is_some() || !holds_typed_body_rows_map(doc) {
        return;
    }
    let map = doc.get_map(TYPED_BODY_ROWS_MAP);
    let carried = row_values(&map, |map_key| {
        entity_of(map_key).is_some_and(|entity| rows.contains(&entity))
    });
    merge_rows(vault, &map, key.as_str(), carried);
}

/// Pins window `window` to history-free transport in the caller's writer,
/// as an erase that rewrites a carrier does.
fn pin_history_free_in_txn(vault: &Vault, txn: &mut heed::RwTxn<'_>, window: &str) -> Result<()> {
    HISTORY_FREE_WINDOW.put(&vault.store, txn, &window.to_owned(), &[1u8])
}

/// Whether `doc` holds a typed body row map. Looking a root up by name
/// creates it: look first.
fn holds_typed_body_rows_map(doc: &LoroDoc) -> bool {
    matches!(doc.get_value(), LoroValue::Map(roots) if roots.contains_key(TYPED_BODY_ROWS_MAP))
}

/// Each row `map` holds whose key `keep` takes, with its value. A part is
/// no row.
fn row_values(map: &LoroMap, keep: impl Fn(&str) -> bool) -> Vec<(String, Vec<u8>)> {
    let mut rows = Vec::new();
    map.for_each(|map_key, value| {
        if !is_part_key(map_key)
            && keep(map_key)
            && let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value
        {
            rows.push((map_key.to_owned(), bytes.to_vec()));
        }
    });
    rows
}

/// Merges each carried row into this vault's, one write each, so a refusal
/// stays with its row; a fork's snapshot is joined from its parts in `map`
/// first, and one whose parts have not all landed waits. A copy that
/// diverges from the one held here is quarantined in the same write, once
/// per divergence, and both copies stand.
fn merge_rows(vault: &Vault, map: &LoroMap, window: &str, rows: Vec<(String, Vec<u8>)>) {
    let mut merged = 0_usize;
    for (map_key, bytes) in rows {
        let Ok(row) = decode_row(&map_key, &bytes) else {
            tracing::warn!(window, key = %map_key, "typed body row malformed; left out");
            continue;
        };
        let outcome = match row {
            Row::Receipt(record) => vault.with_write_txn_grouped(|txn| {
                // An erased receipt in the window may have replaced a live
                // one whose actor and MadeBy its history still holds, here or
                // on the machine that erased it: the window is pinned
                // history-free in this writer, whatever the merge, before any
                // export of it can ship that history.
                if !record.names_actor() {
                    pin_history_free_in_txn(vault, txn, window)?;
                }
                let merge = merge_carried_receipt_in_txn(vault, txn, &record)?;
                if merge == DocumentMerge::Conflict {
                    let divergence = receipt_divergence_digest(vault, txn, &record, &bytes)?;
                    quarantine_once_in_txn(
                        vault,
                        txn,
                        window,
                        QuarantineContainer::TypedBodyRows,
                        &map_key,
                        &refused("receipts diverge"),
                        &divergence,
                    )?;
                }
                Ok(merge)
            }),
            Row::Fork(mut carried) => {
                if let Some(parts) = snapshot_parts(&carried).cloned() {
                    let Some(snapshot) = join_parts(map, &parts) else {
                        tracing::debug!(window, key = %map_key, "typed body fork waits for its parts");
                        continue;
                    };
                    carried.snapshot = Some(ForkSnapshot::Whole(snapshot));
                }
                vault.with_write_txn_grouped(|txn| {
                    // A fork whose opener or settler reads as erased may have
                    // replaced a copy that named them, which the window's
                    // history still holds: pinned as an erased receipt is.
                    if carried.names_erased_actor() {
                        pin_history_free_in_txn(vault, txn, window)?;
                    }
                    let merge =
                        merge_carried_fork_in_txn(vault, txn, &carried, &OFFICE_BODY_OWNER)?;
                    if merge == DocumentMerge::Conflict {
                        let divergence = fork_divergence_digest(vault, txn, &carried, &bytes)?;
                        quarantine_once_in_txn(
                            vault,
                            txn,
                            window,
                            QuarantineContainer::TypedBodyRows,
                            &map_key,
                            &refused("forks diverge"),
                            &divergence,
                        )?;
                    }
                    Ok(merge)
                })
            }
        };
        match outcome {
            Ok(DocumentMerge::Written) => merged += 1,
            Ok(DocumentMerge::Held) => {}
            Ok(DocumentMerge::Waiting) => {
                tracing::debug!(window, key = %map_key, "typed body row waits for its body");
            }
            Ok(DocumentMerge::Conflict) => tracing::warn!(
                window,
                key = %map_key,
                "typed body row diverges; quarantined, and the one held here stands"
            ),
            Ok(DocumentMerge::Refused(reason) | DocumentMerge::Deferred(reason)) => {
                tracing::debug!(window, key = %map_key, reason, "typed body row left out");
            }
            Err(error) => {
                tracing::warn!(window, key = %map_key, error = %error, "typed body row not merged");
            }
        }
    }
    if merged > 0 {
        tracing::debug!(window, merged, "typed body rows merged");
    }
}

/// What the divergence of `carried`, encoded as `bytes`, from the copy held
/// here is quarantined under, beside the receipt's key: a digest of both
/// copies in byte order, so the same two copies name one row however often
/// they meet.
fn receipt_divergence_digest(
    vault: &Vault,
    txn: &RoTxn<'_>,
    carried: &CarriedReceipt,
    bytes: &[u8],
) -> Result<[u8; 32]> {
    let held = carried
        .held_here_in_txn(vault, txn)?
        .map(|held| encode_receipt(&held))
        .transpose()?
        .unwrap_or_default();
    Ok(divergence_digest(&held, bytes))
}

/// [`receipt_divergence_digest`] for `carried`, a fork whose row the map
/// holds as `bytes`: against this vault's copy, its document whole.
fn fork_divergence_digest(
    vault: &Vault,
    txn: &RoTxn<'_>,
    carried: &CarriedFork,
    bytes: &[u8],
) -> Result<[u8; 32]> {
    let held = carried
        .held_here_in_txn(vault, txn, &OFFICE_BODY_OWNER)?
        .map(|held| encode_fork(&held))
        .transpose()?
        .unwrap_or_default();
    Ok(divergence_digest(&held, bytes))
}

/// A digest of `held` and `carried`, two copies of one row, in byte order.
fn divergence_digest(held: &[u8], carried: &[u8]) -> [u8; 32] {
    let mut copies = [held, carried];
    copies.sort_unstable();
    let mut hasher = blake3::Hasher::new_derive_key(DIVERGENCE_CONTEXT);
    for copy in copies {
        hasher.update(&u64::try_from(copy.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(copy);
    }
    *hasher.finalize().as_bytes()
}

/// Drops from `doc` each row of a body this vault removed or the window
/// does not carry, and each part no fork row lists: erase wins over a row,
/// and a row never rides where its body does not. A copy naming an actor
/// this vault erased takes its erased form: a receipt the commit time alone,
/// a fork naming no one in its place, and an open fork whose opener this
/// vault erased goes. A live doc keeps the old copies in its history, so
/// `history_free` names the window pinned history-free before any row goes
/// or changes, as `office_proposals::scrub_office_proposals` does; the
/// sweep, whose shallow cut drops that history, passes `None`. Returns
/// whether a row went or changed, committed.
pub(crate) fn scrub_typed_body_rows(
    vault: &Vault,
    doc: &LoroDoc,
    history_free: Option<&WindowKey>,
) -> Result<bool> {
    if !holds_typed_body_rows_map(doc) {
        return Ok(false);
    }
    let map = doc.get_map(TYPED_BODY_ROWS_MAP);
    let entities = doc.get_map("entities");
    let mut changed = Vec::new();
    let mut listed = BTreeSet::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        for (map_key, bytes) in row_values(&map, |_| true) {
            let Ok(row) = decode_row(&map_key, &bytes) else {
                continue;
            };
            let entity = row.entity();
            if !map_contains_binary(&entities, &entity.to_hex())
                || crate::ports::removed_in_txn(&vault.store, &rtxn, &entity)?
            {
                changed.push((map_key, None));
                continue;
            }
            match row {
                Row::Receipt(record) => {
                    let here = record.clone().carried_here(vault, &rtxn)?;
                    if here != record {
                        changed.push((map_key, Some(encode_receipt(&here)?)));
                    }
                }
                Row::Fork(carried) => {
                    match carried
                        .clone()
                        .carried_here(vault, &rtxn, &OFFICE_BODY_OWNER)?
                    {
                        None => changed.push((map_key, None)),
                        Some(here) => {
                            if let Some(parts) = snapshot_parts(&here) {
                                listed.extend(parts.keys());
                            }
                            if here != carried {
                                changed.push((map_key, Some(encode_fork(&here)?)));
                            }
                        }
                    }
                }
            }
        }
    }
    changed.extend(
        unreferenced_parts(&map, &listed)
            .into_iter()
            .map(|part| (part, None)),
    );
    if changed.is_empty() {
        return Ok(false);
    }
    if let Some(key) = history_free {
        super::window::require_history_free_window(vault, key)?;
    }
    for (map_key, bytes) in &changed {
        match bytes {
            Some(bytes) => map_insert_bytes(&map, map_key, bytes)?,
            None => map_delete(&map, map_key)?,
        }
    }
    doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    Ok(true)
}
