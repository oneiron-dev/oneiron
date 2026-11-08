//! FIX 12470 (slice A): a typed body's rows on the window plane.
//!
//! A typed body's operations ride its entity's document frame to the owner's
//! other machines (FIX 2458), but each commit's receipt row stayed on the
//! machine that wrote it, so every carried commit read as unreceipted there
//! and a fold of the body's provenance failed. Those rows now ride the base
//! window's `typed_body_rows` map beside their body, as an office proposal
//! rides `office_proposals`. Only the owner's machines take the map: a
//! federated or guest window copies none of it. Each family of rows files
//! under a key prefix of its own; a commit receipt's is `r/`.
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
//! - Admission refuses every insert into the map that is not a whole receipt
//!   filed under its own key, in the latest state, at a snapshot's root and
//!   in every retained operation.
//! - Every export, and the erase sweep, drop each receipt of a body this
//!   vault removed or the window does not carry, and a copy naming an actor
//!   this vault erased takes its erased form.

pub(super) mod checkpoint;

use std::collections::BTreeSet;

use heed::RoTxn;
use loro::event::MapDelta;
use loro::{CommitOptions, LoroDoc, LoroMap, LoroValue, ValueOrContainer};

use super::bridge::BRIDGE_ORIGIN;
use super::loro_support::{map_contains_binary, map_delete, map_get_bytes, map_insert_bytes};
use super::quarantine::{QuarantineContainer, quarantine_once_in_txn};
use super::types::WindowKey;
use super::window_rows::HISTORY_FREE_WINDOW;
use crate::Vault;
use crate::entity_doc::DocumentMerge;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::typed_body::{CarriedReceipt, carried_receipts_in_txn, merge_carried_receipt_in_txn};

/// The base window root map that carries a typed body's rows.
pub(crate) const TYPED_BODY_ROWS_MAP: &str = "typed_body_rows";

/// The key prefix of a commit receipt's row.
const RECEIPT_KEY_PREFIX: &str = "r/";

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

/// The body's entity `map_key` names, when it is a row's key in its one
/// spelling.
fn entity_of(map_key: &str) -> Option<EntityId> {
    receipt_of(map_key).map(|(entity, _)| entity)
}

/// Admits one insert into a window's `typed_body_rows` map: a whole receipt
/// of a base window filed under its own key.
pub(crate) fn admit_typed_body_row_carrier(
    key: Option<&WindowKey>,
    map_key: &str,
    value: &LoroValue,
) -> Result<()> {
    if key.is_some_and(|key| key.world().is_some()) {
        return Err(refused("in a world window"));
    }
    let LoroValue::Binary(bytes) = value else {
        return Err(refused("not bytes"));
    };
    if receipt_key(&decode_receipt(bytes)?) != map_key {
        return Err(refused("filed under another key"));
    }
    Ok(())
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

/// Merges every row window `key`'s document carries into this vault's, as a
/// window open does. A row that fails is logged and left; it never stops the
/// open.
pub(crate) fn apply_typed_body_rows_map(vault: &Vault, doc: &LoroDoc, key: &WindowKey) {
    if key.world().is_some() || !holds_typed_body_rows_map(doc) {
        return;
    }
    let rows = row_values(&doc.get_map(TYPED_BODY_ROWS_MAP), |_| true);
    merge_rows(vault, key.as_str(), rows);
}

/// Observer B for the typed body row map: each row an import brought.
pub(crate) fn materialize_typed_body_rows_from_delta(
    _doc: &LoroDoc,
    delta: &MapDelta<'_>,
    vault: &Vault,
    window_key: &str,
    _lease_vault_id: u64,
) -> Option<Vec<EntityId>> {
    let mut rows = Vec::new();
    for (map_key, value) in &delta.updated {
        if let Some(ValueOrContainer::Value(LoroValue::Binary(bytes))) = value {
            rows.push((map_key.to_string(), bytes.to_vec()));
        }
    }
    merge_rows(vault, window_key, rows);
    Some(Vec::new())
}

/// Merges the rows window `key`'s document carries for the bodies among
/// `rows`, just committed here: a receipt that waited for its body finds it.
pub(crate) fn merge_committed_typed_body_rows(
    vault: &Vault,
    doc: &LoroDoc,
    key: &WindowKey,
    rows: &BTreeSet<EntityId>,
) {
    if key.world().is_some() || !holds_typed_body_rows_map(doc) {
        return;
    }
    let carried = row_values(&doc.get_map(TYPED_BODY_ROWS_MAP), |map_key| {
        entity_of(map_key).is_some_and(|entity| rows.contains(&entity))
    });
    merge_rows(vault, key.as_str(), carried);
}

/// Whether `doc` holds a typed body row map. Looking a root up by name
/// creates it: look first.
fn holds_typed_body_rows_map(doc: &LoroDoc) -> bool {
    matches!(doc.get_value(), LoroValue::Map(roots) if roots.contains_key(TYPED_BODY_ROWS_MAP))
}

/// Each row `map` holds whose key `keep` takes, with its value.
fn row_values(map: &LoroMap, keep: impl Fn(&str) -> bool) -> Vec<(String, Vec<u8>)> {
    let mut rows = Vec::new();
    map.for_each(|map_key, value| {
        if keep(map_key)
            && let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value
        {
            rows.push((map_key.to_owned(), bytes.to_vec()));
        }
    });
    rows
}

/// Merges each carried row into this vault's, one write each, so a refusal
/// stays with its row. A copy that diverges from the one held here is
/// quarantined in the same write, once per divergence, and both copies
/// stand.
fn merge_rows(vault: &Vault, window: &str, rows: Vec<(String, Vec<u8>)>) {
    let mut merged = 0_usize;
    for (map_key, bytes) in rows {
        let record = match decode_receipt(&bytes) {
            Ok(record) if receipt_key(&record) == map_key => record,
            _ => {
                tracing::warn!(window, key = %map_key, "typed body row malformed; left out");
                continue;
            }
        };
        let outcome = vault.with_write_txn_grouped(|txn| {
            // An erased receipt in the window may have replaced a live one
            // whose actor and MadeBy its history still holds, here or on the
            // machine that erased it: the window is pinned history-free in
            // this writer, whatever the merge, before any export of it can
            // ship that history.
            if !record.names_actor() {
                HISTORY_FREE_WINDOW.put(&vault.store, txn, &window.to_owned(), &[1u8])?;
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
        });
        match outcome {
            Ok(DocumentMerge::Written) => merged += 1,
            Ok(DocumentMerge::Held) => {}
            Ok(DocumentMerge::Waiting) => {
                tracing::debug!(window, key = %map_key, "typed body receipt waits for its body");
            }
            Ok(DocumentMerge::Conflict) => tracing::warn!(
                window,
                key = %map_key,
                "typed body receipt diverges; quarantined, and the one held here stands"
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
    let mut copies = [held.as_slice(), bytes];
    copies.sort_unstable();
    let mut hasher = blake3::Hasher::new_derive_key(DIVERGENCE_CONTEXT);
    for copy in copies {
        hasher.update(&u64::try_from(copy.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(copy);
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Drops from `doc` each receipt of a body this vault removed or the window
/// does not carry: erase wins over a receipt, and a receipt never rides
/// where its body does not. A copy naming an actor this vault erased takes
/// its erased form, the commit time alone. A live doc keeps the old copies
/// in its history, so `history_free` names the window pinned history-free
/// before any row goes or changes, as `office_proposals::scrub_office_proposals`
/// does; the sweep, whose shallow cut drops that history, passes `None`.
/// Returns whether a row went or changed, committed.
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
    {
        let rtxn = vault.store.env.read_txn()?;
        for (map_key, bytes) in row_values(&map, |_| true) {
            let Ok(record) = decode_receipt(&bytes) else {
                continue;
            };
            let entity = record.entity;
            if !map_contains_binary(&entities, &entity.to_hex())
                || crate::ports::removed_in_txn(&vault.store, &rtxn, &entity)?
            {
                changed.push((map_key, None));
                continue;
            }
            let here = record.clone().carried_here(vault, &rtxn)?;
            if here != record {
                changed.push((map_key, Some(encode_receipt(&here)?)));
            }
        }
    }
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
