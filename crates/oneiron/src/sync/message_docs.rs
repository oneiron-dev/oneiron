//! FIX 853 (OF-460): a MESSAGE's document on the window plane.
//!
//! A streamed or migrated MESSAGE keeps its text in an entity document, and
//! its row holds only a pointer. Windows carried the row and never the
//! document, so another of the owner's machines held no text for the
//! message, and a quote of it read Drifted there. The document now rides the
//! base window's `message_docs` map, beside its MESSAGE. Only the owner's
//! machines take the map: a federated or guest window copies none of it.
//!
//! - A document rides as its head, under its message, and a snapshot of its
//!   history in linked parts (`carrier_parts`), so no size is skipped. The
//!   head names the document, its incarnation and its version.
//! - A machine whose document holds more than the window's head writes a new
//!   head and snapshot, and the old parts go. After an owner purge the new
//!   snapshot is shallow, and the window is pinned history-free first, so the
//!   purged history stops riding.
//! - Admission refuses every insert into the map that is not a whole head
//!   filed under its message or a part filed under its digest, in the latest
//!   state, at a snapshot's root and in every retained operation.
//! - Reverse rematerialization mirrors a MESSAGE's document beside it, and
//!   the live mirror does as a commit touches the message.
//! - Forward rematerialization, Observer B and the live mirror install a
//!   carried document here (`Vault::merge_carried_message_document_in_txn`):
//!   the same document joins by Loro merge, and another one is logged.
//! - Every export, and the erase sweep, drop the document of a message this
//!   vault erased or the window does not carry, with every part no head
//!   lists.

use std::collections::BTreeSet;

use loro::event::MapDelta;
use loro::{CommitOptions, LoroDoc, LoroMap, LoroValue, ValueOrContainer};
use serde::{Deserialize, Serialize};

use super::bridge::BRIDGE_ORIGIN;
use super::carrier_parts::{
    Parts, admit_part, is_part_key, join_parts, split_parts, unreferenced_parts, write_parts,
};
use super::loro_support::{map_contains_binary, map_delete, map_get_bytes, map_insert_bytes};
use super::types::WindowKey;
use crate::Vault;
use crate::entity_doc::{CarriedDocument, DocumentMerge};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// The base window root map that carries MESSAGE documents.
pub(crate) const MESSAGE_DOCS_MAP: &str = "message_docs";

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("message document refused: {reason}"))
}

/// A MESSAGE's document as a window carries it: its head, and the parts of
/// its snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CarriedHead {
    head: CarriedDocument,
    snapshot: Parts,
}

fn encode(carried: &CarriedHead) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(carried).map_err(|_| refused("does not encode"))
}

/// Decodes a carried head, with its message. A head has one spelling.
fn decode(bytes: &[u8]) -> Result<(CarriedHead, EntityId)> {
    let carried: CarriedHead =
        rmp_serde::from_slice(bytes).map_err(|_| refused("not a document head"))?;
    if encode(&carried)? != bytes {
        return Err(refused("not in its one spelling"));
    }
    let message = carried
        .head
        .message()
        .ok_or_else(|| refused("not a whole head"))?;
    if !carried.snapshot.well_formed() {
        return Err(refused("not a snapshot's parts"));
    }
    Ok((carried, message))
}

/// Admits one insert into a window's `message_docs` map: a whole head of a
/// base window filed under its message, or a part.
pub(crate) fn admit_message_doc_carrier(
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
    let (_, message) = decode(bytes)?;
    if message.to_hex() != map_key {
        return Err(refused("filed under another key"));
    }
    Ok(())
}

/// [`admit_message_doc_carrier`] over every row `map` holds.
pub(crate) fn admit_message_doc_map(key: Option<&WindowKey>, map: &LoroMap) -> Result<()> {
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
        admit_message_doc_carrier(key, map_key, value)?;
    }
    Ok(())
}

/// Writes into `doc` the document MESSAGE `message` holds here, when it holds
/// more than the window's head: operations the head lacks, or a purge. The
/// window's head stands where it holds as much, where it holds operations
/// this machine lacks (they merge here first), where it names another
/// document, or where another machine purged history this one keeps. The
/// head and each part commit on their own. Returns whether it wrote.
pub(crate) fn mirror_message_document(
    vault: &Vault,
    doc: &LoroDoc,
    message: &EntityId,
    window: &WindowKey,
) -> Result<bool> {
    let local = {
        let rtxn = vault.store.env.read_txn()?;
        vault.carried_message_document_in_txn(&rtxn, message)?
    };
    let Some(local) = local else {
        return Ok(false);
    };
    let map = doc.get_map(MESSAGE_DOCS_MAP);
    let key = message.to_hex();
    let held = map_get_bytes(&map, &key)
        .and_then(|bytes| decode(&bytes).ok())
        .map(|(held, _)| held);
    if held.as_ref().is_some_and(|held| {
        !local.holds(&held.head)
            || held.head.covers(&local)
            || (local.shallow.is_empty() && !held.head.shallow.is_empty())
    }) {
        return Ok(false);
    }
    let Some((head, snapshot)) = vault.export_message_document(message)? else {
        return Ok(false);
    };
    let (parts, pieces) = split_parts(&snapshot)?;
    let carried = CarriedHead {
        head,
        snapshot: parts,
    };
    if let Some(held) = &held
        && !carried.head.covers(&held.head)
    {
        // An owner purge here: the old snapshot holds the history it dropped.
        super::window::require_history_free_window(vault, window)?;
    }
    map_insert_bytes(&map, &key, &encode(&carried)?)?;
    commit(doc);
    write_parts(&map, &pieces, || commit(doc))?;
    if let Some(held) = held {
        let listed: BTreeSet<String> = carried.snapshot.keys().collect();
        for part in held.snapshot.keys() {
            if !listed.contains(&part) && map_contains_binary(&map, &part) {
                map_delete(&map, &part)?;
            }
        }
        commit(doc);
    }
    Ok(true)
}

fn commit(doc: &LoroDoc) {
    doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
}

/// Installs every document window `key`'s document carries, as a window
/// open does. A document that fails is logged and left; it never stops the
/// open.
pub(crate) fn apply_message_doc_map(vault: &Vault, doc: &LoroDoc, key: &WindowKey) {
    if key.world().is_some() || !holds_message_doc_map(doc) {
        return;
    }
    let map = doc.get_map(MESSAGE_DOCS_MAP);
    let heads = head_rows(&map, |_| true);
    merge_heads(vault, &map, key.as_str(), heads);
}

/// Observer B for the message document map: each head an import brought,
/// and each head one of whose parts it brought, since a head waits for its
/// parts.
pub(crate) fn materialize_message_docs_from_delta(
    doc: &LoroDoc,
    delta: &MapDelta<'_>,
    vault: &Vault,
    window_key: &str,
    _lease_vault_id: u64,
) -> Option<Vec<EntityId>> {
    let mut updated = BTreeSet::new();
    let mut part_landed = false;
    for (key, value) in &delta.updated {
        if let Some(ValueOrContainer::Value(LoroValue::Binary(_))) = value {
            let key = key.to_string();
            part_landed |= is_part_key(&key);
            updated.insert(key);
        }
    }
    let map = doc.get_map(MESSAGE_DOCS_MAP);
    let mut heads = head_rows(&map, |_| true);
    heads.retain(|(map_key, bytes)| {
        updated.contains(map_key)
            || (part_landed
                && decode(bytes).is_ok_and(|(carried, _)| {
                    carried.snapshot.keys().any(|part| updated.contains(&part))
                }))
    });
    merge_heads(vault, &map, window_key, heads);
    Some(Vec::new())
}

/// Installs the documents window `key`'s document carries for `rows`, just
/// committed here: a MESSAGE row that lands after its document's head
/// finds it here.
pub(crate) fn merge_committed_message_docs(
    vault: &Vault,
    doc: &LoroDoc,
    key: &WindowKey,
    rows: &BTreeSet<EntityId>,
) {
    if key.world().is_some() || !holds_message_doc_map(doc) {
        return;
    }
    let map = doc.get_map(MESSAGE_DOCS_MAP);
    let heads = rows
        .iter()
        .filter_map(|row| {
            let map_key = row.to_hex();
            map_get_bytes(&map, &map_key).map(|bytes| (map_key, bytes))
        })
        .collect();
    merge_heads(vault, &map, key.as_str(), heads);
}

/// Each head `map` holds whose key `keep` takes, with its value.
fn head_rows(map: &LoroMap, keep: impl Fn(&str) -> bool) -> Vec<(String, Vec<u8>)> {
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

/// Whether `doc` holds a message document map. Looking a root up by name
/// creates it: look first.
fn holds_message_doc_map(doc: &LoroDoc) -> bool {
    matches!(doc.get_value(), LoroValue::Map(roots) if roots.contains_key(MESSAGE_DOCS_MAP))
}

/// Installs each carried head's document here, one write each, so a refusal
/// stays with its message. A head this vault already holds is passed over
/// before its parts are joined; one whose parts or message have not landed
/// waits for them.
fn merge_heads(vault: &Vault, map: &LoroMap, window: &str, heads: Vec<(String, Vec<u8>)>) {
    let mut merged = 0_usize;
    for (map_key, bytes) in heads {
        let (carried, message) = match decode(&bytes) {
            Ok((carried, message)) if message.to_hex() == map_key => (carried, message),
            _ => {
                tracing::warn!(window, key = %map_key, "message document head malformed; left out");
                continue;
            }
        };
        let held = vault
            .store
            .env
            .read_txn()
            .map_err(Error::from)
            .and_then(|rtxn| vault.carried_message_document_in_txn(&rtxn, &message));
        match held {
            Ok(Some(held)) if held.holds(&carried.head) => continue,
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(window, key = %map_key, error = %error, "message document not merged");
                continue;
            }
        }
        let Some(snapshot) = join_parts(map, &carried.snapshot) else {
            tracing::debug!(window, key = %map_key, "message document waits for its parts");
            continue;
        };
        let outcome = vault.with_write_txn_grouped(|txn| {
            vault.merge_carried_message_document_in_txn(txn, &carried.head, &snapshot)
        });
        match outcome {
            Ok(DocumentMerge::Written) => merged += 1,
            Ok(DocumentMerge::Held) => {}
            Ok(DocumentMerge::Waiting) => {
                tracing::debug!(window, key = %map_key, "message document waits for its message");
            }
            Ok(DocumentMerge::Conflict) => tracing::warn!(
                window,
                key = %map_key,
                "message document conflicts; the one held here stands and the other stays in the window"
            ),
            Ok(DocumentMerge::Refused(reason)) => tracing::warn!(
                window,
                key = %map_key,
                reason,
                "message document does not merge here; left out"
            ),
            Err(error) => {
                tracing::warn!(window, key = %map_key, error = %error, "message document not merged");
            }
        }
    }
    if merged > 0 {
        tracing::debug!(window, merged, "message documents merged");
    }
}

/// Drops from `doc` the document of each message this vault erased or the
/// window no longer carries, with every part no remaining head lists: erase
/// wins over a document, and a document never rides where its message does
/// not. A live doc keeps the old rows in its history, so `history_free`
/// names the window pinned history-free before any row goes, as
/// `room_facts::scrub_room_facts` does; the sweep, whose shallow cut drops
/// that history, passes `None`. Returns whether a row went, committed.
pub(crate) fn scrub_message_docs(
    vault: &Vault,
    doc: &LoroDoc,
    history_free: Option<&WindowKey>,
) -> Result<bool> {
    if !holds_message_doc_map(doc) {
        return Ok(false);
    }
    let map = doc.get_map(MESSAGE_DOCS_MAP);
    let entities = doc.get_map("entities");
    let mut gone = Vec::new();
    let mut referenced = BTreeSet::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        for (map_key, bytes) in head_rows(&map, |_| true) {
            let Ok((carried, message)) = decode(&bytes) else {
                continue;
            };
            if !map_contains_binary(&entities, &map_key)
                || crate::ports::removed_in_txn(&vault.store, &rtxn, &message)?
            {
                gone.push(map_key);
            } else {
                referenced.extend(carried.snapshot.keys());
            }
        }
    }
    gone.extend(unreferenced_parts(&map, &referenced));
    if gone.is_empty() {
        return Ok(false);
    }
    if let Some(key) = history_free {
        super::window::require_history_free_window(vault, key)?;
    }
    for map_key in &gone {
        map_delete(&map, map_key)?;
    }
    doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    Ok(true)
}
