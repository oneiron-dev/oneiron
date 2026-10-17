//! FIX 853 (OF-460): document quote pins on the window plane.
//!
//! A reply that quotes a span of a MESSAGE's document pins the span: its
//! version, its cursors and the quote that version proves
//! (`entity_doc::CitationPin`). The reply carries only the message and its
//! own id, so a machine that holds no pin reads the strip Drifted, with no
//! excerpt. The pin rides the base window's `document_pins` map, beside the
//! MESSAGE it quotes, where the message's history lives. Only the owner's
//! machines take the map: a federated or guest window copies none of it, as
//! a pin holds the quoted text and the quoting actor.
//!
//! - A pin is written once. It rides under its message, its citation and the
//!   digest of its bytes, so an equal pin dedupes and a different one for the
//!   same quote rides beside it; neither replaces the other. Each machine
//!   keeps the pin it holds and logs the other.
//! - Admission refuses every insert into the map that is not a whole pin
//!   filed under its own key, in the latest state, at a snapshot's root and
//!   in every retained operation.
//! - Reverse rematerialization mirrors a MESSAGE's pins beside it. The quote
//!   door hands the message to the live mirror, which mirrors a new pin into
//!   the live window that carries the message.
//! - Forward rematerialization and Observer B install each carried pin here
//!   (`Vault::merge_replicated_quote_pin_in_txn`).
//! - Every export, and the erase sweep, drop each pin of a message or reply
//!   this vault erased, and each pin of a message the window does not carry.

use std::collections::BTreeSet;

use heed::RoTxn;
use loro::event::MapDelta;
use loro::{CommitOptions, LoroDoc, LoroMap, LoroValue, ValueOrContainer};

use super::bridge::BRIDGE_ORIGIN;
use super::loro_support::{map_contains_binary, map_delete, map_insert_bytes};
use super::types::WindowKey;
use crate::Vault;
use crate::entity_doc::{CitationPin, PinMerge};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};

/// The base window root map that carries document quote pins.
pub(crate) const DOCUMENT_PINS_MAP: &str = "document_pins";

/// The largest pin a window carries.
const MAX_PIN_BYTES: usize = 1 << 20;

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("document pin refused: {reason}"))
}

/// Decodes a carried pin, with the message it quotes and the record that
/// cites it. A pin has one spelling, so equal pins ride under one key.
fn decode(bytes: &[u8]) -> Result<(CitationPin, EntityId, EntityId)> {
    if bytes.len() > MAX_PIN_BYTES {
        return Err(refused("too large"));
    }
    let pin: CitationPin = rmp_serde::from_slice(bytes).map_err(|_| refused("not a pin"))?;
    if rmp_serde::to_vec_named(&pin).ok().as_deref() != Some(bytes) {
        return Err(refused("not in its one spelling"));
    }
    let (message, citation) = pin
        .carried_ids()
        .ok_or_else(|| refused("not a whole pin"))?;
    Ok((pin, message, citation))
}

/// The key a pin of `message` cited by `citation`, encoded as `bytes`, rides
/// under: the two ids, then its own digest.
fn carrier_key(message: EntityId, citation: EntityId, bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.document_pins.v1");
    hasher.update(bytes);
    format!(
        "{}/{}/{}",
        message.to_hex(),
        citation.to_hex(),
        bytes_to_hex_lower(&hasher.finalize().as_bytes()[..16])
    )
}

/// The key and bytes `pin` rides under, when every peer would admit them.
fn carrier(pin: &CitationPin) -> Option<(String, Vec<u8>)> {
    let bytes = rmp_serde::to_vec_named(pin).ok()?;
    let (_, message, citation) = decode(&bytes).ok()?;
    Some((carrier_key(message, citation, &bytes), bytes))
}

/// Admits one insert into a window's `document_pins` map: a whole pin of a
/// base window, filed under its own key.
pub(crate) fn admit_document_pin_carrier(
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
    let (_, message, citation) = decode(bytes)?;
    if carrier_key(message, citation, bytes) != map_key {
        return Err(refused("filed under another key"));
    }
    Ok(())
}

/// [`admit_document_pin_carrier`] over every pin `map` holds.
pub(crate) fn admit_document_pin_map(key: Option<&WindowKey>, map: &LoroMap) -> Result<()> {
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
        admit_document_pin_carrier(key, map_key, value)?;
    }
    Ok(())
}

/// Writes into `doc` each pin this vault holds on MESSAGE `message` that the
/// window lacks. A pin of a reply this vault erased stays out, and so does
/// one no peer would admit. Returns whether it wrote; the caller commits.
pub(crate) fn mirror_document_pins(
    vault: &Vault,
    doc: &LoroDoc,
    message: &EntityId,
) -> Result<bool> {
    let pins = {
        let rtxn = vault.store.env.read_txn()?;
        let mut pins = Vec::new();
        for pin in vault.message_quote_pins_in_txn(&rtxn, message)? {
            let erased = match pin.carried_ids() {
                Some((_, citation)) => {
                    crate::ports::removed_in_txn(&vault.store, &rtxn, &citation)?
                }
                None => true,
            };
            if !erased {
                pins.push(pin);
            }
        }
        pins
    };
    if pins.is_empty() {
        return Ok(false);
    }
    let map = doc.get_map(DOCUMENT_PINS_MAP);
    let mut wrote = false;
    for pin in &pins {
        let Some((key, bytes)) = carrier(pin) else {
            tracing::warn!(
                message = %message.to_hex(),
                citation = %pin.citation,
                "document pin not carried: no peer would admit it"
            );
            continue;
        };
        if map_contains_binary(&map, &key) {
            continue;
        }
        map_insert_bytes(&map, &key, &bytes)?;
        wrote = true;
    }
    Ok(wrote)
}

/// Merges every pin window `key`'s document carries into this vault's, as a
/// window open does. A pin that fails is logged and left; it never stops
/// the open.
pub(crate) fn apply_document_pin_map(vault: &Vault, doc: &LoroDoc, key: &WindowKey) {
    if key.world().is_some() || !holds_document_pin_map(doc) {
        return;
    }
    let mut rows = Vec::new();
    doc.get_map(DOCUMENT_PINS_MAP).for_each(|map_key, value| {
        if let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value {
            rows.push((map_key.to_owned(), bytes.to_vec()));
        }
    });
    merge_pins(vault, key.as_str(), rows);
}

/// Observer B for the document pin map: each pin an import brought. A pin
/// is written once, so a dropped carrier takes nothing from this vault.
pub(crate) fn materialize_document_pins_from_delta(
    _doc: &LoroDoc,
    delta: &MapDelta<'_>,
    vault: &Vault,
    window_key: &str,
    _lease_vault_id: u64,
) -> Option<Vec<EntityId>> {
    let rows = delta
        .updated
        .iter()
        .filter_map(|(key, value)| match value {
            Some(ValueOrContainer::Value(LoroValue::Binary(bytes))) => {
                Some((key.to_string(), bytes.to_vec()))
            }
            _ => None,
        })
        .collect();
    merge_pins(vault, window_key, rows);
    Some(Vec::new())
}

/// Whether `doc` holds a document pin map. Looking a root up by name
/// creates it: look first.
fn holds_document_pin_map(doc: &LoroDoc) -> bool {
    matches!(doc.get_value(), LoroValue::Map(roots) if roots.contains_key(DOCUMENT_PINS_MAP))
}

/// Merges each carried pin into this vault's in one write.
fn merge_pins(vault: &Vault, window: &str, rows: Vec<(String, Vec<u8>)>) {
    let mut carried = Vec::new();
    for (map_key, bytes) in rows {
        match decode(&bytes) {
            Ok((pin, message, citation)) if carrier_key(message, citation, &bytes) == map_key => {
                carried.push((map_key, pin));
            }
            _ => tracing::warn!(window, key = %map_key, "document pin malformed; left out"),
        }
    }
    if carried.is_empty() {
        return;
    }
    let outcome = vault.with_write_txn_grouped(|wtxn| {
        let mut merged = 0_usize;
        for (map_key, pin) in &carried {
            match vault.merge_replicated_quote_pin_in_txn(wtxn, pin)? {
                PinMerge::Written => merged += 1,
                PinMerge::Held => {}
                PinMerge::Conflict => tracing::warn!(
                    window,
                    key = %map_key,
                    "document pin conflicts; the one held here stands and the other stays in the window"
                ),
                PinMerge::Refused(reason) => tracing::warn!(
                    window,
                    key = %map_key,
                    reason,
                    "document pin does not merge here; left out"
                ),
            }
        }
        Ok(merged)
    });
    match outcome {
        Ok(merged) if merged > 0 => tracing::debug!(window, merged, "document pins merged"),
        Ok(_) => {}
        Err(error) => tracing::warn!(window, error = %error, "document pins not merged"),
    }
}

/// Drops from `doc` each pin of a message or reply this vault erased, and
/// each pin of a message the window no longer carries: erase wins over a
/// pin, and a pin never rides where its message does not. A live doc keeps
/// the old pins in its history, so `history_free` names the window pinned
/// history-free before any pin goes, as `room_facts::scrub_room_facts`
/// does; the sweep, whose shallow cut drops that history, passes `None`.
/// Returns whether a pin went, committed.
pub(crate) fn scrub_document_pins(
    vault: &Vault,
    doc: &LoroDoc,
    history_free: Option<&WindowKey>,
) -> Result<bool> {
    if !holds_document_pin_map(doc) {
        return Ok(false);
    }
    let map = doc.get_map(DOCUMENT_PINS_MAP);
    let mut carried = Vec::new();
    map.for_each(|map_key, value| {
        if let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value
            && let Ok((_, message, citation)) = decode(&bytes)
        {
            carried.push((map_key.to_owned(), message, citation));
        }
    });
    let entities = doc.get_map("entities");
    let gone = {
        let rtxn = vault.store.env.read_txn()?;
        let mut gone = Vec::new();
        for (map_key, message, citation) in carried {
            if !map_contains_binary(&entities, &message.to_hex())
                || crate::ports::removed_in_txn(&vault.store, &rtxn, &message)?
                || crate::ports::removed_in_txn(&vault.store, &rtxn, &citation)?
            {
                gone.push(map_key);
            }
        }
        gone
    };
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

/// The pin carriers among `rows` a canonical snapshot keeps as the window
/// holds them: each but a pin this vault holds on a message whose document
/// the snapshot captures, in `documents`. That pin rides in the document's
/// history and takes fresh cursors as the document is restored; the
/// window's reverse pass then mirrors it again.
pub(crate) fn canonical_pin_rows(
    vault: &Vault,
    txn: &RoTxn<'_>,
    rows: impl IntoIterator<Item = (String, Vec<u8>)>,
    documents: &BTreeSet<EntityId>,
) -> Result<Vec<(String, Vec<u8>)>> {
    let mut kept = Vec::new();
    for (key, row) in rows {
        if let Ok((pin, message, citation)) = decode(&row)
            && documents.contains(&message)
            && vault
                .message_quote_pin_in_txn(txn, &message, &citation)?
                .is_some_and(|held| held == pin)
        {
            continue;
        }
        kept.push((key, row));
    }
    Ok(kept)
}
