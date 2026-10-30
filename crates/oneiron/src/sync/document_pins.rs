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
//!   digest of its bytes naming no one, so an equal pin dedupes and a
//!   different one for the same quote rides beside it; neither replaces the
//!   other. Each machine keeps the pin it holds and logs the other. Pins that
//!   differ only in their actor ride under one key: one naming no one
//!   replaces its live twin, never the other way, and two live actors
//!   conflict (FIX 4247).
//! - A pin larger than a part rides as linked parts (`carrier_parts`), its
//!   key holding their manifest, so no quote is too long to travel. The
//!   parts hold the pin naming no one and the manifest names its actor, so
//!   no part names anyone and a scrub rewrites the actor of a pin whose
//!   parts have not all landed (FIX 4789).
//! - Admission refuses every insert into the map that is not a whole pin or
//!   a pin's manifest filed under its own key, or a part filed under its
//!   digest, in the latest state, at a snapshot's root and in every retained
//!   operation.
//! - Reverse rematerialization mirrors a MESSAGE's pins beside it. The quote
//!   door hands the message to the live mirror, which mirrors a new pin into
//!   the live window that carries the message, or faults in the message's
//!   window when none is loaded (FIX 3462, `cold_pin_windows`).
//! - Forward rematerialization and Observer B install each carried pin here
//!   (`Vault::merge_replicated_quote_pin_in_txn`).
//! - Every export, and the erase sweep, drop each pin of a message or reply
//!   this vault erased, and each pin of a message the window does not carry,
//!   with the parts no pin lists. A pin whose actor this vault erased, or
//!   whose erased twin it holds, rides naming no one.

pub(super) mod checkpoint;

use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;
use loro::event::MapDelta;
use loro::{CommitOptions, LoroDoc, LoroMap, LoroValue, ValueOrContainer};
use serde::{Deserialize, Serialize};

use super::bridge::BRIDGE_ORIGIN;
use super::carrier_parts::{
    PART_BYTES, Parts, admit_part, is_part_key, join_parts, split_parts, unreferenced_parts,
    write_parts,
};
use super::loro_support::{map_contains_binary, map_delete, map_get_bytes, map_insert_bytes};
use super::types::WindowKey;
use crate::Vault;
use crate::entity_doc::{CitationPin, DocActor, PinMerge};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};

/// The base window root map that carries document quote pins.
pub(crate) const DOCUMENT_PINS_MAP: &str = "document_pins";

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("document pin refused: {reason}"))
}

/// Decodes a pin's bytes, with the message it quotes and the record that
/// cites it. A pin has one spelling, so equal pins ride under one key.
fn decode_pin(bytes: &[u8]) -> Result<(CitationPin, EntityId, EntityId)> {
    let pin: CitationPin = rmp_serde::from_slice(bytes).map_err(|_| refused("not a pin"))?;
    if rmp_serde::to_vec_named(&pin).ok().as_deref() != Some(bytes) {
        return Err(refused("not in its one spelling"));
    }
    let (message, citation) = pin
        .carried_ids()
        .ok_or_else(|| refused("not a whole pin"))?;
    Ok((pin, message, citation))
}

/// What a pin key holds: the pin, when it fits in a part, or the manifest of
/// its parts.
enum Carried {
    Whole(CitationPin, EntityId, EntityId),
    Parted(PartedPin),
}

/// The manifest of a pin larger than a part (FIX 4789): the parts of the
/// pin naming no one, and the actor it names, so no part names anyone and
/// the actor is rewritten here alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PartedPin {
    parts: Parts,
    actor: DocActor,
}

/// Decodes the value under a pin key, in its one spelling.
fn decode_carried(bytes: &[u8]) -> Result<Carried> {
    if bytes.len() <= PART_BYTES
        && let Ok((pin, message, citation)) = decode_pin(bytes)
    {
        return Ok(Carried::Whole(pin, message, citation));
    }
    let parted: PartedPin = rmp_serde::from_slice(bytes).map_err(|_| refused("not a pin"))?;
    if rmp_serde::to_vec_named(&parted).ok().as_deref() != Some(bytes)
        || !parted.parts.well_formed()
    {
        return Err(refused("not a pin's parts"));
    }
    Ok(Carried::Parted(parted))
}

/// The key `pin`, of `message` cited by `citation`, rides under: the two
/// ids, then the digest of its one spelling naming no one, so the pin and
/// its erased twin ride under one key (FIX 4247).
fn carrier_key(message: EntityId, citation: EntityId, pin: &CitationPin) -> Result<String> {
    let bytes =
        rmp_serde::to_vec_named(&pin.actor_erased()).map_err(|_| refused("does not encode"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.document_pins.v1");
    hasher.update(&bytes);
    Ok(format!(
        "{}/{}/{}",
        message.to_hex(),
        citation.to_hex(),
        bytes_to_hex_lower(&hasher.finalize().as_bytes()[..16])
    ))
}

/// The message and citation a pin key names, when it is one's spelling.
fn key_ids(map_key: &str) -> Option<(EntityId, EntityId)> {
    let named = |hex: &str| EntityId::from_hex(hex).ok().filter(|id| id.to_hex() == hex);
    let mut segments = map_key.split('/');
    let message = named(segments.next()?)?;
    let citation = named(segments.next()?)?;
    let digest = segments.next()?;
    let digest_spelled = digest.len() == 32
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    (segments.next().is_none() && digest_spelled).then_some((message, citation))
}

/// The pin under `map_key`, joined from `map`'s parts when it rides in
/// them; `Ok(None)` while a part has not landed.
fn carried_pin(map: &LoroMap, map_key: &str, bytes: &[u8]) -> Result<Option<CitationPin>> {
    let (pin, message, citation) = match decode_carried(bytes)? {
        Carried::Whole(pin, message, citation) => (pin, message, citation),
        Carried::Parted(parted) => {
            let Some(whole) = join_parts(map, &parted.parts) else {
                return Ok(None);
            };
            let (mut pin, message, citation) = decode_pin(&whole)?;
            if pin.actor != DocActor::Erased {
                return Err(refused("a part names an actor"));
            }
            pin.actor = parted.actor;
            // A pin that fits in a part rides whole: one spelling per pin.
            if !rmp_serde::to_vec_named(&pin).is_ok_and(|bytes| bytes.len() > PART_BYTES) {
                return Err(refused("not a pin's parts"));
            }
            (pin, message, citation)
        }
    };
    if carrier_key(message, citation, &pin)? != map_key {
        return Err(refused("filed under another key"));
    }
    Ok(Some(pin))
}

/// Admits one insert into a window's `document_pins` map: a whole pin or a
/// pin's manifest of a base window, filed under its own key, or a part.
pub(crate) fn admit_document_pin_carrier(
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
    match decode_carried(bytes)? {
        Carried::Whole(pin, message, citation) => {
            if carrier_key(message, citation, &pin)? != map_key {
                return Err(refused("filed under another key"));
            }
        }
        // The digest is checked once the parts join.
        Carried::Parted(_) => {
            if key_ids(map_key).is_none() {
                return Err(refused("filed under another key"));
            }
        }
    }
    Ok(())
}

/// [`admit_document_pin_carrier`] over every row `map` holds.
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
/// window lacks, in parts when it is larger than one. A pin of a reply this
/// vault erased stays out. An erased pin here takes its live twin's place,
/// with `window` pinned history-free first, as the twin's bytes stay in its
/// history (FIX 4247). Each pin and part commits on its own. Returns whether
/// it wrote.
pub(crate) fn mirror_document_pins(
    vault: &Vault,
    doc: &LoroDoc,
    message: &EntityId,
    window: &WindowKey,
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
    let mut replaced = false;
    for pin in &pins {
        let bytes = rmp_serde::to_vec_named(pin).map_err(|_| refused("does not encode"))?;
        let Ok((_, message, citation)) = decode_pin(&bytes) else {
            tracing::warn!(
                message = %message.to_hex(),
                citation = %pin.citation,
                "document pin not carried: it is not whole"
            );
            continue;
        };
        let key = carrier_key(message, citation, pin)?;
        if let Some(held) = map_get_bytes(&map, &key) {
            if !replaces(&map, &key, &held, pin) {
                continue;
            }
            if !replaced {
                super::window::require_history_free_window(vault, window)?;
                replaced = true;
            }
        }
        write_carrier(doc, &map, &key, pin)?;
        wrote = true;
    }
    if replaced {
        // And the live twins' parts, which no pin lists now.
        for part in unreferenced_parts(&map, &listed_parts(&map)) {
            map_delete(&map, &part)?;
        }
        doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    }
    Ok(wrote)
}

/// The base windows a quote pin flush faults in (FIX 3462): the window of
/// each MESSAGE among `rows`, which a local write queued, that holds a pin,
/// by the message's learned month, where `loaded` holds none of it. A pin
/// rides only beside the message it quotes, so a quote of a message older
/// than every loaded window rode nowhere until that window opened.
pub(crate) fn cold_pin_windows(
    vault: &Vault,
    rows: &BTreeSet<EntityId>,
    loaded: &[WindowKey],
) -> Vec<WindowKey> {
    let Ok(rtxn) = vault.store.env.read_txn() else {
        return Vec::new();
    };
    let mut keys = Vec::new();
    for id in rows {
        let Some(raw) = vault.get_raw_in(&rtxn, id).ok().flatten() else {
            continue;
        };
        if crate::batch::EntityMetadataHeader::parse(&raw)
            .is_none_or(|header| header.entity_type != crate::registry::ENTITY_TYPE_MESSAGE)
        {
            continue;
        }
        let Ok(key) = super::residence::residence_window_for_blob(&raw) else {
            continue;
        };
        if key.world().is_none()
            && !loaded.contains(&key)
            && !keys.contains(&key)
            && vault
                .message_quote_pins_in_txn(&rtxn, id)
                .is_ok_and(|pins| !pins.is_empty())
        {
            keys.push(key);
        }
    }
    keys
}

/// Whether `pin`, held here, takes the place of `held`, the carrier the
/// window holds under its key: only an erased pin over its live twin
/// ([`CitationPin::erased_wins`]).
fn replaces(map: &LoroMap, map_key: &str, held: &[u8], pin: &CitationPin) -> bool {
    carried_pin(map, map_key, held)
        .ok()
        .flatten()
        .is_some_and(|twin| twin.erased_wins(pin).is_some_and(|stands| *stands != twin))
}

/// Writes `pin` under `map_key`, in parts when it is larger than one: the
/// parts of the pin naming no one, under a manifest that names its actor
/// (FIX 4789), so a pin and its erased twin share their parts. The pin and
/// each part commit on their own. Returns the parts it lists.
fn write_carrier(
    doc: &LoroDoc,
    map: &LoroMap,
    map_key: &str,
    pin: &CitationPin,
) -> Result<BTreeSet<String>> {
    let encode =
        |pin: &CitationPin| rmp_serde::to_vec_named(pin).map_err(|_| refused("does not encode"));
    let commit = || doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    let bytes = encode(pin)?;
    if bytes.len() <= PART_BYTES {
        map_insert_bytes(map, map_key, &bytes)?;
        commit();
        return Ok(BTreeSet::new());
    }
    let no_one = encode(&pin.actor_erased())?;
    let (parts, pieces) = split_parts(&no_one)?;
    let listed = parts.keys().collect();
    write_manifest(
        map,
        map_key,
        PartedPin {
            parts,
            actor: pin.actor,
        },
    )?;
    commit();
    write_parts(map, &pieces, commit)?;
    Ok(listed)
}

/// Writes a parted pin's manifest under `map_key`.
fn write_manifest(map: &LoroMap, map_key: &str, parted: PartedPin) -> Result<()> {
    let manifest = rmp_serde::to_vec_named(&parted).map_err(|_| refused("does not encode"))?;
    map_insert_bytes(map, map_key, &manifest)
}

/// Every part a pin key in `map` lists.
fn listed_parts(map: &LoroMap) -> BTreeSet<String> {
    let mut listed = BTreeSet::new();
    for (_, bytes) in pin_rows(map, |_, _| true) {
        if let Ok(Carried::Parted(parted)) = decode_carried(&bytes) {
            listed.extend(parted.parts.keys());
        }
    }
    listed
}

/// Merges every pin window `key`'s document carries into this vault's, as a
/// window open does. A pin that fails is logged and left; it never stops
/// the open.
pub(crate) fn apply_document_pin_map(vault: &Vault, doc: &LoroDoc, key: &WindowKey) {
    if key.world().is_some() || !holds_document_pin_map(doc) {
        return;
    }
    let map = doc.get_map(DOCUMENT_PINS_MAP);
    let rows = pin_rows(&map, |_, _| true);
    merge_pins(vault, &map, key.as_str(), rows);
}

/// Observer B for the document pin map: each pin an import brought, and
/// each pin one of whose parts it brought. A pin is written once, so a
/// dropped carrier takes nothing from this vault.
pub(crate) fn materialize_document_pins_from_delta(
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
    let map = doc.get_map(DOCUMENT_PINS_MAP);
    let rows = pin_rows(&map, |map_key, bytes| {
        updated.contains(map_key)
            || (part_landed
                && matches!(decode_carried(bytes), Ok(Carried::Parted(parted))
                    if parted.parts.keys().any(|part| updated.contains(&part))))
    });
    merge_pins(vault, &map, window_key, rows);
    Some(Vec::new())
}

/// Each pin key `map` holds that `keep` takes, with its value.
fn pin_rows(map: &LoroMap, keep: impl Fn(&str, &[u8]) -> bool) -> Vec<(String, Vec<u8>)> {
    let mut rows = Vec::new();
    map.for_each(|map_key, value| {
        if !is_part_key(map_key)
            && let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value
            && keep(map_key, &bytes)
        {
            rows.push((map_key.to_owned(), bytes.to_vec()));
        }
    });
    rows
}

/// Whether `doc` holds a document pin map. Looking a root up by name
/// creates it: look first.
fn holds_document_pin_map(doc: &LoroDoc) -> bool {
    matches!(doc.get_value(), LoroValue::Map(roots) if roots.contains_key(DOCUMENT_PINS_MAP))
}

/// Merges each carried pin into this vault's in one write. A pin whose
/// parts have not all landed waits for them.
fn merge_pins(vault: &Vault, map: &LoroMap, window: &str, rows: Vec<(String, Vec<u8>)>) {
    let mut carried = Vec::new();
    for (map_key, bytes) in rows {
        match carried_pin(map, &map_key, &bytes) {
            Ok(Some(pin)) => carried.push((map_key, pin)),
            Ok(None) => tracing::debug!(window, key = %map_key, "document pin waits for its parts"),
            Err(_) => tracing::warn!(window, key = %map_key, "document pin malformed; left out"),
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
/// each pin of a message the window no longer carries, with every part no
/// remaining pin lists: erase wins over a pin, and a pin never rides where
/// its message does not. A pin whose actor this vault erased, or whose
/// erased twin it holds, is rewritten naming no one (FIX 4247). A live doc
/// keeps the old pins in its history, so `history_free` names the window
/// pinned history-free before any row goes or changes, as
/// `room_facts::scrub_room_facts` does; the sweep, whose shallow cut drops
/// that history, passes `None`. Returns whether a row went or changed,
/// committed.
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
    for (map_key, bytes) in pin_rows(&map, |_, _| true) {
        if let Some((message, citation)) = key_ids(&map_key) {
            let parted = match decode_carried(&bytes) {
                Ok(Carried::Parted(parted)) => Some(parted),
                _ => None,
            };
            let pin = carried_pin(&map, &map_key, &bytes).ok().flatten();
            carried.push((map_key, message, citation, parted, pin));
        }
    }
    let entities = doc.get_map("entities");
    let mut gone = Vec::new();
    let mut erased = Vec::new();
    let mut renamed = Vec::new();
    let mut referenced = BTreeSet::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        for (map_key, message, citation, parted, pin) in carried {
            if !map_contains_binary(&entities, &message.to_hex())
                || crate::ports::removed_in_txn(&vault.store, &rtxn, &message)?
                || crate::ports::removed_in_txn(&vault.store, &rtxn, &citation)?
            {
                gone.push(map_key);
                continue;
            }
            if let Some(pin) = &pin
                && let Some(twin) = erased_twin(vault, &rtxn, &message, &citation, pin)?
            {
                erased.push((map_key, twin));
                continue;
            }
            let Some(parted) = parted else {
                continue;
            };
            referenced.extend(parted.parts.keys());
            // Its parts have not all landed, and they name no one: the
            // manifest alone names the actor (FIX 4789).
            if pin.is_none()
                && unjoined_actor_erased(vault, &rtxn, (&message, &citation), &map_key, &parted)?
            {
                renamed.push((
                    map_key,
                    PartedPin {
                        actor: DocActor::Erased,
                        ..parted
                    },
                ));
            }
        }
    }
    let mut stale = unreferenced_parts(&map, &referenced);
    if gone.is_empty() && erased.is_empty() && renamed.is_empty() && stale.is_empty() {
        return Ok(false);
    }
    if let Some(key) = history_free {
        super::window::require_history_free_window(vault, key)?;
    }
    // The erased twin rides under the live one's key.
    for (map_key, twin) in &erased {
        let listed = write_carrier(doc, &map, map_key, twin)?;
        stale.retain(|part| !listed.contains(part));
    }
    for (map_key, parted) in renamed {
        write_manifest(&map, &map_key, parted)?;
    }
    for map_key in gone.iter().chain(&stale) {
        map_delete(&map, map_key)?;
    }
    doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    Ok(true)
}

/// `carried`, a pin of `message` cited by `citation` the window holds,
/// naming no one, when this vault erased its actor or holds its erased twin
/// ([`CitationPin::erased_wins`]); `None` when it rides as it is.
fn erased_twin(
    vault: &Vault,
    txn: &RoTxn<'_>,
    message: &EntityId,
    citation: &EntityId,
    carried: &CitationPin,
) -> Result<Option<CitationPin>> {
    let mut here = carried.clone();
    here.actor = here.actor.erased_here(vault, txn)?;
    let held = vault.message_quote_pin_in_txn(txn, message, citation)?;
    let stands = match &held {
        Some(held) => held.erased_wins(&here).unwrap_or(&here),
        None => &here,
    };
    Ok((stands != carried).then(|| stands.clone()))
}

/// Whether the parted pin under `map_key`, of `message` cited by `citation`,
/// whose parts have not all landed, names an actor this vault erased, or
/// rides live where this vault holds its erased twin (FIX 4789). Only the
/// manifest is read: it names the actor.
fn unjoined_actor_erased(
    vault: &Vault,
    txn: &RoTxn<'_>,
    (message, citation): (&EntityId, &EntityId),
    map_key: &str,
    parted: &PartedPin,
) -> Result<bool> {
    if parted.actor == DocActor::Erased {
        return Ok(false);
    }
    if parted.actor.erased_here(vault, txn)? == DocActor::Erased {
        return Ok(true);
    }
    let Some(held) = vault.message_quote_pin_in_txn(txn, message, citation)? else {
        return Ok(false);
    };
    Ok(held.actor == DocActor::Erased && carrier_key(*message, *citation, &held)? == map_key)
}

/// The pin rows among `rows` a canonical snapshot keeps as the window holds
/// them: each but a pin this vault holds on a message whose document the
/// snapshot captures, in `documents`, and the parts only such pins list.
/// That pin rides in the document's history and takes fresh cursors as the
/// document is restored; the window's reverse pass then mirrors it again.
/// The live twin of a pin held erased goes with it; an erased twin of one
/// held live stays, as the document's copy names the actor (FIX 4247).
pub(crate) fn canonical_pin_rows(
    vault: &Vault,
    txn: &RoTxn<'_>,
    rows: BTreeMap<String, Vec<u8>>,
    documents: &BTreeSet<EntityId>,
) -> Result<Vec<(String, Vec<u8>)>> {
    let scratch = LoroDoc::new();
    let map = scratch.get_map(DOCUMENT_PINS_MAP);
    for (key, row) in &rows {
        if is_part_key(key) {
            map_insert_bytes(&map, key, row)?;
        }
    }
    let mut kept = BTreeSet::new();
    let mut referenced = BTreeSet::new();
    for (key, row) in &rows {
        if is_part_key(key) {
            continue;
        }
        if let Ok(Some(pin)) = carried_pin(&map, key, row)
            && let Some((message, citation)) = pin.carried_ids()
            && documents.contains(&message)
            && let Some(held) = vault.message_quote_pin_in_txn(txn, &message, &citation)?
            && held.erased_wins(&pin) == Some(&held)
        {
            continue;
        }
        if let Ok(Carried::Parted(parted)) = decode_carried(row) {
            referenced.extend(parted.parts.keys());
        }
        kept.insert(key.clone());
    }
    Ok(rows
        .into_iter()
        .filter(|(key, _)| kept.contains(key) || referenced.contains(key))
        .collect())
}
