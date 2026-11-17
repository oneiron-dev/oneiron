//! Doors for `tests/sync_discard_whole_row_binding.rs` (FIX
//! SYNC-DISCARD-KEEPS-UNBOUND-WHOLE-ROW; Engine RULING UC10-PR1-PREMISE =
//! A, 15 Nov 17:45): a window document holding one whole row of a window
//! map under one row's key while its body names another, for the BASE-window
//! discard projection (`sync_parted_row_binding::discard_projection`).
//! Compiled only under `--cfg oneiron_test_support`; never API.

use std::collections::{BTreeMap, BTreeSet};

use loro::cursor::Side;
use loro::{ExportMode, LoroDoc};

use crate::entity_doc::{CitationPin, DocActor, TextAnchor};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::room_codec::document_pins::carrier_key;
use crate::sync::document_pins::DOCUMENT_PINS_MAP;
use crate::sync::loro_support::map_insert_bytes;
use crate::sync::room_facts::ROOM_FACTS_MAP;
use crate::sync::room_turns::ROOM_TURNS_MAP;
use crate::sync::turn_programs::{TURN_PROGRAM_ARMS_MAP, TURN_PROGRAM_WAKES_MAP};
use crate::workspace_roster::{RoomClaimReceipt, RoomSideRow, RoomTurn};

/// A window map that carries a row whole, filed under a key the row's own
/// body spells.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WholeMap {
    /// A document pin: its key spells the quoted message, the citing
    /// record and a digest of the pin; its holder is the citing record.
    DocumentPin,
    /// A room turn row: its key and holder are the turn.
    RoomTurn,
    /// A room side row (a turn's claim): its key spells the turn it rides
    /// with, its holder, and a digest of the row.
    RoomSideRow,
    /// A turn program's disarmed arming row: its key is the registration,
    /// its holder the actor.
    TurnProgramArming,
    /// A turn program's decided wake: its key is the turn then the
    /// registration, and it is held while the turn is.
    TurnProgramWake,
}

/// Each map, in a fixed order.
pub const WHOLE_MAPS: [WholeMap; 5] = [
    WholeMap::DocumentPin,
    WholeMap::RoomTurn,
    WholeMap::RoomSideRow,
    WholeMap::TurnProgramArming,
    WholeMap::TurnProgramWake,
];

/// The actor every fixture arming row names: a correct arming row goes
/// with it.
#[must_use]
pub fn arming_actor() -> EntityId {
    fixed(0x41)
}

fn refused(reason: &str) -> Error {
    Error::InvalidConfig(format!("whole row door: {reason}"))
}

/// The snapshot of a window document holding one whole row of `map` under
/// the key of the row `keyed`, its body naming the row `body`. `keyed ==
/// body` writes a correct row.
///
/// # Errors
/// A fixture row that does not encode.
pub fn whole_window(map: WholeMap, keyed: EntityId, body: EntityId) -> Result<Vec<u8>> {
    let doc = LoroDoc::new();
    match map {
        WholeMap::DocumentPin => {
            let text = quoted()?;
            let key = carrier_key(fixed(0x4d), keyed, &pin(keyed, &text)?)?;
            let value = rmp_serde::to_vec_named(&pin(body, &text)?)
                .map_err(|_| refused("a pin that does not encode"))?;
            map_insert_bytes(&doc.get_map(DOCUMENT_PINS_MAP), &key, &value)?;
        }
        WholeMap::RoomTurn => {
            let value = serde_json::to_vec(&turn(body))
                .map_err(|_| refused("a turn row that does not encode"))?;
            map_insert_bytes(&doc.get_map(ROOM_TURNS_MAP), &keyed.to_hex(), &value)?;
        }
        WholeMap::RoomSideRow => {
            let encode = |turn: EntityId| {
                serde_json::to_vec(&claim(turn))
                    .map_err(|_| refused("a side row that does not encode"))
            };
            let key = crate::sync::room_facts::carrier_key(&claim(keyed), &encode(keyed)?);
            map_insert_bytes(&doc.get_map(ROOM_FACTS_MAP), &key, &encode(body)?)?;
        }
        WholeMap::TurnProgramArming => {
            let id = |id: EntityId| {
                serde_json::to_value(id).map_err(|_| refused("an id that does not encode"))
            };
            let value = serde_json::to_vec(&serde_json::json!({
                "disarmed": {
                    "actor": id(arming_actor())?,
                    "registration": id(body)?,
                    "at": 1,
                },
            }))
            .map_err(|_| refused("an arming row that does not encode"))?;
            map_insert_bytes(&doc.get_map(TURN_PROGRAM_ARMS_MAP), &keyed.to_hex(), &value)?;
        }
        WholeMap::TurnProgramWake => {
            let id = |id: EntityId| {
                serde_json::to_value(id).map_err(|_| refused("an id that does not encode"))
            };
            let registration = fixed(0x47);
            let admission = [0_u8; 32];
            let value = serde_json::to_vec(&serde_json::json!({
                "admitted": {
                    "turn": id(body)?,
                    "registration": id(registration)?,
                    "admission": admission,
                },
            }))
            .map_err(|_| refused("a wake row that does not encode"))?;
            let key = format!("{}{}", keyed.to_hex(), registration.to_hex());
            map_insert_bytes(&doc.get_map(TURN_PROGRAM_WAKES_MAP), &key, &value)?;
        }
    }
    doc.commit();
    snapshot(&doc)
}

/// The snapshot of a window document holding, under the turn key of
/// `keyed`, bytes that read as no turn row: they prove no other row.
///
/// # Errors
/// A window that does not export.
pub fn turn_window_of_no_row(keyed: EntityId) -> Result<Vec<u8>> {
    let doc = LoroDoc::new();
    map_insert_bytes(
        &doc.get_map(ROOM_TURNS_MAP),
        &keyed.to_hex(),
        b"not a turn row",
    )?;
    doc.commit();
    snapshot(&doc)
}

/// `doc`'s snapshot.
fn snapshot(doc: &LoroDoc) -> Result<Vec<u8>> {
    doc.export(ExportMode::Snapshot)
        .map_err(|_| refused("a window that does not export"))
}

/// A fixed id standing for every row the fixtures name besides the two the
/// test gives: a room, a quoted message, a document, an actor.
fn fixed(byte: u8) -> EntityId {
    EntityId::from_bytes_unchecked([byte; 16])
}

/// The frontier and cursors of one quoted text, so two pins built from one
/// `Quoted` differ only in their citing record.
struct Quoted {
    frontier: Vec<u8>,
    start: Vec<u8>,
    end: Vec<u8>,
}

fn quoted() -> Result<Quoted> {
    let text = LoroDoc::new();
    let body = text.get_text("body");
    body.insert(0, "quoted")
        .map_err(|_| refused("a quoted text that does not write"))?;
    text.commit();
    let cursor = |at: usize, side: Side| {
        body.get_cursor(at, side)
            .map(|cursor| cursor.encode())
            .ok_or_else(|| refused("a quote cursor"))
    };
    Ok(Quoted {
        frontier: text.oplog_frontiers().encode(),
        start: cursor(0, Side::Right)?,
        end: cursor(1, Side::Left)?,
    })
}

/// A whole pin of the quoted message by `citation`, naming no actor.
fn pin(citation: EntityId, quoted: &Quoted) -> Result<CitationPin> {
    let quote = "q";
    let message = fixed(0x4d).to_hex();
    let pin: CitationPin = serde_json::from_value(serde_json::json!({
        "citation": citation.to_hex(),
        "entity": message,
        "document": fixed(0x44).to_hex(),
        "anchor": {
            "entity": message,
            "frontier": quoted.frontier,
            "start": quoted.start,
            "end": quoted.end,
            "hash": TextAnchor::quote_hash(quote),
            "quote": quote,
        },
        "actor": serde_json::to_value(DocActor::Erased)
            .map_err(|_| refused("an actor that does not encode"))?,
    }))
    .map_err(|error| refused(&format!("a pin that does not decode: {error}")))?;
    if pin.carried_ids().is_none() {
        return Err(refused("a pin that is not whole"));
    }
    Ok(pin)
}

/// A whole turn row of `turn`.
fn turn(turn: EntityId) -> RoomTurn {
    RoomTurn {
        turn_id: turn.to_hex(),
        room_id: fixed(0x52).to_hex(),
        actor: fixed(0x41).to_hex(),
        addressed_agents: BTreeSet::new(),
        message_ids: Vec::new(),
        reply_to: None,
        thread_of: None,
        at: 1,
        task_ids: Vec::new(),
        converted_project: None,
        quotes: BTreeMap::new(),
    }
}

/// A whole claim of `turn`.
fn claim(turn: EntityId) -> RoomSideRow {
    RoomSideRow::Claim {
        claim: RoomClaimReceipt {
            room_id: fixed(0x52).to_hex(),
            turn_id: turn.to_hex(),
            actor: fixed(0x41).to_hex(),
            receipt_ref: "r".to_owned(),
            at: 1,
        },
    }
}
