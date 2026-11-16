//! Doors for `tests/sync_parted_row_binding.rs` (UC-10 PR 1; Engine RULING
//! UC10-PR1-PREMISE = A, 15 Nov 17:45): a window document holding one row
//! of a parted map in parts, its manifest under one row's key and its parts
//! joining to another's, then the BASE-window discard projection and the
//! checkpoint capture over it. Compiled only under
//! `--cfg oneiron_test_support`; never API.

use std::collections::BTreeSet;

use loro::cursor::Side;
use loro::{ExportMode, LoroDoc, LoroMap};
use serde::Serialize;

use crate::entity_doc::{CitationPin, DocActor, TextAnchor};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::origin::{REPO_MANIFEST_VERSION, RepoManifest, RepoPortableId};
use crate::room_codec::document_pins::{PartedPin, carrier_key};
use crate::side_table::WINDOW_SNAPSHOT;
use crate::store::checkpoint_payload::rows::OwnerRef;
use crate::sync::carrier_parts::{PART_BYTES, Parts, split_parts};
use crate::sync::checkpoint_payload::{
    AtomHome, AtomRef, CapturedSyncRow, CapturedSyncRows, KindPlacement, Placement, SkeletonRow,
    SyncAtom, SyncCarrier, SyncPayloadOwners, project_checkpoint_windows, root_entry,
};
use crate::sync::document_pins::DOCUMENT_PINS_MAP;
use crate::sync::loro_support::{doc_from_snapshot, map_get_bytes, map_insert_bytes};
use crate::sync::repo_manifests::REPO_MANIFESTS_MAP;
use crate::sync::room_facts::ROOM_FACTS_MAP;
use crate::sync::room_parts::{ROOM_FACT_MAX_ROW_BYTES, ROOM_TURN_MAX_ROW_BYTES, write_row};
use crate::sync::room_turns::ROOM_TURNS_MAP;
use crate::sync::turn_programs::TURN_PROGRAM_ARMS_MAP;
use crate::sync::window::{Projected, project_window_doc};
use crate::workspace_roster::{RoomClaimReceipt, RoomSideRow, RoomTurn};

/// A window map that carries a row past its bound in parts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartedMap {
    /// A repo head: its key is a portable id, its holder the head's CODE
    /// entity, and its joined manifest names a CODE entity again.
    RepoHead,
    /// A document pin: its holder is the citing record, its joined pin
    /// names one.
    DocumentPin,
    /// A room turn row: its key and holder are the turn, its joined row
    /// names one.
    RoomTurn,
    /// A room side row (a turn's claim): its key names the turn it rides
    /// with, its holder; its joined row names one.
    RoomSideRow,
}

/// Each map, in a fixed order.
pub const PARTED_MAPS: [PartedMap; 4] = [
    PartedMap::RepoHead,
    PartedMap::DocumentPin,
    PartedMap::RoomTurn,
    PartedMap::RoomSideRow,
];

fn refused(reason: &str) -> Error {
    Error::InvalidConfig(format!("parted row door: {reason}"))
}

/// The snapshot of a window document holding one row of `map` in parts:
/// its manifest under the key of the row `keyed` holds, its parts joining
/// to the row `body` holds. `keyed == body` writes a correct row.
///
/// # Errors
/// A fixture row that does not encode.
pub fn parted_window(map: PartedMap, keyed: EntityId, body: EntityId) -> Result<Vec<u8>> {
    let doc = LoroDoc::new();
    match map {
        PartedMap::RepoHead => {
            repo_head(&doc.get_map(REPO_MANIFESTS_MAP), keyed, body)?;
        }
        PartedMap::DocumentPin => {
            document_pin(
                &doc.get_map(DOCUMENT_PINS_MAP),
                keyed,
                body,
                PART_BYTES + 1024,
            )?;
        }
        PartedMap::RoomTurn => {
            let row = serde_json::to_vec(&turn(body))
                .map_err(|_| refused("a turn row that does not encode"))?;
            write_row(
                &doc.get_map(ROOM_TURNS_MAP),
                &keyed.to_hex(),
                &row,
                ROOM_TURN_MAX_ROW_BYTES,
            )?;
        }
        PartedMap::RoomSideRow => {
            let encode = |turn: EntityId| {
                serde_json::to_vec(&claim(turn))
                    .map_err(|_| refused("a side row that does not encode"))
            };
            let key = claim_key(keyed, &encode(keyed)?);
            write_row(
                &doc.get_map(ROOM_FACTS_MAP),
                &key,
                &encode(body)?,
                ROOM_FACT_MAX_ROW_BYTES,
            )?;
        }
    }
    doc.commit();
    snapshot(&doc)
}

/// The snapshot of a window document holding, in `map`'s own spelling
/// under the key of the row `keyed` holds, a manifest whose parts all join
/// to bytes that read as no row of the map (Astra F3, UC-10 PR 1).
///
/// # Errors
/// A fixture row that does not encode.
pub fn parted_window_of_no_row(map: PartedMap, keyed: EntityId) -> Result<Vec<u8>> {
    let doc = LoroDoc::new();
    match map {
        PartedMap::RepoHead => {
            let heads = doc.get_map(REPO_MANIFESTS_MAP);
            let no_manifest = [0_u8; 64];
            let (parts, pieces) = split_parts(&no_manifest)?;
            head_with_parts(&heads, keyed, &parts)?;
            for (key, piece) in pieces {
                map_insert_bytes(&heads, &key, piece)?;
            }
        }
        PartedMap::DocumentPin => {
            let pins = doc.get_map(DOCUMENT_PINS_MAP);
            let no_pin = vec![0_u8; PART_BYTES + 1];
            let (parts, pieces) = split_parts(&no_pin)?;
            pin_manifest(&pins, keyed, parts)?;
            for (key, piece) in pieces {
                map_insert_bytes(&pins, &key, piece)?;
            }
        }
        PartedMap::RoomTurn => write_row(
            &doc.get_map(ROOM_TURNS_MAP),
            &keyed.to_hex(),
            &vec![0_u8; ROOM_TURN_MAX_ROW_BYTES + 1],
            ROOM_TURN_MAX_ROW_BYTES,
        )?,
        PartedMap::RoomSideRow => {
            let no_row = vec![0_u8; ROOM_FACT_MAX_ROW_BYTES + 1];
            write_row(
                &doc.get_map(ROOM_FACTS_MAP),
                &claim_key(keyed, &no_row),
                &no_row,
                ROOM_FACT_MAX_ROW_BYTES,
            )?;
        }
    }
    doc.commit();
    snapshot(&doc)
}

/// The snapshot of a window document holding `row`'s repo head in parts,
/// and under the key of `pin_holder`'s pin a pin manifest listing the same
/// parts, none of which the pin map holds (Astra F1, UC-10 PR 1).
///
/// # Errors
/// A fixture row that does not encode.
pub fn repo_parts_listed_by_a_pin(row: EntityId, pin_holder: EntityId) -> Result<Vec<u8>> {
    let doc = LoroDoc::new();
    let parts = repo_head(&doc.get_map(REPO_MANIFESTS_MAP), row, row)?;
    pin_manifest(&doc.get_map(DOCUMENT_PINS_MAP), pin_holder, parts)?;
    doc.commit();
    snapshot(&doc)
}

/// The snapshot of a window document whose history writes, in this order,
/// a turn manifest under `keyed`'s key whose parts join to `body`'s turn,
/// a value in a root outside the window's maps, then the parts (Astra F2,
/// UC-10 PR 1): a capture pass stops at that root before it meets a part.
///
/// # Errors
/// A fixture row that does not encode.
pub fn parted_turn_behind_an_unlisted_root(keyed: EntityId, body: EntityId) -> Result<Vec<u8>> {
    let row =
        serde_json::to_vec(&turn(body)).map_err(|_| refused("a turn row that does not encode"))?;
    let key = keyed.to_hex();
    let written = LoroDoc::new();
    let written_turns = written.get_map(ROOM_TURNS_MAP);
    write_row(&written_turns, &key, &row, ROOM_TURN_MAX_ROW_BYTES)?;
    let bytes = |key: &str| {
        map_get_bytes(&written_turns, key)
            .ok_or_else(|| refused("a turn map value that is not bytes"))
    };
    let mut parts = Vec::new();
    written_turns.for_each(|part, _| {
        if part != key {
            parts.push(part.to_owned());
        }
    });
    let doc = LoroDoc::new();
    let turns = doc.get_map(ROOM_TURNS_MAP);
    map_insert_bytes(&turns, &key, &bytes(&key)?)?;
    doc.commit();
    map_insert_bytes(&doc.get_map("unlisted_root"), "row", b"value")?;
    doc.commit();
    for part in &parts {
        map_insert_bytes(&turns, part, &bytes(part)?)?;
    }
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

/// A repo head (CarriedHead's spelling): the CODE entity and its parts.
#[derive(Serialize)]
struct Head<'a> {
    code: EntityId,
    body: &'a Parts,
}

/// The portable id every fixture head is filed under.
fn portable() -> Result<RepoPortableId> {
    RepoPortableId::from_hex(&"07".repeat(32))
        .ok_or_else(|| refused("a portable id that does not parse"))
}

/// A repo head of `keyed`'s CODE entity whose parts join to `body`'s
/// manifest, and its parts. Returns the parts the head lists.
fn repo_head(map: &LoroMap, keyed: EntityId, body: EntityId) -> Result<Parts> {
    let portable = portable()?;
    let manifest = RepoManifest {
        portable,
        version: REPO_MANIFEST_VERSION,
        code: body,
        minted_at: 1,
        origin_name: None,
        visible_refs: Vec::new(),
        lfs_pointers: Vec::new(),
        epoch: 0,
        updated_at: 1,
        writer: None,
    }
    .encode()?;
    let (parts, pieces) = split_parts(&manifest)?;
    head_with_parts(map, keyed, &parts)?;
    for (key, piece) in pieces {
        map_insert_bytes(map, &key, piece)?;
    }
    Ok(parts)
}

/// A repo head of `code`'s CODE entity listing `parts`, under the fixture
/// portable id.
fn head_with_parts(map: &LoroMap, code: EntityId, parts: &Parts) -> Result<()> {
    let head = rmp_serde::to_vec_named(&Head { code, body: parts })
        .map_err(|_| refused("a head that does not encode"))?;
    map_insert_bytes(map, &portable()?.to_hex(), &head)
}

/// The quoted text a pin anchors in, written once. A fresh Loro document has
/// a fresh peer, so every pin a fixture builds from one `Quoted` shares its
/// frontier and cursors, and two pins differ only in what the fixture changes.
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

/// A whole pin of the quoted message by `citation`, its quote `quote_len`
/// bytes, naming no actor.
fn pin(citation: EntityId, quoted: &Quoted, quote_len: usize) -> Result<CitationPin> {
    let quote = "q".repeat(quote_len);
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
            "hash": TextAnchor::quote_hash(&quote),
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

/// A pin manifest under the key of `keyed`'s pin, its parts joining to
/// `body`'s; both pins quote `quote_len` bytes of one quoted text.
fn document_pin(map: &LoroMap, keyed: EntityId, body: EntityId, quote_len: usize) -> Result<()> {
    let text = quoted()?;
    let key = carrier_key(fixed(0x4d), keyed, &pin(keyed, &text, quote_len)?)?;
    let joined = rmp_serde::to_vec_named(&pin(body, &text, quote_len)?)
        .map_err(|_| refused("a pin that does not encode"))?;
    let (parts, pieces) = split_parts(&joined)?;
    pin_manifest_under(map, &key, parts)?;
    for (key, piece) in pieces {
        map_insert_bytes(map, &key, piece)?;
    }
    Ok(())
}

/// A pin manifest listing `parts` under the key of `keyed`'s pin, writing
/// no part.
fn pin_manifest(map: &LoroMap, keyed: EntityId, parts: Parts) -> Result<()> {
    let key = carrier_key(fixed(0x4d), keyed, &pin(keyed, &quoted()?, 64)?)?;
    pin_manifest_under(map, &key, parts)
}

/// A pin manifest listing `parts`, naming no actor, under `key`.
fn pin_manifest_under(map: &LoroMap, key: &str, parts: Parts) -> Result<()> {
    let manifest = rmp_serde::to_vec_named(&PartedPin {
        parts,
        actor: DocActor::Erased,
    })
    .map_err(|_| refused("a pin manifest that does not encode"))?;
    map_insert_bytes(map, key, &manifest)
}

/// The snapshot of a window document holding `row`'s pin in parts under its
/// own key, though the joined pin fits in one part: the spelling an actor
/// scrub leaves when erasing a parted pin's actor brings it under a part's
/// size. The pin codec refuses that spelling; it is still `row`'s pin.
///
/// # Errors
/// A fixture row that does not encode.
pub fn parted_pin_fitting_one_part(row: EntityId) -> Result<Vec<u8>> {
    let doc = LoroDoc::new();
    document_pin(&doc.get_map(DOCUMENT_PINS_MAP), row, row, 64)?;
    doc.commit();
    snapshot(&doc)
}

/// A turn row of `turn`, past its whole-row bound.
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
        converted_project: Some("p".repeat(ROOM_TURN_MAX_ROW_BYTES + 1024)),
        quotes: std::collections::BTreeMap::new(),
    }
}

/// A claim of `turn`, past a side row's whole-row bound.
fn claim(turn: EntityId) -> RoomSideRow {
    RoomSideRow::Claim {
        claim: RoomClaimReceipt {
            room_id: fixed(0x52).to_hex(),
            turn_id: turn.to_hex(),
            actor: fixed(0x41).to_hex(),
            receipt_ref: "r".repeat(ROOM_FACT_MAX_ROW_BYTES + 1024),
            at: 1,
        },
    }
}

/// The key a claim of `turn` encoded as `bytes` rides under: the side row
/// codec's own (`sync::room_facts::carrier_key`).
fn claim_key(turn: EntityId, bytes: &[u8]) -> String {
    crate::sync::room_facts::carrier_key(&claim(turn), bytes)
}

/// What the BASE-window discard projection does with the window `snapshot`
/// when the rows `discarded` go: `unchanged`, `erased <n>`, or
/// `deferred: <why>`.
///
/// # Errors
/// A snapshot that does not open, or the projection's own error.
pub fn discard_projection(snapshot: &[u8], discarded: &[EntityId]) -> Result<String> {
    let doc = doc_from_snapshot(snapshot)?;
    let discarded: BTreeSet<EntityId> = discarded.iter().copied().collect();
    Ok(match project_window_doc(&doc, &discarded, None)? {
        Projected::Unchanged => "unchanged".to_owned(),
        Projected::Joined { erased, .. } => format!("erased {erased}"),
        Projected::Deferred(why) => format!("deferred: {why}"),
    })
}

/// Why a checkpoint capture keeps a window whole: the owner it names, and
/// its reason as the receipt's family names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureRefusal {
    /// The owner hint, when the capture names one.
    pub owner: Option<EntityId>,
    /// The reason, as `SyncUnclassified`'s debug form spells it.
    pub reason: String,
}

/// Every entity kind its own row's.
struct EveryKindOwned;

impl SyncPayloadOwners for EveryKindOwned {
    fn entity_kind(&self, _: u8) -> KindPlacement {
        KindPlacement::Owner
    }
}

/// Why a checkpoint capture keeps the window `snapshot` whole; `None` when
/// it splits.
///
/// # Errors
/// The capture's own error.
pub fn checkpoint_refusal(snapshot: &[u8]) -> Result<Option<CaptureRefusal>> {
    let key = [WINDOW_SNAPSHOT.prefix, b"parted-row-door"].concat();
    let rows = CapturedSyncRows::new(vec![CapturedSyncRow {
        carrier: SyncCarrier::WindowSnapshot,
        key: &key,
        value: snapshot,
    }]);
    let mut copies = 0_u32;
    let mut emit = |_: AtomHome, _: SyncAtom| -> Result<AtomRef> {
        copies += 1;
        Ok(AtomRef(copies))
    };
    let projection = project_checkpoint_windows(&rows, &EveryKindOwned, &mut emit)?;
    Ok(projection
        .unclassified
        .into_iter()
        .find_map(|row| match row {
            SkeletonRow::Unclassified { owner, reason, .. } => Some(CaptureRefusal {
                owner: owner.map(entity_of),
                reason: format!("{reason:?}"),
            }),
            _ => None,
        }))
}

/// The one holder a checkpoint files a turn program's arming row under: a
/// disarmed row of `actor` for `registration`, filed under the key of the
/// registration `keyed` (the D5 guard: a turn program row is placed by its
/// body, whatever its key). `None` for any other placement.
///
/// # Errors
/// A fixture row that does not encode.
pub fn turn_program_arming_holder(
    keyed: EntityId,
    registration: EntityId,
    actor: EntityId,
) -> Result<Option<EntityId>> {
    let id =
        |id: EntityId| serde_json::to_value(id).map_err(|_| refused("an id that does not encode"));
    let row = serde_json::to_vec(&serde_json::json!({
        "disarmed": {
            "actor": id(actor)?,
            "registration": id(registration)?,
            "at": 1,
        },
    }))
    .map_err(|_| refused("an arming row that does not encode"))?;
    Ok(
        match root_entry(
            TURN_PROGRAM_ARMS_MAP,
            &keyed.to_hex(),
            &row,
            &EveryKindOwned,
        ) {
            Placement::Owned(holders) => match holders.as_slice() {
                [holder] => Some(entity_of(holder.owner)),
                _ => None,
            },
            _ => None,
        },
    )
}

/// The entity an entity tree owner names.
fn entity_of(owner: OwnerRef) -> EntityId {
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&owner.owner32[..16]);
    EntityId::from_bytes_unchecked(bytes)
}
