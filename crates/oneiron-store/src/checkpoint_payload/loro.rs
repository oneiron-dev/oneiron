//! The one Loro history projection the document families share (KS-7, FIX
//! 6072): a group of Loro rows (a full snapshot, then its updates in replay
//! order) read as typed operation history, each actor the family's codec
//! finds split out, and the join that rebuilds the rows from that no-one
//! history and the actors that opened. A family codec ([`LoroActorCodec`])
//! knows its own actor carriers (a birth record, an authorship record, a
//! commit stamp) and their erased spelling; this module owns the walk over
//! every change and operation, the hole addresses, the content framing, the
//! rebuild and the proof. It names no family, no sync type and no vault.
//!
//! A row's content is a Loro export of its history with every actor in its
//! no-one form, the row's slice (a snapshot, or an update's exact operation
//! spans) and the address of each hole, never an actor id. The join fills
//! each opened actor back at its address, leaves every other hole erased,
//! imports the filled history into a fresh document and exports each row's
//! slice again: the same operations, ids, dependencies, timestamps, Lamport
//! values and messages, in a container Loro may encode anew (Engine R1). A
//! capture keeps a split only once its own all-open join gives back the
//! stored history ([`admit_round_trip`]); every join proves the history its
//! bytes carry is the filled one before anything is written. A shallow or
//! state-only document holds no history before its cut, so no projection
//! shows its actors: it stays under the vault-wide seal (Engine R3).

pub mod frame;
pub mod proof;

use std::collections::{BTreeMap, BTreeSet};

use ::loro::{
    ContainerID, EncodedBlobMode, ExportMode, Frontiers, ID, IdSpan, ImportBlobMetadata,
    JsonChange, JsonMapOp, JsonOp, JsonOpContent, JsonSchema, LoroDoc, LoroValue, VersionVector,
};

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// R3: a shallow or state-only document, whose history before its cut no
/// projection holds.
pub const SHALLOW: &str = "shallow document projection not supplied";

/// A group whose all-open join does not give back the stored history.
pub const NOT_PROVED: &str = "a Loro history its projection does not give back";

/// A snapshot whose state is not its history's head.
pub const STATE_NOT_HEAD: &str = "a Loro snapshot whose state is not its head";

/// The JSON history schema the locked Loro reads and writes.
pub const JSON_SCHEMA: u8 = 1;

/// A value with its actors taken out: its no-one form, and each actor with
/// the family's own path to it (`Birth.actor`), never an id.
pub struct SplitValue<T> {
    pub no_one: T,
    pub actors: Vec<(String, EntityId)>,
}

impl<T> SplitValue<T> {
    /// A value that names no one: it stays as it is.
    pub fn kept(value: T) -> Self {
        Self {
            no_one: value,
            actors: Vec::new(),
        }
    }
}

/// A codec's split of one value, or the carrier it cannot split losslessly.
pub type Split<T> = std::result::Result<SplitValue<T>, &'static str>;

/// A family's actor carriers in its Loro history. A split refuses (the
/// group stays under the vault-wide seal, its carrier named) on any message,
/// map value or operation the family cannot split losslessly; a fill refuses
/// a hole that is not one.
pub trait LoroActorCodec {
    /// The family's name in its content framing.
    const FAMILY: &'static str;

    /// One change message: its no-one form, and each actor it names.
    fn split_message(&self, message: &str) -> Split<String>;

    /// The no-one message `no_one` with `actor` back at `path`.
    fn fill_message(&self, no_one: &str, path: &str, actor: EntityId) -> Result<String>;

    /// One value a map insertion wrote under `key` in `container`.
    fn split_map_insert(
        &self,
        container: &ContainerID,
        key: &str,
        value: &LoroValue,
    ) -> Split<LoroValue>;

    /// The no-one value `no_one` with `actor` back at `path`.
    fn fill_map_insert(
        &self,
        container: &ContainerID,
        key: &str,
        no_one: &LoroValue,
        path: &str,
        actor: EntityId,
    ) -> Result<LoroValue>;

    /// Any other operation: `Ok` when it names no one and the family's
    /// schema holds it.
    fn keep_op(&self, op: &JsonOp) -> std::result::Result<(), &'static str>;
}

/// One actor out of a row: the field (its hole's address) it fills, and
/// the actor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Atom {
    pub field: String,
    pub actor: EntityId,
}

/// One row as a split leaves it: its no-one-form content and its actors.
pub struct SplitRow {
    pub content: Vec<u8>,
    pub atoms: Vec<Atom>,
}

/// One row of a group as its compartment opened: its content, and the
/// atoms whose actors opened.
pub struct OpenedRow<'r> {
    pub content: &'r [u8],
    pub atoms: Vec<Atom>,
}

/// What a join rebuilt: each row's bytes, the history each carries, and
/// the document those bytes read back as.
pub struct JoinedLoro {
    pub rows: Vec<Vec<u8>>,
    pub histories: Vec<Vec<JsonChange>>,
    pub doc: LoroDoc,
}

/// Which part of a document's history a row holds: a full snapshot, or an
/// update's exact operation spans, in (peer, counter) order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Slice {
    Snapshot,
    Updates(Vec<IdSpan>),
}

/// Where a hole sits: a change's message, or the value a map insertion
/// wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Site {
    Message,
    MapValue,
}

impl Site {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Message => "msg",
            Self::MapValue => "map",
        }
    }
}

/// A hole's address, as its actor part's field spells it: the site, the
/// operation (a message's change's first one, a map value's own one, never
/// a position in a list of operations) and the family's path inside it. It
/// names no actor.
pub fn address(site: Site, op: ID, path: &str) -> String {
    format!("{}/{}/{}/{path}", site.tag(), op.peer, op.counter)
}

/// The site, operation and path `field` names, when [`address`] spells it
/// exactly so.
pub fn parse_address(field: &str) -> Option<(Site, ID, &str)> {
    let mut parts = field.splitn(4, '/');
    let site = match parts.next()? {
        "msg" => Site::Message,
        "map" => Site::MapValue,
        _ => return None,
    };
    let peer: u64 = parts.next()?.parse().ok()?;
    let counter: i32 = parts.next()?.parse().ok()?;
    let path = parts.next()?;
    let op = ID::new(peer, counter);
    (!path.is_empty() && address(site, op, path) == field).then_some((site, op, path))
}

/// An update's slice: the spans its own metadata names.
pub fn update_slice(bytes: &[u8]) -> Option<Slice> {
    let meta = LoroDoc::decode_import_blob_meta(bytes, true).ok()?;
    if meta.mode == EncodedBlobMode::Updates {
        Some(Slice::Updates(spans_of(&meta)))
    } else {
        None
    }
}

/// The operation spans a blob holds, in (peer, counter) order.
fn spans_of(meta: &ImportBlobMetadata) -> Vec<IdSpan> {
    let mut spans: Vec<IdSpan> = meta
        .partial_end_vv
        .sub_iter(&meta.partial_start_vv)
        .collect();
    spans.sort_by_key(|span| (span.peer, span.counter.start));
    spans
}

/// The typed history `slice` names in `doc`: for a snapshot, everything
/// `doc` holds now; for an update, its spans.
pub fn history(doc: &LoroDoc, slice: &Slice) -> Vec<JsonChange> {
    match slice {
        Slice::Snapshot => {
            let start = VersionVector::default();
            let all = doc.export_json_updates_without_peer_compression(&start, &doc.oplog_vv());
            all.changes
        }
        Slice::Updates(spans) => spans
            .iter()
            .flat_map(|span| doc.export_json_in_id_span(*span))
            .collect(),
    }
}

/// Whether `bytes` is a blob of `slice`'s shape: a full snapshot, or an
/// update holding exactly its spans.
pub fn blob_holds(bytes: &[u8], slice: &Slice) -> bool {
    let Ok(meta) = LoroDoc::decode_import_blob_meta(bytes, true) else {
        return false;
    };
    match slice {
        Slice::Snapshot => meta.mode == EncodedBlobMode::Snapshot,
        Slice::Updates(spans) => meta.mode == EncodedBlobMode::Updates && spans_of(&meta) == *spans,
    }
}

/// Whether two blobs hold the same slice: mode, change count, starting
/// frontiers and spans.
pub fn same_blob(stored: &[u8], rebuilt: &[u8]) -> bool {
    match (
        LoroDoc::decode_import_blob_meta(stored, true),
        LoroDoc::decode_import_blob_meta(rebuilt, true),
    ) {
        (Ok(stored), Ok(rebuilt)) => {
            stored.mode == rebuilt.mode
                && stored.change_num == rebuilt.change_num
                && stored.start_frontiers == rebuilt.start_frontiers
                && spans_of(&stored) == spans_of(&rebuilt)
        }
        _ => false,
    }
}

/// `changes` with every actor `codec` finds taken out, and each actor at its
/// hole's address. Every message and map insertion is read; an operation
/// the family's schema does not hold refuses.
pub fn split_history<C: LoroActorCodec>(
    changes: &[JsonChange],
    codec: &C,
) -> std::result::Result<(Vec<JsonChange>, Vec<Atom>), &'static str> {
    let mut free = changes.to_vec();
    let mut atoms = Vec::new();
    for change in &mut free {
        let peer = change.id.peer;
        if let Some(message) = change.msg.as_mut() {
            let split = codec.split_message(message.as_str())?;
            for (path, actor) in split.actors {
                atoms.push(Atom {
                    field: address(Site::Message, change.id, &path),
                    actor,
                });
            }
            *message = split.no_one;
        }
        for op in &mut change.ops {
            if let JsonOpContent::Map(JsonMapOp::Insert { key, value }) = &mut op.content {
                let split = codec.split_map_insert(&op.container, key.as_str(), value)?;
                for (path, actor) in split.actors {
                    atoms.push(Atom {
                        field: address(Site::MapValue, ID::new(peer, op.counter), &path),
                        actor,
                    });
                }
                *value = split.no_one;
                continue;
            }
            codec.keep_op(op)?;
        }
    }
    let mut fields = BTreeSet::new();
    for atom in &atoms {
        if !fields.insert(atom.field.as_str()) {
            return Err(NOT_PROVED);
        }
    }
    Ok((free, atoms))
}

/// Whether `bytes` is a Loro update blob whose checksum holds.
pub fn is_update(bytes: &[u8]) -> bool {
    LoroDoc::decode_import_blob_meta(bytes, true)
        .is_ok_and(|meta| meta.mode == EncodedBlobMode::Updates)
}
