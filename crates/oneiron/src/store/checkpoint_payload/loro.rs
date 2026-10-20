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

mod frame;
mod proof;

use std::collections::{BTreeMap, BTreeSet};

use ::loro::{
    ContainerID, EncodedBlobMode, ExportMode, Frontiers, ID, IdSpan, ImportBlobMetadata,
    JsonChange, JsonMapOp, JsonOp, JsonOpContent, JsonSchema, LoroDoc, LoroValue, VersionVector,
};

use self::frame::{read_frame, write_frame};
pub(crate) use self::proof::prove_loro_equivalent;
use super::corrupt;
use super::rows::{
    ActorPart, Captured, OwnerRef, RoundTripPolicy, RowLocator, RowPart, Unresolved,
    admit_round_trip,
};
use crate::entity_id::EntityId;
use crate::error::Result;

/// R3: a shallow or state-only document, whose history before its cut no
/// projection holds.
pub(crate) const SHALLOW: &str = "shallow document projection not supplied";

/// A group whose all-open join does not give back the stored history.
pub(crate) const NOT_PROVED: &str = "a Loro history its projection does not give back";

/// A snapshot whose state is not its history's head.
const STATE_NOT_HEAD: &str = "a Loro snapshot whose state is not its head";

/// The JSON history schema the locked Loro reads and writes.
const JSON_SCHEMA: u8 = 1;

/// A value with its actors taken out: its no-one form, and each actor with
/// the family's own path to it (`Birth.actor`), never an id.
pub(crate) struct SplitValue<T> {
    pub(crate) no_one: T,
    pub(crate) actors: Vec<(String, EntityId)>,
}

impl<T> SplitValue<T> {
    /// A value that names no one: it stays as it is.
    pub(crate) fn kept(value: T) -> Self {
        Self {
            no_one: value,
            actors: Vec::new(),
        }
    }
}

/// A codec's split of one value, or the carrier it cannot split losslessly.
pub(crate) type Split<T> = std::result::Result<SplitValue<T>, &'static str>;

/// A family's actor carriers in its Loro history. A split refuses (the
/// group stays under the vault-wide seal, its carrier named) on any message,
/// map value or operation the family cannot split losslessly; a fill refuses
/// a hole that is not one.
pub(crate) trait LoroActorCodec {
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
pub(crate) struct Atom {
    pub(crate) field: String,
    pub(crate) actor: EntityId,
}

/// One row as a split leaves it: its no-one-form content and its actors.
pub(crate) struct SplitRow {
    pub(crate) content: Vec<u8>,
    pub(crate) atoms: Vec<Atom>,
}

/// One row of a group as its compartment opened: its content, and the
/// atoms whose actors opened.
pub(crate) struct OpenedRow<'r> {
    pub(crate) content: &'r [u8],
    pub(crate) atoms: Vec<Atom>,
}

/// What a join rebuilt: each row's bytes, the history each carries, and
/// the document those bytes read back as.
pub(crate) struct JoinedLoro {
    pub(crate) rows: Vec<Vec<u8>>,
    histories: Vec<Vec<JsonChange>>,
    doc: LoroDoc,
}

/// Which part of a document's history a row holds: a full snapshot, or an
/// update's exact operation spans, in (peer, counter) order.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Slice {
    Snapshot,
    Updates(Vec<IdSpan>),
}

/// Where a hole sits: a change's message, or the value a map insertion
/// wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Site {
    Message,
    MapValue,
}

impl Site {
    const fn tag(self) -> &'static str {
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
fn address(site: Site, op: ID, path: &str) -> String {
    format!("{}/{}/{}/{path}", site.tag(), op.peer, op.counter)
}

/// The site, operation and path `field` names, when [`address`] spells it
/// exactly so.
fn parse_address(field: &str) -> Option<(Site, ID, &str)> {
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

/// Splits one document group, a full snapshot then its updates in replay
/// order, through `codec`: each row's content and actors, in the group's
/// order. Every change's message and every map insertion of every row is
/// read, not only the values that stand now. The split stands only once
/// its all-open join gives each stored row back under `policy`, and the
/// rebuilt document's state is the stored one; otherwise the whole group
/// stays under the vault-wide seal with the reason it gives.
pub(crate) fn split_loro<C: LoroActorCodec>(
    rows: &[&[u8]],
    codec: &C,
    policy: RoundTripPolicy,
) -> std::result::Result<Vec<SplitRow>, Unresolved> {
    let (snapshot, updates) = rows.split_first().ok_or(Unresolved::Undecodable)?;
    let source = LoroDoc::new();
    import_snapshot(&source, snapshot)?;
    let mut slices = vec![Slice::Snapshot];
    let mut stored = vec![history(&source, &Slice::Snapshot)];
    for update in updates {
        let slice = update_slice(update).ok_or(Unresolved::Undecodable)?;
        import_blob(&source, update).map_err(undecodable)?;
        stored.push(history(&source, &slice));
        slices.push(slice);
    }
    let mut free = Vec::with_capacity(stored.len());
    let mut atoms = Vec::with_capacity(stored.len());
    for changes in &stored {
        let (changes, row_atoms) = split_history(changes, codec).map_err(carrier)?;
        free.push(changes);
        atoms.push(row_atoms);
    }
    let contents = no_one_contents::<C>(&slices, &free, &atoms);
    let contents = contents.map_err(not_proved)?;
    let opened: Vec<OpenedRow<'_>> = contents
        .iter()
        .zip(&atoms)
        .map(|(content, row_atoms)| OpenedRow {
            content: content.as_slice(),
            atoms: row_atoms.clone(),
        })
        .collect();
    let joined = join_loro(&opened, codec).map_err(not_proved)?;
    let proved = prove_split(rows, &stored, &joined, policy);
    proved.map_err(not_proved)?;
    if source.oplog_frontiers() != joined.doc.oplog_frontiers()
        || source.get_deep_value() != joined.doc.get_deep_value()
    {
        return Err(Unresolved::ActorSplit(NOT_PROVED));
    }
    Ok(contents
        .into_iter()
        .zip(atoms)
        .map(|(content, atoms)| SplitRow { content, atoms })
        .collect())
}

fn undecodable<E>(_: E) -> Unresolved {
    Unresolved::Undecodable
}

fn carrier(reason: &'static str) -> Unresolved {
    Unresolved::ActorSplit(reason)
}

fn not_proved<E>(_: E) -> Unresolved {
    Unresolved::ActorSplit(NOT_PROVED)
}

/// The stored snapshot `bytes` in the empty `doc`: a full one whose state is
/// its head.
fn import_snapshot(doc: &LoroDoc, bytes: &[u8]) -> std::result::Result<(), Unresolved> {
    let meta = LoroDoc::decode_import_blob_meta(bytes, true);
    let meta = meta.map_err(undecodable)?;
    match meta.mode {
        EncodedBlobMode::ShallowSnapshot => return Err(Unresolved::ActorSplit(SHALLOW)),
        EncodedBlobMode::Snapshot => {}
        _ => return Err(Unresolved::Undecodable),
    }
    import_blob(doc, bytes).map_err(undecodable)?;
    if doc.is_shallow() {
        return Err(Unresolved::ActorSplit(SHALLOW));
    }
    if doc.state_frontiers() != doc.oplog_frontiers() {
        return Err(Unresolved::ActorSplit(STATE_NOT_HEAD));
    }
    Ok(())
}

/// An update's slice: the spans its own metadata names.
fn update_slice(bytes: &[u8]) -> Option<Slice> {
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

/// Imports `bytes` into `doc`, refusing one whose dependencies it lacks.
fn import_blob(doc: &LoroDoc, bytes: &[u8]) -> Result<()> {
    let status = doc.import(bytes).map_err(|_| corrupt())?;
    if status.pending.is_some() {
        return Err(corrupt());
    }
    Ok(())
}

/// Imports `changes` into `doc`, refusing ones whose dependencies it lacks.
fn import_changes(doc: &LoroDoc, changes: &[JsonChange]) -> Result<()> {
    let schema = JsonSchema {
        schema_version: JSON_SCHEMA,
        start_version: Frontiers::default(),
        peers: None,
        changes: changes.to_vec(),
    };
    let status = doc.import_json_updates(schema).map_err(|_| corrupt())?;
    if status.pending.is_some() {
        return Err(corrupt());
    }
    Ok(())
}

/// The typed history `slice` names in `doc`: for a snapshot, everything
/// `doc` holds now; for an update, its spans.
fn history(doc: &LoroDoc, slice: &Slice) -> Vec<JsonChange> {
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

/// `slice` of `doc`, as a row stores it.
fn export_slice(doc: &LoroDoc, slice: &Slice) -> Result<Vec<u8>> {
    let mode = match slice {
        Slice::Snapshot => ExportMode::Snapshot,
        Slice::Updates(spans) => ExportMode::updates_in_range(spans.as_slice()),
    };
    doc.export(mode).map_err(|_| corrupt())
}

/// Whether `bytes` is a blob of `slice`'s shape: a full snapshot, or an
/// update holding exactly its spans.
fn blob_holds(bytes: &[u8], slice: &Slice) -> bool {
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
fn same_blob(stored: &[u8], rebuilt: &[u8]) -> bool {
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
fn split_history<C: LoroActorCodec>(
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

/// Each row's content: its no-one history exported as the row's slice of a
/// scratch document that holds the rows before it, with its holes.
fn no_one_contents<C: LoroActorCodec>(
    slices: &[Slice],
    free: &[Vec<JsonChange>],
    atoms: &[Vec<Atom>],
) -> Result<Vec<Vec<u8>>> {
    let scratch = LoroDoc::new();
    let mut contents = Vec::with_capacity(slices.len());
    for ((slice, changes), row_atoms) in slices.iter().zip(free).zip(atoms) {
        import_changes(&scratch, changes)?;
        let history = export_slice(&scratch, slice)?;
        contents.push(write_frame(C::FAMILY, slice, row_atoms, &history)?);
    }
    Ok(contents)
}

/// Each stored row against its all-open join under `policy`: the history
/// the rebuilt bytes carry is the stored one, and the rebuilt blob holds the
/// stored slice.
fn prove_split(
    rows: &[&[u8]],
    stored: &[Vec<JsonChange>],
    joined: &JoinedLoro,
    policy: RoundTripPolicy,
) -> Result<()> {
    if rows.len() != joined.rows.len() || rows.len() != joined.histories.len() {
        return Err(corrupt());
    }
    let rebuilt = joined.rows.iter().zip(&joined.histories);
    for ((row, stored_history), (rebuilt, carried)) in rows.iter().zip(stored).zip(rebuilt) {
        admit_round_trip(policy, row, rebuilt, |stored_bytes, rebuilt_bytes| {
            prove_loro_equivalent(stored_history, carried)?;
            if same_blob(stored_bytes, rebuilt_bytes) {
                Ok(())
            } else {
                Err(corrupt())
            }
        })?;
    }
    Ok(())
}

/// Rebuilds one group's rows from their contents and the atoms that opened:
/// each hole whose actor did not open keeps its erased form, and no actor is
/// taken from anywhere else. Refuses a content that does not read, an atom
/// for no hole or for one twice, and a rebuild whose bytes do not carry the
/// filled history.
pub(crate) fn join_loro<C: LoroActorCodec>(
    rows: &[OpenedRow<'_>],
    codec: &C,
) -> Result<JoinedLoro> {
    let frames = rows
        .iter()
        .map(|row| read_frame(C::FAMILY, row.content))
        .collect::<Result<Vec<_>>>()?;
    let mut shapes = frames.iter().map(|frame| &frame.slice);
    if shapes.next() != Some(&Slice::Snapshot) || shapes.any(|slice| *slice == Slice::Snapshot) {
        return Err(corrupt());
    }
    // The no-one history, row by row, each filled with its opened actors.
    let free = LoroDoc::new();
    let mut filled = Vec::with_capacity(frames.len());
    for (frame, row) in frames.iter().zip(rows) {
        if !blob_holds(&frame.history, &frame.slice) {
            return Err(corrupt());
        }
        import_blob(&free, &frame.history)?;
        if free.is_shallow() {
            return Err(corrupt());
        }
        let changes = history(&free, &frame.slice);
        filled.push(fill_history(changes, &frame.holes, &row.atoms, codec)?);
    }
    // A fresh document rebuilt from the filled history, never one that
    // already holds these operation ids.
    let rebuilt = LoroDoc::new();
    let mut bytes = Vec::with_capacity(frames.len());
    for (frame, changes) in frames.iter().zip(&filled) {
        import_changes(&rebuilt, changes)?;
        bytes.push(export_slice(&rebuilt, &frame.slice)?);
    }
    // What those bytes carry, read back in another fresh document.
    let doc = LoroDoc::new();
    let mut histories = Vec::with_capacity(frames.len());
    for ((frame, row), changes) in frames.iter().zip(&bytes).zip(&filled) {
        if !blob_holds(row, &frame.slice) {
            return Err(corrupt());
        }
        import_blob(&doc, row)?;
        let carried = history(&doc, &frame.slice);
        prove_loro_equivalent(changes, &carried)?;
        histories.push(carried);
    }
    if doc.is_shallow() || doc.get_deep_value() != rebuilt.get_deep_value() {
        return Err(corrupt());
    }
    Ok(JoinedLoro {
        rows: bytes,
        histories,
        doc,
    })
}

/// `changes` with each opened atom's actor back in its hole.
fn fill_history<C: LoroActorCodec>(
    mut changes: Vec<JsonChange>,
    holes: &[String],
    atoms: &[Atom],
    codec: &C,
) -> Result<Vec<JsonChange>> {
    let mut sites: BTreeMap<(Site, u64, i32), Vec<&str>> = BTreeMap::new();
    for hole in holes {
        let (site, op, path) = parse_address(hole).ok_or_else(corrupt)?;
        let paths = sites.entry((site, op.peer, op.counter)).or_default();
        if paths.contains(&path) {
            return Err(corrupt());
        }
        paths.push(path);
    }
    let mut opened: BTreeMap<&str, EntityId> = BTreeMap::new();
    for atom in atoms {
        if !holes.contains(&atom.field) || opened.insert(atom.field.as_str(), atom.actor).is_some()
        {
            return Err(corrupt());
        }
    }
    for change in &mut changes {
        let id = change.id;
        if let Some(paths) = sites.remove(&(Site::Message, id.peer, id.counter)) {
            let message = change.msg.as_mut().ok_or_else(corrupt)?;
            for path in paths {
                let field = address(Site::Message, id, path);
                if let Some(&actor) = opened.get(field.as_str()) {
                    *message = codec.fill_message(message.as_str(), path, actor)?;
                }
            }
        }
        for op in &mut change.ops {
            let Some(paths) = sites.remove(&(Site::MapValue, id.peer, op.counter)) else {
                continue;
            };
            let JsonOpContent::Map(JsonMapOp::Insert { key, value }) = &mut op.content else {
                return Err(corrupt());
            };
            let container = &op.container;
            let at = ID::new(id.peer, op.counter);
            for path in paths {
                let field = address(Site::MapValue, at, path);
                if let Some(&actor) = opened.get(field.as_str()) {
                    *value = codec.fill_map_insert(container, key.as_str(), value, path, actor)?;
                }
            }
        }
    }
    // Every hole names an operation of this row.
    if !sites.is_empty() {
        return Err(corrupt());
    }
    Ok(changes)
}

/// Puts one split row in `owner`'s rows: its no-one-form content, and each
/// actor it named as an actor part naming the row, holding the actor's 16
/// id bytes.
pub(crate) fn place(out: &mut Captured, owner: OwnerRef, at: RowLocator, row: SplitRow) {
    let rows = out.owner(owner);
    for atom in row.atoms {
        rows.actor_parts.push(ActorPart {
            actor_entity: atom.actor,
            content_locator: at.clone(),
            field: atom.field,
            bytes: atom.actor.as_bytes().to_vec(),
        });
    }
    rows.rows.push(RowPart::NoActor {
        at,
        value: row.content,
    });
}

/// The atoms a row's opened actor parts fill: each part's bytes are the
/// 16 id bytes of the actor it is sealed under.
pub(crate) fn opened_atoms(parts: &[&ActorPart]) -> Result<Vec<Atom>> {
    parts
        .iter()
        .map(|part| {
            let id: [u8; 16] = part.bytes.as_slice().try_into().map_err(|_| corrupt())?;
            let actor = EntityId::from_bytes(id)?;
            if actor != part.actor_entity {
                return Err(corrupt());
            }
            Ok(Atom {
                field: part.field.clone(),
                actor,
            })
        })
        .collect()
}

/// Whether `content` is a row `C`'s split framed: its framing reads and
/// names `C`'s family. A restore joins a group by the family its own framing
/// names, never by a guess at its bytes.
pub(crate) fn frames<C: LoroActorCodec>(content: &[u8]) -> bool {
    read_frame(C::FAMILY, content).is_ok()
}

/// Whether `bytes` is a Loro update blob whose checksum holds.
pub(crate) fn is_update(bytes: &[u8]) -> bool {
    LoroDoc::decode_import_blob_meta(bytes, true)
        .is_ok_and(|meta| meta.mode == EncodedBlobMode::Updates)
}
