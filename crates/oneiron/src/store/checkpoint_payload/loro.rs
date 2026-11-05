//! Core half of `store::checkpoint_payload::loro`: its store-layer items live in `oneiron_store::checkpoint_payload::loro` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::checkpoint_payload::loro::*;

use self::frame::{read_frame, write_frame};
pub(crate) use self::proof::prove_loro_equivalent;
use super::corrupt;
use super::rows::{
    ActorPart, Captured, OwnerRef, RoundTripPolicy, RowLocator, RowPart, Unresolved,
    admit_round_trip,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use ::loro::{
    ContainerID, EncodedBlobMode, ExportMode, Frontiers, ID, IdSpan, ImportBlobMetadata,
    JsonChange, JsonMapOp, JsonOp, JsonOpContent, JsonSchema, LoroDoc, LoroValue, VersionVector,
};
use std::collections::{BTreeMap, BTreeSet};

mod frame;
mod proof;

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

/// `slice` of `doc`, as a row stores it.
fn export_slice(doc: &LoroDoc, slice: &Slice) -> Result<Vec<u8>> {
    let mode = match slice {
        Slice::Snapshot => ExportMode::Snapshot,
        Slice::Updates(spans) => ExportMode::updates_in_range(spans.as_slice()),
    };
    doc.export(mode).map_err(|_| corrupt())
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
