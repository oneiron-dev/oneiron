//! A window's Loro rows split for a checkpoint (KS7-3b, FIX 5688), over the
//! vendored root-map checkpoint (`loro::checkpoint`). A window's snapshot
//! is captured alone. Its pending and queued updates are captured together
//! over that snapshot, never folded into it, and each comes back as its own
//! exact operation spans. Every value the capture meets, at a shallow root,
//! in the latest state and in every retained operation, is placed with its
//! family's codec ([`super::owners::root_entry`]): each rightful holder takes its own copy
//! (FIX 9128), the actors it names are split out (FIX 9127), and every key,
//! a deleted one's too, must be one that may stand plaintext
//! ([`super::owners::key_refusal`]). A Loro PeerID only writes; the owner handles the
//! capture records are indexes into this capture's own holders.
//!
//! A window splits only once its all-open join gives each stored row back
//! under [`WINDOW_ROUND_TRIP`]: every split value fills back to its stored
//! bytes, the vendored join's report holds, the rebuilt document is the
//! captured one, and each row cut from it again holds its stored slice.
//! Nothing is emitted before that. Anything else keeps the window's rows
//! whole under the vault-wide seal, named: an operation waiting on one the
//! capture does not hold, an update its window's history no longer wholly
//! holds, a nested container, a message, a key or value no family reads.
//!
//! A room turn row in parts is split from its joined row ([`super::joined_turns`],
//! FIX 12153): its manifest, part keys and parts become derived slots, and
//! the proof joins the all-open turn, its actor absent and the turn absent.

use std::collections::{BTreeMap, BTreeSet};

use loro::checkpoint::{Atom, AtomId, Capture, Parts, Payload, SlotKind, Unsupported};
use loro::{EncodedBlobMode, ExportMode, IdSpan, ImportBlobMetadata, LoroDoc, LoroValue};

use super::classify::{Classifier, Home, Plan, Refusal};
use super::joined_turns::{Transport, TurnSource, derived_atom};
use super::owners::{WINDOW_ROOTS, key_fill, root_fill};
use super::parts::PartHolders;
use super::{
    AtomHome, AtomRef, CapturedSyncRow, DerivedRole, JoinedTurn, LoroCarrier, LoroRow, LoroSlice,
    LoroSlot, SkeletonRow, SlotCopy, SyncAtom, SyncCarrier, SyncPayloadOwners, SyncUnclassified,
    WINDOW_ROUND_TRIP, WindowProjection,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{SYNC_U_W, SideKey, WINDOW_SNAPSHOT};
use crate::store::checkpoint_payload::rows::{ActorPart, RowLocator, admit_round_trip, bad_part};
use crate::sync::loro_support::json_covers_blob;
use crate::sync::window_rows::WindowUpdateKey;

/// A window history with operations waiting on ones the capture does not
/// hold.
const PENDING: &str = "a window history whose operations wait on ones the capture does not hold";

/// A window history that is not plain root-map writes of its state.
const NOT_ROOT_MAP: &str = "a window history that is not plain root-map writes of its state";

/// A pending or queued row that is not a Loro update.
const NOT_AN_UPDATE: &str = "a window's pending row that is not a Loro update";

/// An update the window's history does not wholly hold: clipped below a
/// shallow root, or one it cannot take.
const CLIPPED: &str = "an update whose operations the window's history does not all hold";

/// A split whose all-open join does not give its rows back.
const NOT_PROVED: &str = "a window history its split does not give back";

/// The member path a value's copy rests at: this, its atom id, then its
/// place among the value's holders.
const COPY: &str = "loro";

/// One Loro row of a window: where it sits, its family, and its Loro bytes.
struct LoroIn<'a> {
    at: RowLocator,
    carrier: SyncCarrier,
    blob: &'a [u8],
}

/// Where a row sits among its window's Loro rows.
enum Place {
    Snapshot,
    Pending(u64),
    Queued(u64),
}

/// A window's Loro rows: its snapshot, then its pending updates and its
/// queued ones, each in sequence order.
#[derive(Default)]
struct WindowRows<'a> {
    snapshot: Option<LoroIn<'a>>,
    updates: BTreeMap<(u8, u64), LoroIn<'a>>,
}

/// The window `row` names, its place there and its Loro bytes. `None` for a
/// row that is no window's Loro row; `Some(None)` for one that does not read.
fn read<'a>(row: &CapturedSyncRow<'a>) -> Option<Option<(String, Place, &'a [u8])>> {
    match row.carrier {
        SyncCarrier::WindowSnapshot => Some(
            row.key
                .strip_prefix(WINDOW_SNAPSHOT.prefix)
                .and_then(|window| std::str::from_utf8(window).ok())
                .map(|window| (window.to_owned(), Place::Snapshot, row.value)),
        ),
        SyncCarrier::WindowUpdate => Some(
            row.key
                .strip_prefix(SYNC_U_W.prefix)
                .and_then(WindowUpdateKey::decode_key)
                .map(|key| (key.window, Place::Pending(key.seq), row.value)),
        ),
        SyncCarrier::SyncQueue => crate::sync::queue::checkpoint::queued_update(row.key, row.value)
            .map(|(seq, window, update)| Some((window.to_owned(), Place::Queued(seq), update))),
        _ => None,
    }
}

/// The window `row` names, when it is a window's Loro row that reads.
pub(super) fn window_of(row: &CapturedSyncRow<'_>) -> Option<String> {
    read(row).flatten().map(|(window, _, _)| window)
}

pub(super) fn project(
    rows: &[CapturedSyncRow<'_>],
    owners: &dyn SyncPayloadOwners,
    emit: &mut dyn FnMut(AtomHome, SyncAtom) -> Result<AtomRef>,
) -> Result<WindowProjection> {
    let mut projection = WindowProjection::default();
    let mut windows: BTreeMap<String, WindowRows<'_>> = BTreeMap::new();
    for row in rows {
        let at = RowLocator::row(row.carrier.db(), row.key.to_vec());
        let Some(read) = read(row) else {
            continue;
        };
        let Some((window, place, blob)) = read else {
            projection.unclassified.push(SkeletonRow::Unclassified {
                at,
                owner: None,
                reason: SyncUnclassified::Undecodable,
            });
            continue;
        };
        let row = LoroIn {
            at,
            carrier: row.carrier,
            blob,
        };
        let window = windows.entry(window).or_default();
        match place {
            Place::Snapshot => window.snapshot = Some(row),
            Place::Pending(seq) => {
                window.updates.insert((0, seq), row);
            }
            Place::Queued(seq) => {
                window.updates.insert((1, seq), row);
            }
        }
    }
    for (window, rows) in windows {
        let base = rows.snapshot.as_ref().map(|row| row.blob);
        if let Some(snapshot) = rows.snapshot {
            group(&window, None, vec![snapshot], owners, emit, &mut projection)?;
        }
        if !rows.updates.is_empty() {
            let updates = rows.updates.into_values().collect();
            group(&window, base, updates, owners, emit, &mut projection)?;
        }
    }
    Ok(projection)
}

/// Splits one group of `window`'s rows and emits its copies, or names each
/// of its rows whole with why.
fn group(
    window: &str,
    base: Option<&[u8]>,
    rows: Vec<LoroIn<'_>>,
    owners: &dyn SyncPayloadOwners,
    emit: &mut dyn FnMut(AtomHome, SyncAtom) -> Result<AtomRef>,
    projection: &mut WindowProjection,
) -> Result<()> {
    match prepare(base, &rows, owners) {
        Ok(prepared) => projection.carriers.push(prepared.emit(window, rows, emit)?),
        Err((owner, reason)) => {
            let whole = rows.into_iter().map(|row| SkeletonRow::Unclassified {
                at: row.at,
                owner,
                reason,
            });
            projection.unclassified.extend(whole);
        }
    }
    Ok(())
}

/// Why the vendored capture left a window whole, when no family said.
fn unsupported(why: Unsupported) -> SyncUnclassified {
    match why {
        Unsupported::NonQuiescent => SyncUnclassified::ActorSplit(PENDING),
        Unsupported::Root => SyncUnclassified::UnknownRoot,
        Unsupported::Shape => SyncUnclassified::ActorSplit(NOT_ROOT_MAP),
        Unsupported::Key | Unsupported::Ownership => SyncUnclassified::NoOwner,
    }
}

/// A group proved split, not yet emitted.
struct Prepared {
    parts: Parts,
    plans: Vec<Plan>,
    homes: Vec<Home>,
    slices: Vec<LoroSlice>,
    turn: Option<TurnSource>,
}

/// Captures and proves one group; nothing is emitted.
fn prepare(
    base: Option<&[u8]>,
    rows: &[LoroIn<'_>],
    owners: &dyn SyncPayloadOwners,
) -> std::result::Result<Prepared, Refusal> {
    let (doc, slices) = open(base, rows)?;
    let mut classifier = Classifier::new(owners, None, None);
    let mut captured = doc.export_root_map_checkpoint(&WINDOW_ROOTS, &mut classifier);
    if classifier.needs_parts {
        // A part's holders are every manifest's in the capture's history:
        // note them all first, then place. A parted turn row the notes
        // prove is carried joined (FIX 12153).
        let mut noting = Classifier::new(owners, None, None);
        noting.noting = Some(PartHolders::default());
        doc.export_root_map_checkpoint(&WINDOW_ROOTS, &mut noting);
        let turn = TurnSource::of(&noting.turns);
        classifier = Classifier::new(owners, noting.noting, turn);
        captured = doc.export_root_map_checkpoint(&WINDOW_ROOTS, &mut classifier);
    }
    let parts = match captured {
        Capture::Classified(parts) => parts,
        Capture::Unclassified(why) => {
            return Err(classifier.refusal.unwrap_or((None, unsupported(why))));
        }
    };
    let Classifier {
        plans, homes, turn, ..
    } = classifier;
    if plans.len() != parts.atoms.len() {
        return Err(not_proved());
    }
    // A joined turn is carried only with its manifest derived from it.
    let turn = turn.filter(|_| {
        plans.iter().any(|plan| {
            plan.derived
                .is_some_and(|slot| slot.role == DerivedRole::Manifest)
        })
    });
    // Current-map values alone miss historical heads and removed parts.
    // Judge manifest bindings against every value this group captured.
    {
        let entries: Vec<(&str, &[u8])> = plans
            .iter()
            .filter(|plan| {
                plan.kind == SlotKind::Value
                    && plan.root.as_str() == crate::sync::repo_manifests::REPO_MANIFESTS_MAP
            })
            .map(|plan| (plan.key.as_str(), plan.value.as_slice()))
            .collect();
        if let Some((owner, reason)) =
            crate::sync::repo_manifests::checkpoint::binding_refusal(&entries)
        {
            return Err((Some(owner), reason));
        }
    }
    prove(&doc, rows, &slices, &parts, &plans, turn.as_ref())?;
    Ok(Prepared {
        parts,
        plans,
        homes,
        slices,
        turn,
    })
}

fn not_proved() -> Refusal {
    (None, SyncUnclassified::ActorSplit(NOT_PROVED))
}

/// The document a group's rows hold, and each row's slice of it: a window's
/// snapshot alone, or every update over `base`, the window's snapshot when
/// it has one.
fn open(
    base: Option<&[u8]>,
    rows: &[LoroIn<'_>],
) -> std::result::Result<(LoroDoc, Vec<LoroSlice>), Refusal> {
    let undecodable = || (None, SyncUnclassified::Undecodable);
    if let [row] = rows
        && row.carrier == SyncCarrier::WindowSnapshot
    {
        if !meta(row.blob).is_some_and(|meta| meta.mode.is_snapshot()) {
            return Err(undecodable());
        }
        let doc = LoroDoc::from_snapshot(row.blob).map_err(|_| undecodable())?;
        return Ok((doc, vec![LoroSlice::Snapshot]));
    }
    let doc = match base {
        Some(base) => LoroDoc::from_snapshot(base).map_err(|_| undecodable())?,
        None => LoroDoc::new(),
    };
    let mut metas = Vec::with_capacity(rows.len());
    for row in rows {
        let meta = meta(row.blob).ok_or_else(undecodable)?;
        if meta.mode != EncodedBlobMode::Updates {
            return Err((None, SyncUnclassified::ActorSplit(NOT_AN_UPDATE)));
        }
        // What waits on an operation no row holds stays pending, and the
        // capture refuses a pending document.
        doc.import(row.blob)
            .map_err(|_| (None, SyncUnclassified::ActorSplit(CLIPPED)))?;
        metas.push(meta);
    }
    let mut slices = Vec::with_capacity(rows.len());
    for meta in &metas {
        let held = doc.export_json_updates(&meta.partial_start_vv, &meta.partial_end_vv);
        if !json_covers_blob(&held, meta) {
            return Err((None, SyncUnclassified::ActorSplit(CLIPPED)));
        }
        slices.push(LoroSlice::Updates(spans_of(meta)));
    }
    Ok((doc, slices))
}

/// Proves a capture's split against the stored rows: each split value
/// fills back to its stored bytes with every actor, each slot derived from
/// the joined turn `turn` is what the all-open turn re-parts to, and the
/// all-open join of those atoms rebuilds the captured document, each row cut
/// from it holding its stored slice, under [`WINDOW_ROUND_TRIP`] fed the join
/// report's verdict. A joined turn's other forms join too: its actor absent,
/// and the turn absent (FIX 12153).
fn prove(
    doc: &LoroDoc,
    rows: &[LoroIn<'_>],
    slices: &[LoroSlice],
    parts: &Parts,
    plans: &[Plan],
    turn: Option<&TurnSource>,
) -> std::result::Result<(), Refusal> {
    let open = turn.map(|turn| &turn.open);
    for (atom, plan) in parts.atoms.iter().zip(plans) {
        if let Some(derived) = plan.derived {
            if derived_atom(atom.id, &atom.holders, derived.role, open).as_ref() != Some(atom) {
                return Err(not_proved());
            }
            continue;
        }
        let stored: &[u8] = match (&atom.payload, plan.kind) {
            (Payload::Value(LoroValue::Binary(stored)), SlotKind::Value) => stored.as_slice(),
            (Payload::Key(key), SlotKind::Key) if *key == plan.key => key.as_bytes(),
            _ => return Err(not_proved()),
        };
        let Some(split) = &plan.split else {
            // A key held whole is emitted as it is.
            if plan.kind == SlotKind::Key && plan.value != stored {
                return Err(not_proved());
            }
            continue;
        };
        let mut fields = BTreeSet::new();
        let distinct = split
            .actors
            .iter()
            .all(|(field, _)| fields.insert(field.as_str()));
        let opened: Vec<(&str, EntityId)> = split
            .actors
            .iter()
            .map(|(field, actor)| (field.as_str(), *actor))
            .collect();
        let filled = match plan.kind {
            SlotKind::Key => {
                key_fill(&plan.root, &split.no_one, &opened).map(|key| key.map(String::into_bytes))
            }
            _ => root_fill(&plan.root, &plan.key, &split.no_one, &opened, &fields),
        };
        if !distinct || !matches!(filled, Ok(Some(filled)) if filled == stored) {
            return Err(not_proved());
        }
    }
    let (atoms, erased) = expand(parts, plans, open);
    if !erased.is_empty() {
        return Err(not_proved());
    }
    let joined = LoroDoc::join_root_map_checkpoint(&parts.skeleton, &atoms, &[])
        .map_err(|_| not_proved())?;
    let rejoined = LoroDoc::from_snapshot(&joined.bytes).map_err(|_| not_proved())?;
    if !same_doc(doc, &rejoined) {
        return Err(not_proved());
    }
    for (row, slice) in rows.iter().zip(slices) {
        let rebuilt = export_slice(&rejoined, slice).map_err(|_| not_proved())?;
        let proved = admit_round_trip(WINDOW_ROUND_TRIP, row.blob, &rebuilt, |stored, rebuilt| {
            if joined.report.equivalent && same_slice(stored, rebuilt, slice) {
                Ok(())
            } else {
                Err(bad_part())
            }
        });
        proved.map_err(|_| not_proved())?;
    }
    if let Some(turn) = turn {
        if !turn.split.actors.is_empty() {
            let parts_held = usize::try_from(turn.parts).map_err(|_| not_proved())?;
            let erased_actor =
                Transport::of(&turn.split.no_one, parts_held).map_err(|_| not_proved())?;
            joins(parts, plans, Some(&erased_actor))?;
        }
        joins(parts, plans, None)?;
    }
    Ok(())
}

/// The atoms a join takes, each slot derived from the joined turn made from
/// `transport`, and the derived slots it erases.
fn expand(
    parts: &Parts,
    plans: &[Plan],
    transport: Option<&Transport>,
) -> (Vec<Atom>, Vec<AtomId>) {
    let mut atoms = Vec::with_capacity(parts.atoms.len());
    let mut erased = Vec::new();
    for (atom, plan) in parts.atoms.iter().zip(plans) {
        let Some(derived) = plan.derived else {
            atoms.push(atom.clone());
            continue;
        };
        match derived_atom(atom.id, &atom.holders, derived.role, transport) {
            Some(atom) => atoms.push(atom),
            None => erased.push(atom.id),
        }
    }
    (atoms, erased)
}

/// Whether the join of `parts`, each derived slot made from `transport`,
/// proves its skeleton.
fn joins(
    parts: &Parts,
    plans: &[Plan],
    transport: Option<&Transport>,
) -> std::result::Result<(), Refusal> {
    let (atoms, erased) = expand(parts, plans, transport);
    let joined = LoroDoc::join_root_map_checkpoint(&parts.skeleton, &atoms, &erased)
        .map_err(|_| not_proved())?;
    if joined.report.equivalent {
        Ok(())
    } else {
        Err(not_proved())
    }
}

impl Prepared {
    /// Emits each value's copies, one per holder, each at its own member
    /// path, and returns the window's outer skeleton.
    fn emit(
        self,
        window: &str,
        rows: Vec<LoroIn<'_>>,
        emit: &mut dyn FnMut(AtomHome, SyncAtom) -> Result<AtomRef>,
    ) -> Result<LoroCarrier> {
        let Self {
            parts,
            plans,
            homes,
            slices,
            turn,
        } = self;
        let first = rows
            .first()
            .map(|row| row.at.clone())
            .ok_or_else(bad_part)?;
        let mut slots = Vec::with_capacity(plans.len());
        for (atom, plan) in parts.atoms.iter().zip(plans) {
            // A derived slot holds no copy: the join makes it (FIX 12153).
            if plan.derived.is_some() {
                slots.push(LoroSlot {
                    copies: Vec::new(),
                    holes: Vec::new(),
                    derived: plan.derived,
                });
                continue;
            }
            let mut copies = Vec::with_capacity(atom.holders.len());
            for (place, handle) in atom.holders.iter().enumerate() {
                let home = usize::try_from(*handle)
                    .ok()
                    .and_then(|index| homes.get(index));
                let (target, dependencies) = home.ok_or_else(bad_part)?.target();
                let at = first.fragment(format!("{COPY} {} {place}", atom.id));
                let actors = match (&plan.split, target) {
                    (Some(split), AtomHome::Owner(_)) => split
                        .actors
                        .iter()
                        .map(|(field, actor)| ActorPart {
                            actor_entity: *actor,
                            content_locator: at.clone(),
                            field: field.clone(),
                            bytes: actor.as_bytes().to_vec(),
                        })
                        .collect(),
                    (Some(_), _) => return Err(bad_part()),
                    (None, _) => Vec::new(),
                };
                let copy = SyncAtom {
                    at: at.clone(),
                    value: plan.value.clone(),
                    dependencies: dependencies.clone(),
                    actors,
                };
                let ordinal = emit(target, copy)?;
                copies.push(SlotCopy {
                    at,
                    atom: ordinal,
                    home: target,
                    dependencies,
                });
            }
            let holes = plan
                .split
                .map(|split| split.actors.into_iter().map(|(field, _)| field).collect())
                .unwrap_or_default();
            slots.push(LoroSlot {
                copies,
                holes,
                derived: None,
            });
        }
        let joined = match turn {
            Some(turn) => vec![emit_turn(turn, &first, emit)?],
            None => Vec::new(),
        };
        let rows = rows
            .into_iter()
            .zip(slices)
            .map(|(row, slice)| LoroRow {
                at: row.at,
                carrier: row.carrier,
                slice,
            })
            .collect();
        Ok(LoroCarrier {
            window: window.to_owned(),
            skeleton: parts.skeleton,
            rows,
            slots,
            joined,
        })
    }
}

/// Emits the joined turn `turn`'s copy, the turn naming no one under its
/// holder with its actor split out beside it, as a whole row's copy is
/// (FIX 12153), at its own member path.
fn emit_turn(
    turn: TurnSource,
    first: &RowLocator,
    emit: &mut dyn FnMut(AtomHome, SyncAtom) -> Result<AtomRef>,
) -> Result<JoinedTurn> {
    let TurnSource {
        key,
        parts,
        holder,
        split,
        ..
    } = turn;
    let at = first.fragment(format!("{COPY} turn 0 0"));
    let home = AtomHome::Owner(holder.owner);
    let actors = split
        .actors
        .iter()
        .map(|(field, actor)| ActorPart {
            actor_entity: *actor,
            content_locator: at.clone(),
            field: field.clone(),
            bytes: actor.as_bytes().to_vec(),
        })
        .collect();
    let copy = SyncAtom {
        at: at.clone(),
        value: split.no_one,
        dependencies: holder.dependencies.clone(),
        actors,
    };
    let atom = emit(home, copy)?;
    Ok(JoinedTurn {
        key,
        parts,
        copies: vec![SlotCopy {
            at,
            atom,
            home,
            dependencies: holder.dependencies,
        }],
        holes: split.actors.into_iter().map(|(field, _)| field).collect(),
    })
}

/// Whether two documents hold one history and one state: versions,
/// frontiers, shallow root and value.
fn same_doc(stored: &LoroDoc, rebuilt: &LoroDoc) -> bool {
    stored.oplog_vv() == rebuilt.oplog_vv()
        && stored.oplog_frontiers() == rebuilt.oplog_frontiers()
        && stored.is_shallow() == rebuilt.is_shallow()
        && stored.shallow_since_vv().to_vv() == rebuilt.shallow_since_vv().to_vv()
        && stored.shallow_since_frontiers() == rebuilt.shallow_since_frontiers()
        && stored.get_deep_value() == rebuilt.get_deep_value()
}

/// A blob's metadata, its checksum held.
pub(super) fn meta(blob: &[u8]) -> Option<ImportBlobMetadata> {
    LoroDoc::decode_import_blob_meta(blob, true).ok()
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

/// `slice` of `doc`, as a row stores it.
pub(super) fn export_slice(doc: &LoroDoc, slice: &LoroSlice) -> Result<Vec<u8>> {
    let mode = match slice {
        LoroSlice::Snapshot => ExportMode::Snapshot,
        LoroSlice::Updates(spans) => ExportMode::updates_in_range(spans.as_slice()),
    };
    doc.export(mode).map_err(|_| bad_part())
}

/// Whether `blob` is of `slice`'s shape: a snapshot, or an update holding
/// exactly its spans.
pub(super) fn holds_slice(blob: &[u8], slice: &LoroSlice) -> bool {
    meta(blob).is_some_and(|meta| match slice {
        LoroSlice::Snapshot => meta.mode.is_snapshot(),
        LoroSlice::Updates(spans) => {
            meta.mode == EncodedBlobMode::Updates && spans_of(&meta) == *spans
        }
    })
}

/// Whether `rebuilt` holds `stored`'s slice: its shape, mode, starting
/// frontiers and versions.
fn same_slice(stored: &[u8], rebuilt: &[u8], slice: &LoroSlice) -> bool {
    let (Some(before), Some(after)) = (meta(stored), meta(rebuilt)) else {
        return false;
    };
    holds_slice(stored, slice)
        && holds_slice(rebuilt, slice)
        && before.mode == after.mode
        && before.start_frontiers == after.start_frontiers
        && before.partial_start_vv == after.partial_start_vv
        && before.partial_end_vv == after.partial_end_vv
}
