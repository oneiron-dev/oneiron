//! A window's Loro rows split for a checkpoint (KS7-3b, FIX 5688), over the
//! vendored root-map checkpoint (`loro::checkpoint`). A window's snapshot
//! is captured alone. Its pending and queued updates are captured together
//! over that snapshot, never folded into it, and each comes back as its own
//! exact operation spans. Every value the capture meets, at a shallow root,
//! in the latest state and in every retained operation, is placed with its
//! family's codec ([`root_entry`]): each rightful holder takes its own copy
//! (FIX 9128), the actors it names are split out (FIX 9127), and every key,
//! a deleted one's too, must be one that may stand plaintext
//! ([`key_refusal`]). A Loro PeerID only writes; the owner handles the
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

use std::collections::{BTreeMap, BTreeSet};

use loro::checkpoint::{Capture, Classify, Field, OwnerId, Parts, Payload, Unsupported};
use loro::{EncodedBlobMode, ExportMode, IdSpan, ImportBlobMetadata, LoroDoc, LoroValue};

use super::owners::{WINDOW_ROOTS, key_refusal, root_entry, root_fill};
use super::parts::PartHolders;
use super::{
    AtomHome, AtomRef, CapturedSyncRow, Holder, LoroCarrier, LoroRow, LoroSlice, LoroSlot,
    Placement, SkeletonRow, SlotCopy, SyncAtom, SyncCarrier, SyncPayloadOwners, SyncUnclassified,
    ValueSplit, WINDOW_ROUND_TRIP, WindowProjection,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{SYNC_U_W, SideKey, WINDOW_SNAPSHOT};
use crate::store::checkpoint_payload::rows::{
    ActorPart, OtherClient, OwnerRef, RowLocator, admit_round_trip, bad_part,
};
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

/// A change's commit message.
const MESSAGE: &str = "a window change's message, which no window family writes";

/// A split whose all-open join does not give its rows back.
const NOT_PROVED: &str = "a window history its split does not give back";

/// The member path a value's copy rests at: this, its atom id, then its
/// place among the value's holders.
const COPY: &str = "loro";

/// The owner found, when one was, and why a window stays whole.
type Refusal = (Option<OwnerRef>, SyncUnclassified);

/// One Loro row of a window: where it sits, its family, and its Loro bytes.
struct LoroIn<'a> {
    at: RowLocator,
    carrier: SyncCarrier,
    blob: &'a [u8],
}

/// Where a row sits among its window's Loro rows.
enum Place {
    Snapshot,
    Pending(u32),
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
                window.updates.insert((0, u64::from(seq)), row);
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

/// What one copy of a value goes to. Its index among a capture's homes is
/// the owner handle the vendored capture records.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Home {
    Holder(Holder),
    Structure(Vec<OwnerRef>),
    Client(OtherClient),
}

impl Home {
    fn target(&self) -> (AtomHome, Vec<OwnerRef>) {
        match self {
            Self::Holder(holder) => (AtomHome::Owner(holder.owner), holder.dependencies.clone()),
            Self::Structure(dependencies) => (AtomHome::Structure, dependencies.clone()),
            Self::Client(client) => (AtomHome::Client(*client), Vec::new()),
        }
    }
}

/// One value the capture met, in the order it made its atoms: its root map
/// and key, what each of its copies holds, and its actors.
struct Plan {
    root: String,
    key: String,
    value: Vec<u8>,
    split: Option<ValueSplit>,
}

/// The families' answers to one capture.
struct Classifier<'o> {
    owners: &'o dyn SyncPayloadOwners,
    /// Every part's holders, once a first pass noted the manifests.
    parts: Option<PartHolders>,
    /// The first pass's notes, while it runs.
    noting: Option<PartHolders>,
    homes: Vec<Home>,
    plans: Vec<Plan>,
    refusal: Option<Refusal>,
    /// A part was met before the manifests were noted.
    needs_parts: bool,
}

impl<'o> Classifier<'o> {
    fn new(owners: &'o dyn SyncPayloadOwners, parts: Option<PartHolders>) -> Self {
        Self {
            owners,
            parts,
            noting: None,
            homes: Vec::new(),
            plans: Vec::new(),
            refusal: None,
            needs_parts: false,
        }
    }

    /// Notes the first reason the window stays whole.
    fn refuse(
        &mut self,
        owner: Option<OwnerRef>,
        reason: SyncUnclassified,
    ) -> Option<Vec<OwnerId>> {
        if self.refusal.is_none() {
            self.refusal = Some((owner, reason));
        }
        None
    }

    /// The capture-local handle of `home`: equal homes share one, and two
    /// holders of one owner with other dependencies do not.
    fn handle(&mut self, home: Home) -> OwnerId {
        let index = match self.homes.iter().position(|known| *known == home) {
            Some(index) => index,
            None => {
                self.homes.push(home);
                self.homes.len() - 1
            }
        };
        OwnerId::try_from(index).unwrap_or(OwnerId::MAX)
    }
}

impl Classify for Classifier<'_> {
    fn plain_key(&mut self, root: &str, key: &str) -> bool {
        if self.noting.is_some() {
            return true;
        }
        match key_refusal(root, key) {
            None => true,
            Some(reason) => {
                self.refuse(None, reason);
                false
            }
        }
    }

    fn holders(&mut self, field: Field<'_>) -> Option<Vec<OwnerId>> {
        let Field::Value {
            root, key, value, ..
        } = field
        else {
            return self.refuse(None, SyncUnclassified::ActorSplit(MESSAGE));
        };
        let LoroValue::Binary(bytes) = value else {
            return self.refuse(None, SyncUnclassified::Undecodable);
        };
        let placed = root_entry(root, key, bytes.as_slice(), self.owners);
        if let Some(noting) = self.noting.as_mut() {
            noting.note(root, &placed);
            return Some(vec![0]);
        }
        let placed = match placed {
            Placement::Part => match &self.parts {
                Some(parts) => parts.place(root, key),
                None => {
                    self.needs_parts = true;
                    return None;
                }
            },
            placed => placed,
        };
        let held =
            |holders: Vec<Holder>| -> Vec<Home> { holders.into_iter().map(Home::Holder).collect() };
        let (homes, split): (Vec<Home>, Option<ValueSplit>) = match placed {
            Placement::Owned(owned) => (held(owned), None),
            Placement::Split {
                holders: owned,
                split,
            } => (held(owned), Some(split)),
            Placement::Structure { dependencies } => (vec![Home::Structure(dependencies)], None),
            Placement::Dispatched(client) => (vec![Home::Client(client)], None),
            Placement::Manifest {
                holders: owned,
                joined: None,
                ..
            } => (held(owned), None),
            Placement::Manifest {
                holders: owned,
                joined: Some(reason),
                ..
            } => return self.refuse(owned.first().map(|holder| holder.owner), reason),
            Placement::Unclassified { owner, reason } => return self.refuse(owner, reason),
            Placement::Part => return self.refuse(None, SyncUnclassified::OrphanPart),
        };
        if homes.is_empty() {
            return self.refuse(None, SyncUnclassified::NoOwner);
        }
        let handles: Vec<OwnerId> = homes.into_iter().map(|home| self.handle(home)).collect();
        let value = match &split {
            Some(split) => split.no_one.clone(),
            None => bytes.to_vec(),
        };
        self.plans.push(Plan {
            root: root.to_owned(),
            key: key.to_owned(),
            value,
            split,
        });
        Some(handles)
    }
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
}

/// Captures and proves one group; nothing is emitted.
fn prepare(
    base: Option<&[u8]>,
    rows: &[LoroIn<'_>],
    owners: &dyn SyncPayloadOwners,
) -> std::result::Result<Prepared, Refusal> {
    let (doc, slices) = open(base, rows)?;
    let mut classifier = Classifier::new(owners, None);
    let mut captured = doc.export_root_map_checkpoint(&WINDOW_ROOTS, &mut classifier);
    if classifier.needs_parts {
        // A part's holders are every manifest's in the capture's history:
        // note them all first, then place.
        let mut noting = Classifier::new(owners, None);
        noting.noting = Some(PartHolders::default());
        doc.export_root_map_checkpoint(&WINDOW_ROOTS, &mut noting);
        classifier = Classifier::new(owners, noting.noting);
        captured = doc.export_root_map_checkpoint(&WINDOW_ROOTS, &mut classifier);
    }
    let parts = match captured {
        Capture::Classified(parts) => parts,
        Capture::Unclassified(why) => {
            return Err(classifier.refusal.unwrap_or((None, unsupported(why))));
        }
    };
    let Classifier { plans, homes, .. } = classifier;
    if plans.len() != parts.atoms.len() {
        return Err(not_proved());
    }
    prove(&doc, rows, &slices, &parts, &plans)?;
    Ok(Prepared {
        parts,
        plans,
        homes,
        slices,
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
/// fills back to its stored bytes with every actor, and the all-open join
/// rebuilds the captured document, each row cut from it holding its stored
/// slice, under [`WINDOW_ROUND_TRIP`] fed the join report's verdict.
fn prove(
    doc: &LoroDoc,
    rows: &[LoroIn<'_>],
    slices: &[LoroSlice],
    parts: &Parts,
    plans: &[Plan],
) -> std::result::Result<(), Refusal> {
    for (atom, plan) in parts.atoms.iter().zip(plans) {
        let Payload::Value(LoroValue::Binary(stored)) = &atom.payload else {
            return Err(not_proved());
        };
        let Some(split) = &plan.split else {
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
        let filled = root_fill(&plan.root, &plan.key, &split.no_one, &opened);
        if !distinct || !matches!(filled, Ok(Some(filled)) if filled == stored.as_slice()) {
            return Err(not_proved());
        }
    }
    let joined = LoroDoc::join_root_map_checkpoint(&parts.skeleton, &parts.atoms, &[])
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
    Ok(())
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
        } = self;
        let first = rows
            .first()
            .map(|row| row.at.clone())
            .ok_or_else(bad_part)?;
        let mut slots = Vec::with_capacity(plans.len());
        for (atom, plan) in parts.atoms.iter().zip(plans) {
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
                    dependencies,
                    actors,
                };
                let ordinal = emit(target, copy)?;
                copies.push(SlotCopy { at, atom: ordinal });
            }
            let holes = plan
                .split
                .map(|split| split.actors.into_iter().map(|(field, _)| field).collect())
                .unwrap_or_default();
            slots.push(LoroSlot { copies, holes });
        }
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
        })
    }
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
