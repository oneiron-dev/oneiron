//! The owner's discard of a world copy, carried into the persisted BASE
//! windows (FIX 14534 part E, Engine 11-06 23:52 E1-E4 = A).
//!
//! The discard takes the world's exclusive rows from LMDB, but a BASE
//! month's document still holds their carriers and history: entity rows,
//! incident edges, births, NOTE carriers and the rest. A Loro delete would
//! sync, and this discard is local. So the window is projected in place:
//! the vendored root-map checkpoint splits the document into its payload
//! free skeleton and one atom per value (`loro::checkpoint`), every atom a
//! discarded row owns is erased, a NOTE bundle that keeps other members is
//! rewritten redacted (`sync::note::discard`), and the join writes each
//! erased value as a delete at its own operation id. No operation is
//! authored; the version vector, frontiers and every other value stay, and
//! the join proves it before anything is written.
//!
//! A projected history differs, at the same operation ids, from the one
//! the owner's other machines hold. So it is installed only while the home,
//! as this device last exchanged with it, holds every operation the window
//! does (E2 = A): the home never takes a rewritten delete for content it
//! still holds. The version vector the projection kept is filed as the
//! window's floor (`SYNC_BASE_WINDOW_DISCARD`), and a send to a home below
//! it waits. A shared value stays whole; what the projection cannot place
//! (a NOTE carrier that does not decode, a root outside the window's maps)
//! defers the window, never counts as erased.

use std::collections::{BTreeMap, BTreeSet};

use heed::RwTxn;
use loro::checkpoint::{Atom, AtomId, Capture, Classify, Field, OwnerId, Payload, Skeleton};
use loro::{LoroDoc, LoroValue, VersionVector};

use super::super::bridge::parse_edge_key;
use super::super::carrier_parts::part_key;
use super::super::checkpoint_payload::{
    Holder, KindPlacement, Placement, SyncPayloadOwners, WINDOW_ROOTS, root_entry,
};
use super::super::loro_support::{doc_from_snapshot, import_doc};
use super::super::note::discard::{NoteAtom, is_note_carrier_map, project_atom, project_current};
use super::super::schema::{ASSET_BODY_REFS_MAP, create_window_doc};
use super::super::types::WindowKey;
use super::super::window_rows::{
    WINDOW_FULL_RESYNC_MARKER, WINDOW_SHALLOW_FENCE, WINDOW_SNAPSHOT, WINDOW_STATE_VECTOR,
    WINDOW_UPDATE, WINDOW_UPDATE_SEQ,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{WindowAddress, WindowDeletionRows};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::store::checkpoint_payload::rows::OwnerRef;

/// A BASE window the owner's discard touched, by its key: a first byte of
/// 1 while its persisted document still waits for its projection, 0 once
/// installed, then the version vector the last projection kept, the floor
/// below which no send of the window goes. Key: window key.
const BASE_WINDOW_DISCARD: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_BASE_WINDOW_DISCARD);

/// The holder of a value that stays.
const KEEP: OwnerId = 0;
/// The holder of a value a discarded row owns.
const ERASE: OwnerId = 1;
/// A part's holder: this plus its key's place in [`DiscardClassifier::parts`].
const PART: OwnerId = 1 << 32;
/// A rewritten value's holder: this plus its place in
/// [`DiscardClassifier::rewrites`].
const REWRITE: OwnerId = 1 << 40;

/// Every entity kind its own row's: the projection asks only who owns a
/// value, never where a checkpoint would seal it.
struct EveryKindOwned;

impl SyncPayloadOwners for EveryKindOwned {
    fn entity_kind(&self, _: u8) -> KindPlacement {
        KindPlacement::Owner
    }
}

/// Which of a window's values the discarded rows own.
struct DiscardClassifier<'a> {
    discarded: &'a BTreeSet<EntityId>,
    owners: BTreeSet<OwnerRef>,
    /// Each part key the capture met, by its place.
    parts: Vec<String>,
    part_places: BTreeMap<String, usize>,
    /// Part keys a manifest that goes names, and ones a manifest that stays
    /// names, across the window's whole history.
    parts_going: BTreeSet<String>,
    parts_staying: BTreeSet<String>,
    rewrites: Vec<Vec<u8>>,
    /// Why the window cannot be projected, once a value names an owner the
    /// projection cannot read.
    unknown: Option<&'static str>,
}

impl<'a> DiscardClassifier<'a> {
    fn new(discarded: &'a BTreeSet<EntityId>) -> Self {
        Self {
            discarded,
            owners: discarded.iter().map(OwnerRef::entity).collect(),
            parts: Vec::new(),
            part_places: BTreeMap::new(),
            parts_going: BTreeSet::new(),
            parts_staying: BTreeSet::new(),
            rewrites: Vec::new(),
            unknown: None,
        }
    }

    fn names_discarded(&self, key: &str) -> bool {
        EntityId::from_hex(key).is_ok_and(|id| id.to_hex() == key && self.discarded.contains(&id))
    }

    /// Whether no holder of a value keeps it: each is a discarded row, or
    /// holds it only while a discarded row stands.
    fn gone(&self, holders: &[Holder]) -> bool {
        !holders.is_empty()
            && holders.iter().all(|holder| {
                self.owners.contains(&holder.owner)
                    || holder
                        .dependencies
                        .iter()
                        .any(|on| self.owners.contains(on))
            })
    }

    fn decide(&mut self, root: &str, key: &str, value: &[u8]) -> OwnerId {
        match root {
            // A deletion's id-only truth stays (call 3).
            "tombstones" => KEEP,
            // A row and every edge it ends are its own, whatever kind
            // carries them (an ASSET row is no sealing owner's).
            "entities" | ASSET_BODY_REFS_MAP => erase(self.names_discarded(key)),
            "edges" => erase(parse_edge_key(key).is_some_and(|(source, _, target)| {
                self.discarded.contains(&source) || self.discarded.contains(&target)
            })),
            map if is_note_carrier_map(map) => self.note_atom(map, key, value),
            _ => self.placed(root_entry(root, key, value, &EveryKindOwned), key),
        }
    }

    /// A NOTE carrier's atom, as its codec projects it.
    fn note_atom(&mut self, map: &str, key: &str, value: &[u8]) -> OwnerId {
        match project_atom(map, key, value, self.discarded) {
            Ok(NoteAtom::Keep) => KEEP,
            Ok(NoteAtom::Drop) => ERASE,
            Ok(NoteAtom::Rewrite(bytes)) => {
                self.rewrites.push(bytes);
                REWRITE + place_of(self.rewrites.len() - 1)
            }
            Err(_) => {
                self.unknown = Some("a NOTE carrier whose owner does not read");
                KEEP
            }
        }
    }

    /// Any other family's value, as its codec places it.
    fn placed(&mut self, placement: Placement, key: &str) -> OwnerId {
        match placement {
            Placement::Owned(holders) | Placement::Split { holders, .. } => {
                erase(self.gone(&holders))
            }
            Placement::Manifest { holders, parts, .. } => {
                let going = self.gone(&holders);
                let named = parts.parts.iter().map(part_key);
                if going {
                    self.parts_going.extend(named);
                } else {
                    self.parts_staying.extend(named);
                }
                erase(going)
            }
            Placement::Part => {
                let place = match self.part_places.get(key) {
                    Some(place) => *place,
                    None => {
                        self.parts.push(key.to_owned());
                        self.part_places
                            .insert(key.to_owned(), self.parts.len() - 1);
                        self.parts.len() - 1
                    }
                };
                PART + place_of(place)
            }
            Placement::Structure { dependencies } => {
                erase(dependencies.iter().any(|on| self.owners.contains(on)))
            }
            Placement::Unclassified { owner, .. } => {
                erase(owner.is_some_and(|owner| self.owners.contains(&owner)))
            }
            Placement::Dispatched(_) => KEEP,
        }
    }
}

/// The holder of a value that goes when `going`, else of one that stays.
fn erase(going: bool) -> OwnerId {
    if going { ERASE } else { KEEP }
}

/// `place` as an owner handle offset: a capture holds far fewer values than
/// a handle's range.
fn place_of(place: usize) -> OwnerId {
    OwnerId::try_from(place).unwrap_or(OwnerId::MAX >> 1)
}

impl Classify for DiscardClassifier<'_> {
    /// The skeleton never leaves this process, so every key may stand in it.
    fn plain_key(&mut self, _: &str, _: &str) -> bool {
        true
    }

    fn holders(&mut self, field: Field<'_>) -> Option<Vec<OwnerId>> {
        let Field::Value {
            root, key, value, ..
        } = field
        else {
            return Some(vec![KEEP]);
        };
        let LoroValue::Binary(bytes) = value else {
            return Some(vec![KEEP]);
        };
        Some(vec![self.decide(root, key, bytes.as_slice())])
    }
}

/// What projecting one window's document came to.
pub(crate) enum Projected {
    /// The document holds nothing the discarded rows own.
    Unchanged,
    /// The projected document's native snapshot bytes, how many values went
    /// and were rewritten, and how many the rows own stay whole for now: each
    /// written by an operation the home does not hold.
    Joined {
        bytes: Vec<u8>,
        erased: usize,
        rewritten: usize,
        waiting: usize,
    },
    /// The document cannot be projected now, and why.
    Deferred(&'static str),
}

/// `doc`, a quiescent window document, with every value the rows in
/// `discarded` own erased at its own operation and every NOTE bundle that
/// keeps other members redacted. No operation is authored. With `held`, the
/// operations the home holds, a value written by any other operation stays
/// whole and counts as waiting (E2 = A): only the home's operations are
/// rewritten.
///
/// # Errors
///
/// A NOTE carrier of the current state that does not decode.
pub(crate) fn project_window_doc(
    doc: &LoroDoc,
    discarded: &BTreeSet<EntityId>,
    held: Option<&VersionVector>,
) -> Result<Projected> {
    if discarded.is_empty() {
        return Ok(Projected::Unchanged);
    }
    let mut classifier = DiscardClassifier::new(discarded);
    let Capture::Classified(parts) = doc.export_root_map_checkpoint(&WINDOW_ROOTS, &mut classifier)
    else {
        return Ok(Projected::Deferred(
            "a window document that is not plain root-map writes of its maps",
        ));
    };
    if let Some(why) = classifier.unknown {
        return Ok(Projected::Deferred(why));
    }
    let unheld = held
        .map(|held| unheld_atoms(&parts.skeleton, held))
        .unwrap_or_default();
    let mut sorted = match classifier.sort(parts.atoms, unheld) {
        Ok(sorted) => sorted,
        Err(why) => return Ok(Projected::Deferred(why)),
    };
    // The current rows of the NOTE maps beyond what each atom's own
    // projection took: a retained NOTE's attachments a departed member
    // alone bound go too, so the window still validates.
    if let Err(why) = sorted.apply_current(&parts.skeleton, project_current(doc, discarded)?) {
        return Ok(Projected::Deferred(why));
    }
    if sorted.erased.is_empty() && sorted.rewritten == 0 {
        return Ok(if sorted.waiting == 0 {
            Projected::Unchanged
        } else {
            Projected::Deferred("values the rows own whose operations the home lacks")
        });
    }
    Ok(sorted.join(&parts.skeleton))
}

/// The atoms `skeleton`'s retained operations write past `held`, and, when
/// `held` does not hold the shallow root itself, each root winner no retained
/// operation writes: a local cut is no proof the home holds what is under it.
fn unheld_atoms(skeleton: &Skeleton, held: &VersionVector) -> BTreeSet<AtomId> {
    let mut unheld = BTreeSet::new();
    let mut retained = BTreeSet::new();
    for change in &skeleton.changes {
        let from = held.get(&change.peer).copied().unwrap_or(0);
        for (index, op) in change.ops.iter().enumerate() {
            let Some(atom) = op.value else {
                continue;
            };
            retained.insert(atom);
            let counter = i32::try_from(index)
                .ok()
                .and_then(|index| change.counter.checked_add(index));
            if counter.is_none_or(|counter| counter >= from) {
                unheld.insert(atom);
            }
        }
    }
    if let Some(shallow) = &skeleton.shallow
        && !shallow
            .vv
            .iter()
            .all(|(peer, end)| held.get(peer).copied().unwrap_or(0) >= *end)
    {
        unheld.extend(
            shallow
                .winners
                .iter()
                .filter_map(|winner| winner.value)
                .filter(|atom| !retained.contains(atom)),
        );
    }
    unheld
}

/// A capture's atoms, sorted: the ones that go, and the ones that stay,
/// some with rewritten values.
struct Sorted {
    erased: BTreeSet<AtomId>,
    available: BTreeMap<AtomId, Atom>,
    rewritten: usize,
    /// Atoms written by operations the home does not hold: they stay whole.
    unheld: BTreeSet<AtomId>,
    /// How many of those the projection would have changed.
    waiting: usize,
}

impl DiscardClassifier<'_> {
    /// Sorts the atoms of this classifier's capture by their holders: a part
    /// goes only when a manifest that goes names it and none that stays does;
    /// an atom in `unheld` stays as it is.
    fn sort(
        &self,
        atoms: Vec<Atom>,
        unheld: BTreeSet<AtomId>,
    ) -> std::result::Result<Sorted, &'static str> {
        let mut sorted = Sorted {
            erased: BTreeSet::new(),
            available: BTreeMap::new(),
            rewritten: 0,
            unheld,
            waiting: 0,
        };
        for mut atom in atoms {
            let holder = match atom.holders.as_slice() {
                [holder] => *holder,
                _ => KEEP,
            };
            let changes = holder == ERASE
                || holder >= REWRITE
                || (holder >= PART && self.part_goes(holder - PART));
            if changes && sorted.unheld.contains(&atom.id) {
                sorted.waiting += 1;
                sorted.available.insert(atom.id, atom);
            } else if holder == ERASE {
                sorted.erased.insert(atom.id);
            } else if holder >= REWRITE {
                let bytes = usize::try_from(holder - REWRITE)
                    .ok()
                    .and_then(|place| self.rewrites.get(place))
                    .ok_or("a rewritten value the projection lost")?;
                atom.payload = Payload::Value(LoroValue::Binary(bytes.clone().into()));
                sorted.rewritten += 1;
                sorted.available.insert(atom.id, atom);
            } else if holder >= PART && self.part_goes(holder - PART) {
                sorted.erased.insert(atom.id);
            } else {
                sorted.available.insert(atom.id, atom);
            }
        }
        Ok(sorted)
    }

    fn part_goes(&self, place: OwnerId) -> bool {
        usize::try_from(place)
            .ok()
            .and_then(|place| self.parts.get(place))
            .is_some_and(|key| self.parts_going.contains(key) && !self.parts_staying.contains(key))
    }
}

impl Sorted {
    /// Applies `changes`, the current NOTE rows to rewrite or erase, to each
    /// row's latest winner in `skeleton`.
    fn apply_current(
        &mut self,
        skeleton: &Skeleton,
        changes: BTreeMap<(&'static str, String), Option<Vec<u8>>>,
    ) -> std::result::Result<(), &'static str> {
        for ((map, key), after) in changes {
            let winner = skeleton.latest.iter().find(|winner| {
                winner.key == key
                    && usize::try_from(winner.root)
                        .ok()
                        .and_then(|root| skeleton.roots.get(root))
                        .is_some_and(|root| root == map)
            });
            let Some(atom) = winner.and_then(|winner| winner.value) else {
                if after.is_some() {
                    return Err("a NOTE row the projection cannot rewrite");
                }
                continue;
            };
            if self.unheld.contains(&atom) {
                self.waiting += 1;
                continue;
            }
            match after {
                Some(bytes) => {
                    let found = self
                        .available
                        .get_mut(&atom)
                        .ok_or("a NOTE row the projection erased")?;
                    found.payload = Payload::Value(LoroValue::Binary(bytes.into()));
                    self.rewritten += 1;
                }
                None => {
                    self.available.remove(&atom);
                    self.erased.insert(atom);
                }
            }
        }
        Ok(())
    }

    /// The native document `skeleton` holds with these atoms, proved.
    fn join(self, skeleton: &Skeleton) -> Projected {
        let available: Vec<Atom> = self.available.into_values().collect();
        let erased: Vec<AtomId> = self.erased.into_iter().collect();
        match LoroDoc::join_root_map_checkpoint(skeleton, &available, &erased) {
            Ok(joined) if joined.report.equivalent => Projected::Joined {
                bytes: joined.bytes,
                erased: erased.len(),
                rewritten: self.rewritten,
                waiting: self.waiting,
            },
            Ok(_) => Projected::Deferred("a projection its join did not prove"),
            Err(error) => {
                tracing::warn!(%error, "a window's discard projection did not join");
                Projected::Deferred("a projection that did not join")
            }
        }
    }
}

/// What installing one window's projection came to.
pub(crate) enum DiscardInstall {
    /// The window holds no persisted state, or nothing the rows own.
    Unchanged,
    /// The projected document replaced the window's persisted state.
    Installed { erased: usize, rewritten: usize },
    /// The window waits, and why.
    Deferred(&'static str),
}

/// Projects the persisted state of BASE window `key`, which the caller
/// holds closed, for every row the owner's discard marks (read once the
/// window is closed, and read again in the write), and installs it: the
/// snapshot replaced by the projected one, its update rows folded in, its
/// version vector unchanged, and the floor filed. Nothing is written unless
/// the home, as this device last exchanged with it, holds every operation
/// the window does, no send of the window is queued, the rows read first
/// are still the window's, and no row the projection took has come back
/// since (a NOTE accepted again as shared clears its mark).
///
/// # Errors
///
/// Store errors, and a stored document or update that does not open.
pub(crate) fn install_discard_projection(vault: &Vault, key: &WindowKey) -> Result<DiscardInstall> {
    let window = key.to_string();
    let address = WindowAddress::new(&window);
    let (discarded, snapshot, updates) = {
        let txn = vault.store.env.read_txn()?;
        let discarded = crate::sync::residence::discarded_rows_in(&vault.store, &txn)?;
        let snapshot = vault
            .store
            .port_window_doc_with_raw(&txn, address, |raw| Ok(raw.to_vec()))?;
        let updates = vault
            .store
            .port_window_updates(&txn, address, |row, bytes| (row, bytes.to_vec()))?
            .collect::<Result<Vec<_>>>()?;
        (discarded, snapshot, updates)
    };
    if snapshot.is_none() && updates.is_empty() {
        return Ok(DiscardInstall::Unchanged);
    }
    let doc = match &snapshot {
        Some(bytes) => doc_from_snapshot(bytes)?,
        None => create_window_doc("local", key),
    };
    for (_, bytes) in &updates {
        import_doc(&doc, bytes)?;
    }
    // Every operation is the home's: the write checks it.
    let (bytes, erased, rewritten) = match project_window_doc(&doc, &discarded, None)? {
        Projected::Unchanged => return Ok(DiscardInstall::Unchanged),
        Projected::Deferred(why) => return Ok(DiscardInstall::Deferred(why)),
        Projected::Joined {
            bytes,
            erased,
            rewritten,
            ..
        } => (bytes, erased, rewritten),
    };
    let held = doc.oplog_vv();
    if doc_from_snapshot(&bytes)?.oplog_vv() != held {
        return Ok(DiscardInstall::Deferred(
            "a projection that moved the window's version",
        ));
    }
    let floor = held.encode();
    let read_keys: BTreeSet<Vec<u8>> = updates
        .iter()
        .map(|(row, _)| WINDOW_UPDATE.key_bytes(row))
        .collect();
    let update_prefix = format!("{window}:");
    let mut deferred = None;
    vault.with_write_txn_grouped(|txn| {
        // The rows read first must still be the window's whole state.
        let current = vault
            .store
            .port_window_doc_with_raw(txn, address, |raw| Ok(raw.to_vec()))?;
        let current_keys: BTreeSet<Vec<u8>> = vault
            .store
            .port_window_updates(txn, address, |row, _| row)?
            .collect::<Result<Vec<_>>>()?
            .iter()
            .map(|row| WINDOW_UPDATE.key_bytes(row))
            .collect();
        if current != snapshot || current_keys != read_keys {
            deferred = Some("a window written since its projection was read");
            return Ok(());
        }
        if !discarded.is_subset(&crate::sync::residence::discarded_rows_in(
            &vault.store,
            txn,
        )?) {
            deferred = Some("a discarded row accepted back since its projection was read");
            return Ok(());
        }
        if !home_holds_in_txn(&vault.store, txn, &window, &held)? {
            deferred = Some("a window whose operations the home does not all hold");
            return Ok(());
        }
        if vault
            .store
            .sync_hooks
            .queued_window_update_count_in_txn(&vault.store, txn, &window)?
            > 0
        {
            deferred = Some("a window with a queued send");
            return Ok(());
        }
        WINDOW_SNAPSHOT.put(&vault.store, txn, &window, &bytes)?;
        WINDOW_STATE_VECTOR.put(&vault.store, txn, &window, &floor)?;
        WINDOW_UPDATE.delete_from(&vault.store, txn, update_prefix.as_bytes())?;
        WINDOW_SHALLOW_FENCE.put(&vault.store, txn, &window, &[1u8])?;
        file_floor_in_txn(&vault.store, txn, &window, &floor)
    })?;
    Ok(match deferred {
        Some(why) => DiscardInstall::Deferred(why),
        None => DiscardInstall::Installed { erased, rewritten },
    })
}

/// Whether the home's version vector of `window`, as this device last
/// exchanged it, holds `held`.
fn home_holds_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    window: &str,
    held: &VersionVector,
) -> Result<bool> {
    Ok(
        crate::sync::residence::home_window_vv_in_txn(store, txn, window)?
            .is_some_and(|home| home.includes_vv(held)),
    )
}

/// Marks BASE window `window` as waiting for its projection, in the write
/// that took rows from it; a floor an earlier projection filed stays.
pub(crate) fn mark_projection_owed_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    window: &str,
) -> Result<()> {
    let key = window.to_owned();
    let mut record = BASE_WINDOW_DISCARD
        .get(store, txn, &key)?
        .filter(|record| !record.is_empty())
        .unwrap_or_else(|| vec![0]);
    if record.first() == Some(&1) {
        return Ok(());
    }
    record[0] = 1;
    BASE_WINDOW_DISCARD.put(store, txn, &key, &record)
}

/// Marks every persisted BASE window as waiting for its projection, in the
/// write that took rows: a row's values ride off its own month too (a review
/// bundle carries the rows of each member NOTE beside every NOTE it holds a
/// member of), so each window is projected once and the pass lets go of the
/// ones that hold nothing the marks own (`forget_unprojected_in_txn`).
pub(crate) fn mark_base_windows_owed_in_txn(store: &Store, txn: &mut RwTxn<'_>) -> Result<()> {
    let mut windows: BTreeSet<String> = WINDOW_SNAPSHOT
        .scan_keys(store, txn, &[])?
        .into_iter()
        .collect();
    windows.extend(WINDOW_UPDATE_SEQ.scan_keys(store, txn, &[])?);
    for window in windows {
        if WindowKey::try_new(&window).is_some_and(|key| key.world().is_none()) {
            mark_projection_owed_in_txn(store, txn, &window)?;
        }
    }
    Ok(())
}

/// Settles BASE window `window`'s owed projection, found to hold nothing the
/// marks own: one no projection ever rewrote is no longer watched, and one
/// with a floor keeps it.
pub(crate) fn forget_unprojected_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    window: &str,
) -> Result<()> {
    let key = window.to_owned();
    match BASE_WINDOW_DISCARD.get(store, txn, &key)? {
        Some(record) if record.len() <= 1 => {
            BASE_WINDOW_DISCARD.delete(store, txn, &key)?;
            Ok(())
        }
        Some(_) => settle_projection_in_txn(store, txn, window),
        None => Ok(()),
    }
}

/// Files `floor` as BASE window `window`'s, its projection installed.
fn file_floor_in_txn(store: &Store, txn: &mut RwTxn<'_>, window: &str, floor: &[u8]) -> Result<()> {
    let mut record = Vec::with_capacity(1 + floor.len());
    record.push(0);
    record.extend_from_slice(floor);
    BASE_WINDOW_DISCARD.put(store, txn, &window.to_owned(), &record)
}

/// Raises BASE window `window`'s floor to hold `part`, operations the home
/// holds that a projection of an arrival rewrote; its owed state stays.
pub(super) fn raise_floor_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    window: &str,
    part: &VersionVector,
) -> Result<()> {
    let key = window.to_owned();
    let record = BASE_WINDOW_DISCARD
        .get(store, txn, &key)?
        .unwrap_or_default();
    let mut floor = record
        .get(1..)
        .and_then(|bytes| VersionVector::decode(bytes).ok())
        .unwrap_or_default();
    floor.merge(part);
    let mut raised = vec![record.first().copied().unwrap_or(0)];
    raised.extend_from_slice(&floor.encode());
    BASE_WINDOW_DISCARD.put(store, txn, &key, &raised)
}

/// Marks for a full resync every BASE window a projection already rewrote,
/// once a row the discard took is accepted back: each holds deletes where
/// the home holds that row's values, and its replacement from the home is
/// projected anew for the rows the discard still marks.
pub(crate) fn resync_projected_windows_in_txn(store: &Store, txn: &mut RwTxn<'_>) -> Result<()> {
    for (window, record) in BASE_WINDOW_DISCARD.scan(store, txn)? {
        if record.len() > 1 {
            WINDOW_FULL_RESYNC_MARKER.put(store, txn, &window, &[1u8])?;
        }
    }
    Ok(())
}

/// Settles BASE window `window`'s owed projection with nothing to install:
/// its floor, if any, stays.
fn settle_projection_in_txn(store: &Store, txn: &mut RwTxn<'_>, window: &str) -> Result<()> {
    let key = window.to_owned();
    if let Some(mut record) = BASE_WINDOW_DISCARD.get(store, txn, &key)?
        && record.first() == Some(&1)
    {
        record[0] = 0;
        BASE_WINDOW_DISCARD.put(store, txn, &key, &record)?;
    }
    Ok(())
}

/// Every BASE window whose projection is owed.
pub(crate) fn owed_projections_in(store: &Store, txn: &heed::RoTxn<'_>) -> Result<Vec<String>> {
    Ok(BASE_WINDOW_DISCARD
        .scan(store, txn)?
        .into_iter()
        .filter(|(_, record)| record.first() == Some(&1))
        .map(|(window, _)| window)
        .collect())
}

/// Whether the owner's discard touched BASE window `window`: its home's
/// version vector is kept beside it from then on.
pub(crate) fn discard_touched_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    window: &str,
) -> Result<bool> {
    BASE_WINDOW_DISCARD.contains(store, txn, &window.to_owned())
}

/// The floor BASE window `window`'s last projection filed: no send of the
/// window goes to a home whose version vector does not hold it.
pub(crate) fn projection_floor_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    window: &str,
) -> Result<Option<VersionVector>> {
    Ok(BASE_WINDOW_DISCARD
        .get(store, txn, &window.to_owned())?
        .and_then(|record| VersionVector::decode(record.get(1..)?).ok())
        .filter(|floor| !floor.is_empty()))
}
