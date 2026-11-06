//! KS7-3's port (FIX 5688 KS7-3a): each mixed sync carrier row split by
//! the sync families' own codecs (`crate::sync::checkpoint_payload`), one
//! row at a time as the capture reads it. A row is placed in a capture of
//! its own and folded in only whole, so no carrier is ever half sealed
//! beside a raw copy of itself. A row the sync projection leaves for
//! KS7-3b's Loro projection (a window's snapshot or update, a queued window
//! update) waits until every row is read, then its window splits whole
//! ([`MixedCarrierProjection::project_windows`], FIX 10277): each value copy
//! into its holder's compartment, its history into a carrier the image keeps.
//! A copy the credential client holds stays in the image as it stands, as its
//! dispatched rows do (FIX 10278). A window any of whose copies another
//! custody client holds (a world pad, which the image carries only by
//! reference in a whole window's snapshot; a body; a response), or the image
//! does not take, stays whole under the vault-wide seal, named by its family,
//! as before; its rows are never half split. A restore joins each window from
//! its carrier and the copies that opened, each copy only from the home its
//! capture placed it in ([`restore_window_carriers`], FIX 10283). A restore
//! puts an opened carrier's rows back through
//! the restore-only sink, each from a holder's copy that opened; a row a
//! holder that did not open holds up goes, and nothing else does. The
//! image's rows the port keeps as structure are recounted at a restore as
//! the capture placed them, and one linking to an owner that did not open
//! goes ([`prune_carrier_structure`]).

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};

use super::super::CanonicalRows;
use super::rows::{Class, Client, DbClass, Families, class_for_row, kind_class};
use super::{
    Carrier, ClientCopy, DocumentCarrierRow, Getter, ImageFilter, MixedCarrierProjection,
    StructureCopy, WindowCapture, WindowCarrierRecord, db_name,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_NOTE, entity_type_registry_entry};
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{
    ActorPart, Captured, OpenedOwnerRows, OtherClient, OwnerRef, Restored, RowDb, RowLocator,
    RowPart, Unresolved, bad_part, restore_row_in_txn,
};
use crate::sync::checkpoint_payload::{
    AtomHome, AtomRef, CapturedSyncRow, CapturedSyncRows, KindPlacement, LoroCarrier, OpenedAtom,
    OpenedSyncAtoms, SkeletonRow, SlotCopy, SyncAtom, SyncCarrier, SyncPayloadOwners, SyncSkeleton,
    SyncUnclassified, captured_row_window, project_checkpoint_documents, project_checkpoint_sync,
    project_checkpoint_windows, read_document_basis, restore_checkpoint_documents,
    restore_checkpoint_sync, restore_checkpoint_windows,
};
use crate::sync::selector::RepoCopyAliases;

/// A CLAIM's and a NOTE core's cached copy: their getter places them by
/// more than their kind (a dreamer step's response, an origin claim's
/// actor, a NOTE core's author), which no cached copy repeats.
const PLACED_BY_GETTER: &str = "a kind its own getter places by more than its kind";

/// A row the sync projection leaves for KS7-3b.
const PENDING_LORO: &str = "a window's Loro history, which KS7-3b splits";

/// The port KS7-5 hands [`super::project`] and a restore: the sync
/// families' codecs, and the manifest databases a restore writes through.
pub(in crate::recovery::checkpoint) struct SyncCarriers<'d, D> {
    dbs: &'d D,
    /// The capture's masked repo copy aliases: a copy's rows are placed
    /// under its source (FIX 7608, FIX 10799). Empty unless the capture read
    /// them; a read that fails leaves today's placement.
    aliases: RepoCopyAliases,
}

impl<'d, D: ManifestDbs> SyncCarriers<'d, D> {
    pub(in crate::recovery::checkpoint) fn new(dbs: &'d D) -> Self {
        Self {
            dbs,
            aliases: RepoCopyAliases::default(),
        }
    }

    /// Place a masked copy's rows under its source: `aliases` as the
    /// capture's transaction reads them (`RepoCopyAliases::read_in_txn`).
    pub(in crate::recovery::checkpoint) fn with_copy_aliases(
        mut self,
        aliases: RepoCopyAliases,
    ) -> Self {
        self.aliases = aliases;
        self
    }
}

fn sync_carrier(carrier: Carrier) -> SyncCarrier {
    match carrier {
        Carrier::WindowSnapshot => SyncCarrier::WindowSnapshot,
        Carrier::WindowUpdate => SyncCarrier::WindowUpdate,
        Carrier::ResidenceItem => SyncCarrier::ResidenceItem,
        Carrier::PendingEdit => SyncCarrier::PendingEdit,
        Carrier::PendingNoteOperation => SyncCarrier::PendingNoteOperation,
        Carrier::SyncQueue => SyncCarrier::SyncQueue,
    }
}

/// An entity kind placed as the registry places it ([`super::rows`]); a
/// masked copy's rows under its source.
struct RegistryOwners<'a> {
    aliases: &'a RepoCopyAliases,
}

impl SyncPayloadOwners for RegistryOwners<'_> {
    fn owner_entity(&self, id: EntityId) -> EntityId {
        self.aliases.stored(&id)
    }

    fn entity_kind(&self, entity_type: u8) -> KindPlacement {
        let Some(entry) = entity_type_registry_entry(entity_type) else {
            return KindPlacement::Unclassified(SyncUnclassified::UnknownKind);
        };
        match kind_class(entry.kind) {
            Some(Class::Owner(Getter::Entities))
                if [ENTITY_TYPE_CLAIM, ENTITY_TYPE_NOTE].contains(&entity_type) =>
            {
                KindPlacement::Unclassified(SyncUnclassified::ActorSplit(PLACED_BY_GETTER))
            }
            Some(Class::Owner(Getter::Entities)) => KindPlacement::Owner,
            Some(Class::Other(Client::Dispatch(client))) => KindPlacement::Other(client),
            Some(_) => KindPlacement::Unclassified(SyncUnclassified::NoOwner),
            None => KindPlacement::Unclassified(SyncUnclassified::UnknownKind),
        }
    }
}

/// The receipt's reason for a row the sync projection names.
fn unresolved(reason: SyncUnclassified) -> Unresolved {
    match reason {
        SyncUnclassified::Undecodable => Unresolved::Undecodable,
        SyncUnclassified::UnknownKind => Unresolved::UnknownKind,
        SyncUnclassified::UnknownRoot
        | SyncUnclassified::NoOwner
        | SyncUnclassified::OrphanPart => Unresolved::NoOwner,
        SyncUnclassified::ActorSplit(carrier) => Unresolved::ActorSplit(carrier),
        SyncUnclassified::PendingLoroProjection => Unresolved::ActorSplit(PENDING_LORO),
    }
}

impl<D: ManifestDbs> MixedCarrierProjection for SyncCarriers<'_, D> {
    fn project(
        &self,
        _: &RoTxn<'_>,
        carrier: Carrier,
        key: &[u8],
        value: &[u8],
        out: &mut Captured,
    ) -> Result<bool> {
        let rows = CapturedSyncRows::new(vec![CapturedSyncRow {
            carrier: sync_carrier(carrier),
            key,
            value,
        }]);
        let mut placed = Captured::default();
        let mut atoms = 0_u32;
        let mut emit = |owner: OwnerRef, atom: SyncAtom| -> Result<AtomRef> {
            let ordinal = AtomRef(atoms);
            atoms = atoms
                .checked_add(1)
                .ok_or(Error::InvariantViolation("a sync row split past u32 atoms"))?;
            placed.exact(owner, atom.at.clone(), atom.value);
            for on in atom.dependencies {
                placed.depends(owner, &atom.at, on);
            }
            Ok(ordinal)
        };
        let owners = RegistryOwners {
            aliases: &self.aliases,
        };
        let skeleton = project_checkpoint_sync(&rows, &owners, &mut emit)?;
        for row in skeleton.rows {
            match row {
                SkeletonRow::Sealed { .. } => {}
                SkeletonRow::Structure { at, dependencies } => {
                    placed.structure(at, value.to_vec(), dependencies);
                }
                SkeletonRow::Dispatched { at, client } => {
                    placed.dispatch(client, at, value.to_vec())
                }
                // Not split before KS7-3b: the row stays as it was.
                SkeletonRow::Unclassified {
                    reason: SyncUnclassified::PendingLoroProjection,
                    ..
                } => return Ok(false),
                SkeletonRow::Unclassified { at, owner, reason } => {
                    placed.unclassified(at, owner, unresolved(reason));
                }
            }
        }
        out.merge(placed);
        Ok(true)
    }

    fn restore_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        carrier: Carrier,
        opened: OpenedOwnerRows,
    ) -> Result<Restored> {
        let db = sync_carrier(carrier).db();
        let mut skeleton = SyncSkeleton::default();
        for (ordinal, part) in opened.rows.iter().enumerate() {
            // The port seals whole rows, each in its carrier's database, and
            // a document group's parts, which its own restore joins.
            let at = match part {
                RowPart::Exact { at, .. } => at,
                RowPart::NoActor { at, .. } if at.db == db => continue,
                _ => return Err(bad_part()),
            };
            if at.db != db {
                return Err(bad_part());
            }
            let ordinal = u32::try_from(ordinal).map_err(|_| bad_part())?;
            skeleton.rows.push(SkeletonRow::Sealed {
                at: at.clone(),
                copies: vec![AtomRef(ordinal)],
            });
        }
        let restored = restore_checkpoint_sync(&skeleton, &OpenedParts(&opened))?;
        let documents = restore_checkpoint_documents(sync_carrier(carrier), &opened)?;
        for (at, value) in restored.rows.iter().chain(&documents) {
            restore_row_in_txn(self.dbs, txn, at, value)?;
        }
        Ok(Restored {
            written: restored.rows.len() + documents.len(),
            dropped: restored.dropped,
        })
    }

    fn project_documents(
        &self,
        txn: &RoTxn<'_>,
        filter: &ImageFilter,
        rows: &[DocumentCarrierRow],
        out: &mut BTreeMap<Carrier, Captured>,
    ) -> Result<BTreeSet<usize>> {
        let captured = rows.iter().map(|row| CapturedSyncRow {
            carrier: sync_carrier(row.carrier),
            key: &row.key,
            value: &row.value,
        });
        let captured = CapturedSyncRows::new(captured.collect());
        let carriers: BTreeMap<&[u8], Carrier> = rows
            .iter()
            .map(|row| (row.key.as_slice(), row.carrier))
            .collect();
        let takes = |db: RowDb, key: &[u8], value: &[u8]| filter.takes(db_name(db), key, value);
        let mut basis = |entity: EntityId| read_document_basis(self.dbs, txn, entity, &takes);
        // A group's parts rest at its rows' keys: each goes to that row's
        // carrier, its actors split out beside it.
        let mut emit = |owner: OwnerRef, atom: SyncAtom| -> Result<()> {
            let unnamed = Error::InvariantViolation("a document part names no captured row");
            let carrier = carriers
                .get(atom.at.key.as_slice())
                .copied()
                .ok_or(unnamed)?;
            let held = out.entry(carrier).or_default().owner(owner);
            held.actor_parts.extend(atom.actors);
            held.rows.push(RowPart::NoActor {
                at: atom.at,
                value: atom.value,
            });
            Ok(())
        };
        let owners = RegistryOwners {
            aliases: &self.aliases,
        };
        project_checkpoint_documents(&captured, &owners, &mut basis, &mut emit)
    }

    fn project_windows(
        &self,
        _: &RoTxn<'_>,
        filter: &ImageFilter,
        rows: &[DocumentCarrierRow],
        out: &mut WindowCapture,
    ) -> Result<BTreeSet<usize>> {
        let at_of = |row: &DocumentCarrierRow| {
            RowLocator::row(sync_carrier(row.carrier).db(), row.key.clone())
        };
        let captured = CapturedSyncRows::new(rows.iter().map(captured_row).collect());
        let owners = RegistryOwners {
            aliases: &self.aliases,
        };
        // Every copy is staged under its ordinal until its window proved
        // whole: nothing reaches a compartment before that.
        let mut emitted: Vec<(AtomHome, SyncAtom)> = Vec::new();
        let mut emit = |home: AtomHome, atom: SyncAtom| -> Result<AtomRef> {
            let ordinal = u32::try_from(emitted.len())
                .map_err(|_| Error::InvariantViolation("a window capture past u32 copies"))?;
            emitted.push((home, atom));
            Ok(AtomRef(ordinal))
        };
        let projection = project_checkpoint_windows(&captured, &owners, &mut emit)?;
        let index: BTreeMap<RowLocator, usize> = rows
            .iter()
            .enumerate()
            .map(|(place, row)| (at_of(row), place))
            .collect();
        // A window any of whose carriers holds a copy of a custody client
        // other than the credential client, or a value the image does not
        // take, stays whole, named: its snapshot and its updates alike, so no
        // window is half split.
        let mut whole: BTreeSet<&str> = BTreeSet::new();
        for carrier in &projection.carriers {
            // A joined turn's copy is a copy as a slot's is (FIX 12153).
            for copy in carrier.copies() {
                let (home, atom) = staged(&emitted, copy)?;
                if matches!(home, AtomHome::Client(client) if *client != OtherClient::Credential)
                    || !filter.takes_window_value(&carrier.window, &atom.at, &atom.value)
                {
                    whole.insert(carrier.window.as_str());
                }
            }
        }
        // A window whose rows a projection left unsplit stays whole too.
        let unsplit: BTreeSet<String> = projection
            .unclassified
            .iter()
            .filter_map(|row| match row {
                SkeletonRow::Unclassified { at, .. } => index.get(at).copied(),
                _ => None,
            })
            .filter_map(|place| captured_row_window(&captured_row(&rows[place])))
            .collect();
        let whole: BTreeSet<String> = whole
            .into_iter()
            .map(str::to_owned)
            .chain(unsplit)
            .collect();
        let mut placed = BTreeSet::new();
        for carrier in projection.carriers {
            if whole.contains(&carrier.window) {
                continue;
            }
            let copies: Vec<&SlotCopy> = carrier.copies().collect();
            let mut structure = Vec::new();
            let mut clients = Vec::new();
            for copy in &copies {
                let (home, atom) = staged(&emitted, copy)?;
                match home {
                    AtomHome::Owner(owner) => {
                        let held = out.captured.owner(*owner);
                        held.rows.push(RowPart::Exact {
                            at: atom.at.clone(),
                            value: atom.value.clone(),
                        });
                        held.actor_parts.extend(atom.actors.iter().cloned());
                        for on in &atom.dependencies {
                            out.captured.depends(*owner, &atom.at, *on);
                        }
                    }
                    AtomHome::Structure => structure.push(StructureCopy {
                        atom: copy.atom.0,
                        value: atom.value.clone(),
                    }),
                    // The credential client's copy stays as it stands, under
                    // the image's own seal, as its dispatched rows do (FIX 10278).
                    AtomHome::Client(OtherClient::Credential) => clients.push(ClientCopy {
                        atom: copy.atom.0,
                        value: atom.value.clone(),
                    }),
                    AtomHome::Client(_) => {
                        return Err(Error::InvariantViolation(
                            "a split window holds another client's copy",
                        ));
                    }
                }
            }
            for row in &carrier.rows {
                let place = index
                    .get(&row.at)
                    .copied()
                    .ok_or(Error::InvariantViolation(
                        "a window carrier puts back a row its capture did not read",
                    ))?;
                placed.insert(place);
                out.rows.push(row.at.clone());
            }
            out.records.push(WindowCarrierRecord {
                carrier: carrier.to_bytes()?,
                structure,
                clients,
            });
        }
        Ok(placed)
    }
}

/// The owners the row `key` of the mixed sync family `carrier` holds an id
/// link to as structure, placed by the family's codec as the capture places
/// it: none for a row it seals, dispatches or names. A masked copy's row
/// names the copy: the capture's aliases are not in the image.
fn structure_dependencies(carrier: Carrier, key: &[u8], value: &[u8]) -> Vec<OwnerRef> {
    let rows = CapturedSyncRows::new(vec![CapturedSyncRow {
        carrier: sync_carrier(carrier),
        key,
        value,
    }]);
    let aliases = RepoCopyAliases::default();
    let owners = RegistryOwners { aliases: &aliases };
    // Nothing is sealed here: every atom answers the same ordinal.
    let mut emit = |_: OwnerRef, _: SyncAtom| -> Result<AtomRef> { Ok(AtomRef(0)) };
    let Ok(skeleton) = project_checkpoint_sync(&rows, &owners, &mut emit) else {
        return Vec::new();
    };
    skeleton
        .rows
        .into_iter()
        .flat_map(|row| match row {
            SkeletonRow::Structure { dependencies, .. } => dependencies,
            _ => Vec::new(),
        })
        .collect()
}

/// Takes every row of a mixed sync family out of `databases`, the image a
/// restore lands, that the port keeps as structure linking to one of
/// `gone`, each placed as the capture placed it (FIX 6376): how many went.
/// A family a registry gap holds out stays, as the capture left it.
pub(super) fn prune_carrier_structure(
    databases: &mut BTreeMap<String, CanonicalRows>,
    gone: &BTreeSet<OwnerRef>,
) -> usize {
    let preflight = super::preflight::preflight();
    let families = Families::new();
    let mut pruned = 0;
    for &(name, class) in preflight.databases() {
        if matches!(class, DbClass::Rows(declared) if !matches!(declared, Class::Mixed(_))) {
            continue;
        }
        let Some(rows) = databases.get_mut(name) else {
            continue;
        };
        let before = rows.len();
        rows.retain(|(key, value)| {
            let declared = match class {
                DbClass::Rows(declared) => Some(declared),
                DbClass::Families(db) => families
                    .of(db, key)
                    .filter(|(decl, _)| !preflight.holds_out(decl))
                    .map(|(_, declared)| declared),
            };
            let placed = declared.map(|declared| class_for_row(name, key, value, declared));
            let Some(Class::Mixed(carrier)) = placed else {
                return true;
            };
            !structure_dependencies(carrier, key, value)
                .iter()
                .any(|owner| gone.contains(owner))
        });
        pruned += before - rows.len();
    }
    pruned
}

/// A buffered window row as the sync projection reads it.
fn captured_row(row: &DocumentCarrierRow) -> CapturedSyncRow<'_> {
    CapturedSyncRow {
        carrier: sync_carrier(row.carrier),
        key: &row.key,
        value: &row.value,
    }
}

/// The copy a window capture staged under `copy`'s ordinal.
fn staged<'e>(
    emitted: &'e [(AtomHome, SyncAtom)],
    copy: &SlotCopy,
) -> Result<&'e (AtomHome, SyncAtom)> {
    usize::try_from(copy.atom.0)
        .ok()
        .and_then(|ordinal| emitted.get(ordinal))
        .ok_or(Error::InvariantViolation(
            "a window carrier names a copy its capture did not make",
        ))
}

/// Each split window's rows and markers (FIX 10277): its carrier read back
/// from `records`, joined from the copies `windows` (each opened window
/// bundle, by the owner its compartment authenticated) and the image's
/// structure and other clients' copies hold. A copy whose holder, or an owner it holds only
/// while, is among `unopened` is erased.
///
/// # Errors
///
/// A carrier that does not read back; two copies or bundles under one name;
/// an opened copy that does not read, or that came from a home other than
/// its capture's (FIX 10283).
pub(super) fn restore_window_carriers(
    records: &[WindowCarrierRecord],
    windows: &[OpenedOwnerRows],
    unopened: &BTreeSet<OwnerRef>,
) -> Result<Vec<(RowLocator, Vec<u8>)>> {
    let carriers = records
        .iter()
        .map(|record| LoroCarrier::from_bytes(&record.carrier))
        .collect::<Result<Vec<_>>>()?;
    let mut copies = BTreeMap::new();
    for copy in carriers.iter().flat_map(LoroCarrier::copies) {
        if copies.insert(copy.atom.0, copy).is_some() {
            return Err(bad_part());
        }
    }
    let mut structure = BTreeMap::new();
    for copy in records.iter().flat_map(|record| &record.structure) {
        if structure.insert(copy.atom, copy.value.as_slice()).is_some() {
            return Err(bad_part());
        }
    }
    let mut clients = BTreeMap::new();
    for copy in records.iter().flat_map(|record| &record.clients) {
        if clients.insert(copy.atom, copy.value.as_slice()).is_some() {
            return Err(bad_part());
        }
    }
    let mut owners = BTreeMap::new();
    for rows in windows {
        let owner = OwnerRef {
            subtype: rows.subtype,
            owner32: rows.owner32,
        };
        if owners.insert(owner, rows).is_some() {
            return Err(bad_part());
        }
    }
    let opened = OpenedWindowCopies {
        copies,
        owners,
        structure,
        clients,
        unopened,
    };
    let restored = restore_checkpoint_windows(&carriers, &opened)?;
    let mut rows = restored.rows;
    rows.extend(restored.markers);
    Ok(rows)
}

/// The window copies a restore opened (FIX 10277): an owner's copy from
/// that owner's own opened window bundle at its copy locator, a structure
/// copy or another client's from the image. A copy answers only from the home
/// its carrier names (FIX 10283).
struct OpenedWindowCopies<'o> {
    /// Every copy the carriers name, by ordinal.
    copies: BTreeMap<u32, &'o SlotCopy>,
    /// Each opened window bundle, by the owner its compartment authenticated.
    owners: BTreeMap<OwnerRef, &'o OpenedOwnerRows>,
    /// Each structure copy the image keeps, by ordinal.
    structure: BTreeMap<u32, &'o [u8]>,
    /// Each copy the credential client holds that the image keeps, by
    /// ordinal (FIX 10278).
    clients: BTreeMap<u32, &'o [u8]>,
    /// The owners whose compartments the payload holds that did not open.
    unopened: &'o BTreeSet<OwnerRef>,
}

impl OpenedWindowCopies<'_> {
    /// `copy`'s bytes from its own home, when they are there.
    fn found(&self, atom: AtomRef) -> Option<(AtomHome, &[u8])> {
        let copy = self.copies.get(&atom.0)?;
        match copy.home {
            AtomHome::Owner(owner) => {
                let rows = self.owners.get(&owner)?;
                rows.rows.iter().find_map(|part| match part {
                    RowPart::Exact { at, value } if *at == copy.at => {
                        Some((AtomHome::Owner(owner), value.as_slice()))
                    }
                    _ => None,
                })
            }
            AtomHome::Structure => self
                .structure
                .get(&atom.0)
                .map(|value| (AtomHome::Structure, *value)),
            AtomHome::Client(client) => self
                .clients
                .get(&atom.0)
                .map(|value| (AtomHome::Client(client), *value)),
        }
    }
}

impl OpenedSyncAtoms for OpenedWindowCopies<'_> {
    fn atom(&self, atom: AtomRef) -> OpenedAtom<'_> {
        let Some(copy) = self.copies.get(&atom.0) else {
            return OpenedAtom::Unavailable;
        };
        let erased = |owner: &OwnerRef| self.unopened.contains(owner);
        if copy.dependencies.iter().any(erased)
            || matches!(copy.home, AtomHome::Owner(owner) if erased(&owner))
        {
            return OpenedAtom::Erased;
        }
        match self.found(atom) {
            Some((_, value)) => OpenedAtom::Opened(value),
            None => OpenedAtom::Unavailable,
        }
    }

    fn actor_parts(&self, atom: AtomRef) -> Vec<&ActorPart> {
        let Some(copy) = self.copies.get(&atom.0) else {
            return Vec::new();
        };
        let AtomHome::Owner(owner) = copy.home else {
            return Vec::new();
        };
        self.owners.get(&owner).map_or_else(Vec::new, |rows| {
            rows.actor_parts
                .iter()
                .filter(|part| part.content_locator == copy.at)
                .collect()
        })
    }

    fn opened_home(&self, atom: AtomRef) -> Option<AtomHome> {
        self.found(atom).map(|(home, _)| home)
    }
}

/// One owner's opened rows as the atoms the port emitted, in their order: a
/// row an owner that did not open holds up is unavailable.
struct OpenedParts<'o>(&'o OpenedOwnerRows);

impl OpenedSyncAtoms for OpenedParts<'_> {
    fn atom(&self, atom: AtomRef) -> OpenedAtom<'_> {
        let opened = self.0;
        let part = usize::try_from(atom.0)
            .ok()
            .and_then(|ordinal| opened.rows.get(ordinal));
        let Some(RowPart::Exact { at, value }) = part else {
            return OpenedAtom::Unavailable;
        };
        let held_up = opened
            .dependencies
            .iter()
            .any(|dependency| dependency.at == *at && opened.unavailable.contains(&dependency.on));
        if held_up {
            OpenedAtom::Unavailable
        } else {
            OpenedAtom::Opened(value)
        }
    }
}
