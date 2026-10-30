//! KS7-3's port (FIX 5688 KS7-3a): each mixed sync carrier row split by
//! the sync families' own codecs (`crate::sync::checkpoint_payload`), one
//! row at a time as the capture reads it. A row is placed in a capture of
//! its own and folded in only whole, so no carrier is ever half sealed
//! beside a raw copy of itself. A row the sync projection leaves for
//! KS7-3b's Loro projection (a window's snapshot or update, a queued window
//! update) is not split: it stays under the vault-wide seal, named by its
//! family, as before. A restore puts an opened carrier's rows back through
//! the restore-only sink, each from a holder's copy that opened; a row a
//! holder that did not open holds up goes, and nothing else does. The
//! image's rows the port keeps as structure are recounted at a restore as
//! the capture placed them, and one linking to an owner that did not open
//! goes ([`prune_carrier_structure`]).

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};

use super::super::CanonicalRows;
use super::rows::{Class, Client, DbClass, Families, class_for_row, kind_class};
use super::{Carrier, DocumentCarrierRow, Getter, ImageFilter, MixedCarrierProjection, db_name};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_NOTE, entity_type_registry_entry};
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{
    Captured, OpenedOwnerRows, OwnerRef, Restored, RowDb, RowPart, Unresolved, bad_part,
    restore_row_in_txn,
};
use crate::sync::checkpoint_payload::{
    AtomRef, CapturedSyncRow, CapturedSyncRows, KindPlacement, OpenedAtom, OpenedSyncAtoms,
    SkeletonRow, SyncAtom, SyncCarrier, SyncPayloadOwners, SyncSkeleton, SyncUnclassified,
    project_checkpoint_documents, project_checkpoint_sync, read_document_basis,
    restore_checkpoint_documents, restore_checkpoint_sync,
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
            let class = declared.map(|declared| class_for_row(name, key, value, declared));
            let Some(Class::Mixed(carrier)) = class else {
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
