//! KS7-3's port (FIX 5688 KS7-3a): each mixed sync carrier row split by
//! the sync families' own codecs (`crate::sync::checkpoint_payload`), one
//! row at a time as the capture reads it. A row is placed in a capture of
//! its own and folded in only whole, so no carrier is ever half sealed
//! beside a raw copy of itself. A row the sync projection leaves for
//! KS7-3b's Loro projection (a window's snapshot or update, a queued window
//! update) is not split: it stays under the vault-wide seal, named by its
//! family, as before. A restore puts an opened carrier's rows back through
//! the restore-only sink, each from a holder's copy that opened; a row a
//! holder that did not open holds up goes, and nothing else does.

use heed::{RoTxn, RwTxn};

use super::rows::{Class, Client, kind_class};
use super::{Carrier, Getter, MixedCarrierProjection};
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_NOTE, entity_type_registry_entry};
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{
    Captured, OpenedOwnerRows, OwnerRef, Restored, RowPart, Unresolved, bad_part,
    restore_row_in_txn,
};
use crate::sync::checkpoint_payload::{
    AtomRef, CapturedSyncRow, CapturedSyncRows, KindPlacement, OpenedAtom, OpenedSyncAtoms,
    SkeletonRow, SyncAtom, SyncCarrier, SyncPayloadOwners, SyncSkeleton, SyncUnclassified,
    project_checkpoint_sync, restore_checkpoint_sync,
};

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
}

impl<'d, D: ManifestDbs> SyncCarriers<'d, D> {
    pub(in crate::recovery::checkpoint) fn new(dbs: &'d D) -> Self {
        Self { dbs }
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

/// An entity kind placed as the registry places it ([`super::rows`]).
struct RegistryOwners;

impl SyncPayloadOwners for RegistryOwners {
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
        let skeleton = project_checkpoint_sync(&rows, &RegistryOwners, &mut emit)?;
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
            // The port seals whole rows only, each in its carrier's database.
            let RowPart::Exact { at, .. } = part else {
                return Err(bad_part());
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
        for (at, value) in &restored.rows {
            restore_row_in_txn(self.dbs, txn, at, value)?;
        }
        Ok(Restored {
            written: restored.rows.len(),
            dropped: restored.dropped,
        })
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
