//! The positive, known-world slice of an automatic physical backup.
//! Unknown or shared placement keeps the existing snapshot behavior.

use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;
#[cfg(feature = "sync")]
use oneiron_store::window_key::WindowKey;

use super::super::{BackupSelection, INDEX_SOURCE_PHONETIC, INDEX_SOURCE_TEXT};
use crate::authority::SealedCopies;
use crate::batch::EntityMetadataHeader;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
#[cfg(feature = "sync")]
use crate::side_table::SideKey;
use crate::store::checkpoint_payload::rows::{Captured, OwnerRef, RowDb, RowLocator};
#[cfg(feature = "sync")]
use crate::store::window_rows::{WINDOW_SNAPSHOT, WINDOW_UPDATE, WindowUpdateKey};
use crate::{EntityId, Result, Vault};

#[derive(Default)]
pub(super) struct Selection {
    entities: BTreeSet<Vec<u8>>,
    worlds: BTreeSet<EntityId>,
    owners: BTreeSet<OwnerRef>,
    rows: BTreeMap<RowDb, BTreeSet<Vec<u8>>>,
}

impl Selection {
    pub(super) fn read(vault: &Vault, txn: &RoTxn<'_>, selection: BackupSelection) -> Result<Self> {
        let mut out = Self::default();
        if selection == BackupSelection::WholeVault {
            return Ok(out);
        }
        let fold = vault.authority_fold_readonly_in_txn(txn)?;
        // A conflicted root's conservative Off is not an owner's resolved Off.
        if fold.vault_root_is_conflicted() {
            return Ok(out);
        }
        for row in vault.store.port_entity_raw_records(txn)? {
            let (entity, raw) = row?;
            if EntityMetadataHeader::parse(&raw)
                .is_some_and(|header| header.entity_type == ENTITY_TYPE_AUTHORITY_LOG)
            {
                continue;
            }
            let carried = crate::settings::carried_worlds_in(&vault.store, txn, &entity)?;
            let off: BTreeSet<_> = carried
                .worlds
                .iter()
                .copied()
                .filter(|world| fold.world_privacy(*world).sealed == SealedCopies::Off)
                .collect();
            out.worlds.extend(off.iter().copied());
            if !carried.unknown && !carried.worlds.is_empty() && off == carried.worlds {
                out.entities.insert(entity.as_bytes().to_vec());
                out.owners.insert(OwnerRef::entity(&entity));
            }
        }
        if !out.owners.is_empty() {
            // Reuse the native head/NOTE marker/birth/fork associations and its
            // shared-owner verdict. A document slot is never an entity guess.
            let documents = crate::entity_doc::checkpoint::capture(&vault.store, txn)?;
            out.document_rows(&documents);
        }
        Ok(out)
    }

    pub(super) fn keeps_owner(&self, owner: OwnerRef) -> bool {
        !self.owners.contains(&owner)
    }

    pub(super) fn takes(&self, database: &str, key: &[u8]) -> bool {
        if database == "entities" && self.entities.contains(key) {
            return false;
        }
        if database == "vault_meta"
            && [
                INDEX_SOURCE_TEXT.decl().prefix,
                INDEX_SOURCE_PHONETIC.decl().prefix,
            ]
            .into_iter()
            .any(|prefix| {
                key.strip_prefix(prefix)
                    .is_some_and(|entity| self.entities.contains(entity))
            })
        {
            return false;
        }
        if super::row_db(database)
            .and_then(|db| self.rows.get(&db))
            .is_some_and(|rows| rows.contains(key))
        {
            return false;
        }
        #[cfg(feature = "sync")]
        if database == "sync_state"
            && window_of(key).is_some_and(|window| {
                window
                    .world()
                    .is_some_and(|world| self.worlds.contains(&world))
            })
        {
            return false;
        }
        true
    }

    /// A whole native document row leaves only when every part belongs to an
    /// excluded entity. A shared proposal retains its other owners' fragments.
    fn document_rows(&mut self, captured: &Captured) {
        let mut excluded = BTreeMap::<(RowDb, Vec<u8>), bool>::new();
        let mut note = |at: &RowLocator, off: bool| {
            excluded
                .entry((at.db, at.key.clone()))
                .and_modify(|all_off| *all_off &= off)
                .or_insert(off);
        };
        for owner in captured.owners() {
            let off = !self.keeps_owner(owner.owner());
            for part in &owner.rows {
                note(part.at(), off);
            }
        }
        for row in &captured.unclassified {
            // This getter's hint comes from the same native slot/fork join,
            // including a known owner's shallow, unsplittable document group.
            note(
                &row.at,
                row.owner.is_some_and(|owner| !self.keeps_owner(owner)),
            );
        }
        for row in &captured.structure {
            note(&row.at, false);
        }
        for row in &captured.dispatched {
            note(&row.at, false);
        }
        for ((db, key), off) in excluded {
            if off {
                self.rows.entry(db).or_default().insert(key);
            }
        }
    }
}

#[cfg(feature = "sync")]
fn window_of(key: &[u8]) -> Option<WindowKey> {
    if let Some(window) = key.strip_prefix(WINDOW_SNAPSHOT.decl().prefix) {
        return WindowKey::try_new(std::str::from_utf8(window).ok()?);
    }
    let update = key.strip_prefix(WINDOW_UPDATE.decl().prefix)?;
    WindowKey::try_new(WindowUpdateKey::decode_key(update)?.window)
}
