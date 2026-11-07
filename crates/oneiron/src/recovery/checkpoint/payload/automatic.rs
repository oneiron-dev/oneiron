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
                #[cfg(feature = "sync")]
                if let Some(keys) = crate::sync::residence::checkpoint_read_cache_keys(
                    &vault.store,
                    txn,
                    entity,
                    &raw,
                )? {
                    out.rows.entry(RowDb::SyncState).or_default().extend(
                        keys.into_iter()
                            .chain([format!("ri:s:{}", entity.to_hex())])
                            .map(String::into_bytes),
                    );
                }
            }
        }
        #[cfg(feature = "sync")]
        for row in vault.store.sync_state.prefix_iter(txn, "ri:s:")? {
            let (key, value) = row?;
            let Some(item) = key.strip_prefix("ri:s:").and_then(|hex| {
                EntityId::from_hex(hex)
                    .ok()
                    .filter(|item| item.to_hex() == hex)
            }) else {
                continue;
            };
            let Some(worlds) = crate::sync::residence::CachedItemWorlds::decode(&value) else {
                continue;
            };
            if worlds.worlds().is_empty()
                || !worlds
                    .worlds()
                    .iter()
                    .all(|world| fold.world_privacy(*world).sealed == SealedCopies::Off)
            {
                continue;
            }
            let Some(blob) = vault
                .store
                .sync_state
                .get(txn, &format!("ri:b:{}", item.to_hex()))?
            else {
                continue;
            };
            let Some(document) = vault
                .store
                .sync_state
                .get(txn, &format!("ri:d:{}", item.to_hex()))?
            else {
                continue;
            };
            if !worlds.matches(item, &blob, &document) {
                continue;
            }
            if let Some(keys) =
                crate::sync::residence::checkpoint_read_cache_keys(&vault.store, txn, item, &blob)?
            {
                out.worlds.extend(worlds.worlds().iter().copied());
                out.rows.entry(RowDb::SyncState).or_default().extend(
                    keys.into_iter()
                        .chain([key.into_owned()])
                        .map(String::into_bytes),
                );
            }
        }
        if !out.owners.is_empty() {
            // Reuse the native head/NOTE marker/birth/fork associations and its
            // shared-owner verdict. A document slot is never an entity guess.
            let documents = crate::entity_doc::checkpoint::capture(&vault.store, txn)?;
            out.captured_rows(&documents, |_| true);

            // The native body getter binds each occurrence part to the
            // record that actually holds it, not to its shared digest.
            let bodies = crate::provenance::body::checkpoint::capture(&vault.store, txn)?;
            for owner in bodies.owners() {
                if !owner.rows.is_empty()
                    && owner.rows.iter().all(|part| {
                        owner.dependencies.iter().any(|dependency| {
                            dependency.at == *part.at() && !out.keeps_owner(dependency.on)
                        })
                    })
                {
                    out.owners.insert(owner.owner());
                }
            }
            out.captured_rows(&bodies, |_| true);
            for getter in [
                super::Getter::Note,
                super::Getter::TypedBody,
                super::Getter::OfficeBody,
                super::Getter::BlobArtifact,
                super::Getter::EmbedMedia,
                super::Getter::Codebase,
                super::Getter::EntityRevision,
                super::Getter::ProvenanceBirth,
            ] {
                out.captured_rows(&getter.capture(&vault.store, txn)?, |at| {
                    [
                        &crate::side_table::NOTE_HEAD,
                        &crate::side_table::NOTE_HEAD_DOC,
                        &crate::side_table::NOTE_OVERRIDE,
                        &crate::side_table::TYPED_BODY_HEAD,
                        &crate::side_table::TYPED_BODY_DOC,
                        &crate::side_table::OFFICE_BODY_HEAD,
                        &crate::side_table::BLOB_ARTIFACT_HEAD,
                        &crate::side_table::EMBEDDING_MEDIA_VECTOR,
                        &crate::side_table::EMBEDDING_MEDIA_DEVICE,
                        &crate::side_table::CODEBASE_SNAPSHOT,
                        &crate::side_table::ENTITY_REVISION_STATE,
                        &crate::side_table::ENTITY_REVISION_DOC,
                        &crate::side_table::ENTITY_REVISION_FRONTIER,
                        &crate::side_table::ENTITY_REVISION_IDENTITY,
                        &crate::side_table::PROVENANCE_ROW_BIRTH,
                        &crate::side_table::PROVENANCE_BIRTH_BY_TRIGGER,
                    ]
                    .into_iter()
                    .any(|decl| at.in_table(decl))
                });
            }
        }
        #[cfg(feature = "sync")]
        out.queue_rows(&vault.store, txn)?;
        Ok(out)
    }

    #[cfg(feature = "sync")]
    fn queue_rows(&mut self, store: &crate::store::Store, txn: &RoTxn<'_>) -> Result<()> {
        if self.worlds.is_empty() {
            return Ok(());
        }
        for row in store.sync_queue.iter(txn)? {
            let (key, value) = row?;
            let Some((window, has_sidecar)) =
                crate::sync::queue::checkpoint_update_window(store, txn, &key, &value)?
            else {
                continue;
            };
            // Pending deletes must still replay after restore. Keep the entire
            // pair, including an undecodable sidecar, until its own projection.
            if has_sidecar {
                continue;
            }
            if WindowKey::try_new(window)
                .and_then(|window| window.world())
                .is_some_and(|world| self.worlds.contains(&world))
            {
                self.rows
                    .entry(RowDb::SyncQueue)
                    .or_default()
                    .insert(key.to_vec());
            }
        }
        Ok(())
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

    /// A whole native row leaves only when every part belongs to an excluded
    /// owner. A shared row retains its other owners' fragments.
    fn captured_rows(&mut self, captured: &Captured, includes: impl Fn(&RowLocator) -> bool) {
        let mut excluded = BTreeMap::<(RowDb, Vec<u8>), bool>::new();
        let mut note = |at: &RowLocator, off: bool| {
            if !includes(at) {
                return;
            }
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
            // Only the getter's native owner hint can exclude an unsplittable
            // row. An unknown owner leaves the raw row in the image.
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
