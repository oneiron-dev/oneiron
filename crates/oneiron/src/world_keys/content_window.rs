//! The window side of the sealed cloud bundle's world sections (OF-570 (d),
//! FIX 922): what a reader packs from a private world's window, and how a
//! reader takes a section's window back in.
//!
//! The live window of a world flagged device-only never holds the world's rows
//! (reverse rematerialization withholds them), so the reader keeps a second Loro
//! document per sealed window, its mirror, packed with every row of the window.
//! The mirror keeps its history: before each pack it takes the window's own
//! deletes here, so a row deleted here leaves every mirror that merges it (FIX
//! 3360). A section carries each mirror whole; taking one in merges it into the
//! mirror as more of the same history and materializes the mirror's rows here.
//! The live window is not touched.

use std::sync::PoisonError;

use loro::LoroDoc;

use super::content::MIRROR;
use super::refused;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncError};
use crate::ports::{WindowAddress, WindowDeletionRows};
use crate::sync::WindowManager;
use crate::sync::loro_support::{
    export_snapshot, import_doc, map_for_each_tombstone_value, map_get_bytes,
};
use crate::sync::schema::create_window_doc;
use crate::sync::types::WindowKey;
use crate::sync::window::{
    apply_pending_window_updates, apply_tombstone_to_window_doc, forward_rematerialize,
    load_window_from_state, reverse_rematerialize_for_sealing,
};

/// Where a mirror's deletes come from.
enum MirrorDelete {
    /// The tombstones the window holds here, live or durable.
    CanonicalWindow,
    /// The window's pending delete intent (`pt:` markers), read, not taken.
    PendingIntent,
}

/// The deletes a mirror takes before each pack (CALLS:
/// SEALED_MIRROR_DELETE_SOURCE): the window's own tombstones here and its
/// pending delete intent, never a row merely missing here.
const SEALED_MIRROR_DELETE_SOURCE: &[MirrorDelete] =
    &[MirrorDelete::CanonicalWindow, MirrorDelete::PendingIntent];

fn mirror_key(world: EntityId, window: &WindowKey) -> String {
    format!("{}:{}", world.to_hex(), window.as_str())
}

/// The window's mirror, or a fresh document (`true`) when it has none.
fn load_mirror(vault: &Vault, world: EntityId, window: &WindowKey) -> Result<(LoroDoc, bool)> {
    let txn = vault.store.env.read_txn()?;
    let doc = LoroDoc::new();
    match MIRROR.get(&vault.store, &txn, &mirror_key(world, window))? {
        Some(snapshot) => {
            import_doc(&doc, &snapshot)?;
            Ok((doc, false))
        }
        None => Ok((doc, true)),
    }
}

fn store_mirror(vault: &Vault, world: EntityId, window: &WindowKey, doc: &LoroDoc) -> Result<()> {
    let snapshot = export_snapshot(doc)?;
    vault.with_write_txn_grouped(|wtxn| {
        MIRROR.put(&vault.store, wtxn, &mirror_key(world, window), &snapshot)
    })
}

/// Pushes each tombstone `doc` holds onto `deletes`, as its id and raw value.
fn push_tombstones(doc: &LoroDoc, deletes: &mut Vec<(EntityId, Vec<u8>)>) {
    map_for_each_tombstone_value(&doc.get_map("tombstones"), |key, raw| {
        if let Ok(id) = EntityId::from_hex(key) {
            deletes.push((id, raw.to_vec()));
        }
    });
}

/// Each tombstone of `window` here, from [`SEALED_MIRROR_DELETE_SOURCE`], as
/// its id and raw value. Persists nothing.
fn window_deletes(manager: &WindowManager, window: &WindowKey) -> Result<Vec<(EntityId, Vec<u8>)>> {
    let vault = manager.vault();
    let mut deletes = Vec::new();
    for source in SEALED_MIRROR_DELETE_SOURCE {
        match source {
            MirrorDelete::CanonicalWindow => match manager.window(window) {
                Some(live) => push_tombstones(&live.doc, &mut deletes),
                None => match load_window_from_state(vault, "", window) {
                    Ok(doc) => push_tombstones(&doc, &mut deletes),
                    Err(Error::Sync(SyncError::WindowNotFound { .. })) => {
                        let doc = create_window_doc("", window);
                        apply_pending_window_updates(vault, &doc, window)?;
                        push_tombstones(&doc, &mut deletes);
                    }
                    Err(error) => return Err(error),
                },
            },
            MirrorDelete::PendingIntent => {
                let txn = vault.store.env.read_txn()?;
                let address = WindowAddress::new(window.as_str());
                // A marker that does not decode stays for the window's own replay.
                for marker in vault
                    .store
                    .port_pending_tombstones_in_window(&txn, address)?
                    .flatten()
                {
                    deletes.push((marker.id, marker.raw));
                }
            }
        }
    }
    Ok(deletes)
}

impl WindowManager {
    /// Materializes the rows of `window`'s mirror here, on a machine that may
    /// read `world` now: the bundle sections an opened-item machine took in
    /// while the window stood unpromoted. Returns whether it read a mirror.
    pub fn materialize_sealed_mirror(&self, world: EntityId, window: &WindowKey) -> Result<bool> {
        if window.world() != Some(world) {
            return Err(refused("the window is not one of the world's"));
        }
        let vault = self.vault();
        if vault.world_key(world).is_err() {
            return Ok(false);
        }
        let _sealing = vault
            .world_keys
            .sealing
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (mirror, fresh) = load_mirror(vault, world, window)?;
        if fresh {
            return Ok(false);
        }
        forward_rematerialize(vault, &mirror, self.materializer(), window)?;
        Ok(true)
    }

    /// The whole mirror of `window` of the private `world`, packed with every
    /// row of the window here, as one snapshot: what the world's section of the
    /// sealed cloud bundle carries for the window (FIX 922). The mirror keeps
    /// its history and first takes each delete [`SEALED_MIRROR_DELETE_SOURCE`]
    /// names. Refused unless this machine may read the world now.
    pub(crate) fn sealed_mirror_snapshot(
        &self,
        world: EntityId,
        window: &WindowKey,
    ) -> Result<Vec<u8>> {
        if window.world() != Some(world) {
            return Err(refused("the window is not one of the world's"));
        }
        let vault = self.vault();
        vault.world_key(world)?;
        let deletes = window_deletes(self, window)?;
        let _sealing = vault
            .world_keys
            .sealing
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (mirror, _) = load_mirror(vault, world, window)?;
        // A delete reaches a taker's mirror as one, where a mirror started
        // over would merge with it as a union (FIX 3360).
        let tombstones = mirror.get_map("tombstones");
        let entities = mirror.get_map("entities");
        for (id, raw) in &deletes {
            let key = id.to_hex();
            if map_get_bytes(&tombstones, &key).as_deref() == Some(raw.as_slice())
                && entities.get(&key).is_none()
            {
                continue;
            }
            apply_tombstone_to_window_doc(&mirror, id, raw)?;
        }
        mirror.commit();
        reverse_rematerialize_for_sealing(vault, &mirror, window)?;
        let snapshot = export_snapshot(&mirror)?;
        vault.with_write_txn_grouped(|wtxn| {
            MIRROR.put(&vault.store, wtxn, &mirror_key(world, window), &snapshot)
        })?;
        Ok(snapshot)
    }

    /// Takes a bundle's `snapshot` of `window` of `world` into the window's
    /// mirror, on a machine that may read the world now: merged as more of the
    /// same history, never in place of it, so a mirror here that already holds
    /// all of it stays as it is. With `materialize` the mirror's rows land here
    /// too; without, they wait in the mirror for a promotion
    /// ([`Self::materialize_sealed_mirror`]). Returns whether the mirror took
    /// anything new.
    pub(crate) fn merge_bundle_mirror(
        &self,
        world: EntityId,
        window: &WindowKey,
        snapshot: &[u8],
        materialize: bool,
    ) -> Result<bool> {
        if window.world() != Some(world) {
            return Err(refused("the window is not one of the world's"));
        }
        let vault = self.vault();
        vault.world_key(world)?;
        let incoming = LoroDoc::new();
        import_doc(&incoming, snapshot)?;
        let _sealing = vault
            .world_keys
            .sealing
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (mirror, fresh) = load_mirror(vault, world, window)?;
        let mirror = if fresh {
            incoming
        } else if mirror.oplog_vv().includes_vv(&incoming.oplog_vv()) {
            return Ok(false);
        } else {
            import_doc(&mirror, snapshot)?;
            mirror
        };
        if materialize {
            forward_rematerialize(vault, &mirror, self.materializer(), window)?;
        }
        store_mirror(vault, world, window, &mirror)?;
        Ok(true)
    }
}
