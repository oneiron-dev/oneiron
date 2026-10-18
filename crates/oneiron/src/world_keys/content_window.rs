//! The window side of the sealed cloud bundle's world sections (OF-570 (d),
//! FIX 922): what a reader packs from a private world's window, and how a
//! reader takes a section's window back in.
//!
//! The live window of a world flagged device-only never holds the world's rows
//! (reverse rematerialization withholds them), so the reader keeps a second Loro
//! document per sealed window, its mirror, packed with every row of the window.
//! A row deleted here since the last pack resets the mirror. A section carries
//! each mirror whole; taking one in merges it into the mirror as more of the same
//! history and materializes the mirror's rows here. The live window is not
//! touched.

use std::sync::PoisonError;

use loro::{LoroDoc, ValueOrContainer};

use super::content::MIRROR;
use super::refused;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::sync::WindowManager;
use crate::sync::loro_support::{export_snapshot, import_doc};
use crate::sync::types::WindowKey;
use crate::sync::window::{forward_rematerialize, reverse_rematerialize_for_sealing};

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

/// Whether the mirror still carries a row this machine no longer holds.
fn mirror_outlived_rows(vault: &Vault, doc: &LoroDoc) -> Result<bool> {
    let mut carried = Vec::new();
    doc.get_map("entities").for_each(|key, value| {
        if matches!(value, ValueOrContainer::Value(_)) {
            carried.push(key.to_owned());
        }
    });
    for key in carried {
        let Ok(id) = EntityId::from_hex(&key) else {
            return Ok(true);
        };
        if vault.get_raw_unsealed(&id)?.is_none() {
            return Ok(true);
        }
    }
    Ok(false)
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
    /// sealed cloud bundle carries for the window (FIX 922). A mirror that
    /// outlived a row deleted here starts over.
    /// Refused unless this machine may read the world now.
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
        let _sealing = vault
            .world_keys
            .sealing
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (mut mirror, fresh) = load_mirror(vault, world, window)?;
        if !fresh && mirror_outlived_rows(vault, &mirror)? {
            mirror = LoroDoc::new();
        }
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
