//! The window side of the sealed cloud bundle's world sections (OF-570 (d),
//! FIX 922): what a reader packs from a private world's window, and how a
//! reader takes a section's window back in.
//!
//! The live window of a world flagged device-only packs its own world's rows
//! for live readers (reverse rematerialization withholds them from the other
//! windows), and the reader keeps a second Loro document per sealed window,
//! its mirror, packed with every row of the window: the mirror is what a
//! section's packets continue.
//! The mirror keeps its history: before each pack it takes the window's own
//! deletes here, so a row deleted here leaves every mirror that merges it (FIX
//! 3360). A section carries each mirror whole; taking one in merges it into the
//! mirror as more of the same history and materializes the mirror's rows here.
//! The live window is not touched. A take of a mirror whose rows already
//! landed at its version skips that pass (`content_landed`, FIX 5506).

use std::sync::PoisonError;

use loro::LoroDoc;

use super::content::MIRROR;
use super::content_landed::{landed_already, landed_mark, mark_landed_in_txn, repair_pending};
use super::refused;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncError};
use crate::ports::{WindowAddress, WindowDeletionRows};
use crate::store::legal_hold::HoldActor;
use crate::store::loro_document::{
    export_snapshot, import_doc, map_for_each_tombstone_value, map_get_bytes,
};
use crate::sync::WindowManager;
use crate::sync::carrier_holds::CarrierInventory;
use crate::sync::schema::create_window_doc;
use crate::sync::window::{
    apply_pending_window_updates, apply_tombstone_to_window_doc, export_sealed_mirror_snapshot,
    forward_rematerialize_mirror, load_window_from_state, replace_detached_mirror,
    require_history_free_window, reverse_rematerialize_for_sealing, strict_window_cut,
};
use crate::sync::window_rows::HISTORY_FREE_WINDOW;
use crate::window_key::WindowKey;

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
    let (doc, held) = load_mirror_with_bytes(vault, world, window)?;
    Ok((doc, held.is_none()))
}

/// The window's mirror, or a fresh document, with the bytes it was read from
/// (`None` when it has none).
fn load_mirror_with_bytes(
    vault: &Vault,
    world: EntityId,
    window: &WindowKey,
) -> Result<(LoroDoc, Option<Vec<u8>>)> {
    let txn = vault.store.env.read_txn()?;
    let doc = LoroDoc::new();
    let held = MIRROR.get(&vault.store, &txn, &mirror_key(world, window))?;
    if let Some(snapshot) = &held {
        import_doc(&doc, snapshot)?;
    }
    Ok((doc, held))
}

fn store_mirror(vault: &Vault, world: EntityId, window: &WindowKey, doc: &LoroDoc) -> Result<()> {
    let snapshot = export_snapshot(doc)?;
    vault.with_write_txn_grouped(|wtxn| {
        MIRROR.put(&vault.store, wtxn, &mirror_key(world, window), &snapshot)
    })
}

impl WindowManager {
    /// Lands the rows of `window`'s `mirror` here, unless they landed at its
    /// version already and the merge `gained` nothing (FIX 5506): the
    /// forward pass first, then, in one transaction, the mirror when it
    /// gained, and the mark of its version when the pass left no repair
    /// pending and no removal came since. Run under the sealing lock.
    fn land_mirror(
        &self,
        world: EntityId,
        window: &WindowKey,
        mirror: &LoroDoc,
        gained: bool,
    ) -> Result<()> {
        let vault = self.vault();
        let before = landed_mark(vault, world, window)?;
        if landed_already(vault, window, before.as_ref(), mirror, gained)? {
            return Ok(());
        }
        // Only the markers of rows this pass rematerialized settle (FIX 538).
        forward_rematerialize_mirror(vault, mirror, self.materializer(), window)?;
        let snapshot = gained.then(|| export_snapshot(mirror)).transpose()?;
        let settled = !repair_pending(vault, window)?;
        vault.with_write_txn_grouped(|wtxn| {
            if let Some(snapshot) = &snapshot {
                MIRROR.put(&vault.store, wtxn, &mirror_key(world, window), snapshot)?;
            }
            if settled {
                mark_landed_in_txn(&vault.store, wtxn, (world, window), before.as_ref(), mirror)?;
            }
            Ok(())
        })
    }
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
        self.land_mirror(world, window, &mirror, false)?;
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
        let (mirror, held) = load_mirror_with_bytes(vault, world, window)?;
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
        // The export scrubs and the history check, as any export (FIX
        // 17210): a revision, birth or fact the scrubs took out never rides
        // the mirror's history, and the mirror kept here is the one shipped.
        let shipped = export_sealed_mirror_snapshot(vault, window, &mirror)?;
        // A checked snapshot may root later than the mirror: what keeping it
        // would destroy, read before the writer (OF-470).
        let destroyed = shipped
            .checked
            .then(|| CarrierInventory::of_window(&mirror));
        vault.with_write_txn_grouped(|wtxn| {
            let key = mirror_key(world, window);
            // An actor erase rewrites the mirrors in its own writer, without
            // this lock (`rewrite_mirrors_in_txn`), and a world's erase purges
            // them: a mirror changed since this seal read it stays as that
            // writer left it, and this seal ships nothing.
            if MIRROR.get(&vault.store, wtxn, &key)? != held {
                return Err(refused("the sealed mirror changed while it was sealed"));
            }
            // An actor erased since the scrubs ran: a revision naming it is
            // never kept or shipped.
            if crate::sync::source_audiences::carries_erased_actor_in(vault, wtxn, &mirror)? {
                return Err(refused("an actor was erased while the mirror was sealed"));
            }
            // A legal hold keeps every row it names (OF-470): while one
            // stands over what the cut drops, the mirror is kept whole and
            // only the checked snapshot ships.
            let held_rows = match &destroyed {
                Some(destroyed) => destroyed
                    .reject_held_in_txn(&vault.store, wtxn, &HoldActor::TIMER)
                    .is_err(),
                None => false,
            };
            if held_rows {
                MIRROR.put(&vault.store, wtxn, &key, &export_snapshot(&mirror)?)
            } else {
                MIRROR.put(&vault.store, wtxn, &key, &shipped.bytes)
            }
        })?;
        Ok(shipped.bytes)
    }

    /// Takes a bundle's `snapshot` of `window` of `world` into the window's
    /// mirror, on a machine that may read the world now: merged as more of the
    /// same history, never in place of it, so a mirror here that already holds
    /// all of it stays as it is. With `materialize` the mirror's rows land here
    /// too, a mirror that held it all already included (FIX 4788), unless they
    /// landed at that version before and nothing removed them since (FIX
    /// 5506); without, they wait in the mirror for a promotion
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
        // What the merge brought: its history past here is read for an
        // erased actor below.
        let before = if fresh {
            incoming.shallow_since_vv().to_vv()
        } else {
            mirror.oplog_vv()
        };
        let (mirror, gained) = if fresh {
            (incoming, true)
        } else if mirror.oplog_vv().includes_vv(&incoming.oplog_vv()) {
            (mirror, false)
        } else if mirror
            .import(snapshot)
            .is_ok_and(|status| status.pending.is_none())
        {
            (mirror, true)
        } else {
            // A mirror cut history-free (FIX 17210) does not merge into one
            // that lacks its root: it takes this mirror's place, with what
            // this one holds that it does not written back on top. The
            // mirror the failed import touched is read again first. A legal
            // hold over what this mirror holds keeps it as it is (OF-470).
            let (old, _) = load_mirror(vault, world, window)?;
            {
                let rtxn = vault.store.env.read_txn()?;
                CarrierInventory::of_window(&old).reject_held_in_txn(
                    &vault.store,
                    &rtxn,
                    &HoldActor::TIMER,
                )?;
            }
            let (candidate, lost) = replace_detached_mirror(vault, &old, snapshot)?;
            if lost > 0 {
                tracing::warn!(
                    window = %window.as_str(),
                    lost,
                    "a sealed mirror's replacement kept the bundle's value of keys this mirror changed"
                );
            }
            (candidate, true)
        };
        // A revision naming an actor this vault erased that came in with it
        // pins the window history-free: the mirror's seals then check what
        // they ship (FIX 17210).
        if gained {
            let from = if mirror.oplog_vv().includes_vv(&before)
                && before.includes_vv(&mirror.shallow_since_vv().to_vv())
            {
                before
            } else {
                mirror.shallow_since_vv().to_vv()
            };
            let named = {
                let rtxn = vault.store.env.read_txn()?;
                crate::sync::source_audiences::history_names_erased_actor_in(
                    vault, &rtxn, &mirror, &from,
                )?
            };
            if named {
                require_history_free_window(vault, window)?;
            }
        }
        if materialize {
            self.land_mirror(world, window, &mirror, gained)?;
        } else if gained {
            store_mirror(vault, world, window, &mirror)?;
        }
        Ok(gained)
    }
}

/// Rewrites, in an actor erase's write transaction `wtxn`, each sealed mirror
/// this vault keeps (FIX 17210): a mirror is a second document of its window,
/// which no scan of the stored windows reads. Each is rebuilt from its stored
/// bytes, and `rewrite` edits it and answers whether it must go history-free
/// (it edited the mirror, or the mirror's history or shallow root holds what
/// it would have taken out). Such a mirror is kept cut at its one head, so no
/// history behind it holds what went; its next take lands it again, as its
/// version moved. A mirror whose bytes do not rebuild is left for its next
/// seal, which checks its history before anything of it ships.
///
/// # Errors
///
/// Storage failures, and `rewrite`'s.
pub(crate) fn rewrite_mirrors_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    mut rewrite: impl FnMut(&mut heed::RwTxn<'_>, &LoroDoc) -> Result<bool>,
) -> Result<()> {
    for key in MIRROR.scan_keys(&vault.store, wtxn, b"")? {
        let Some(snapshot) = MIRROR.get(&vault.store, wtxn, &key)? else {
            continue;
        };
        let doc = LoroDoc::new();
        if let Err(error) = import_doc(&doc, &snapshot) {
            tracing::warn!(
                mirror = %key,
                %error,
                "an erased actor's carriers: a sealed mirror does not rebuild; its next seal checks it"
            );
            continue;
        }
        if !rewrite(&mut *wtxn, &doc)? {
            continue;
        }
        // A legal hold keeps every row it names (OF-470): while one stands
        // over what the cut drops, the mirror keeps its history and its
        // window is pinned history-free, so its seals check what they ship.
        let held = CarrierInventory::of_window(&doc)
            .reject_held_in_txn(&vault.store, wtxn, &HoldActor::UNATTRIBUTED.privacy(true))
            .is_err();
        let bytes = if held {
            if let Some((_, label)) = key.split_once(':') {
                HISTORY_FREE_WINDOW.put(&vault.store, wtxn, &label.to_owned(), &[1u8])?;
            }
            export_snapshot(&doc)?
        } else {
            // No observer watches the mirror: the barrier reaches no window.
            strict_window_cut(&doc)?.bytes
        };
        MIRROR.put(&vault.store, wtxn, &key, &bytes)?;
    }
    Ok(())
}
