//! The window side of sealed world content: what a reader seals from a private
//! world's window, and how a reader takes a packet back in (OF-570 (d)).
//!
//! The live window of a world flagged device-only never holds the world's rows
//! (reverse rematerialization withholds them), so the reader keeps a second Loro
//! document per sealed window, its mirror, packed with every row of the window.
//! Packets continue the mirror's history: an update since the version vector a
//! holder states, or a replacement when the holder's vector is not one the mirror
//! covers. A row deleted here since the last packet resets the mirror, and the next
//! packet is a replacement without it; the packets it replaces age out (`content`).
//!
//! Taking a packet in opens it with the world's key, merges it into the mirror and
//! materializes the mirror's rows here. The live window is not touched.

use std::sync::PoisonError;

use loro::{LoroDoc, ValueOrContainer, VersionVector};

use super::content::{
    MIRROR, SealedContentBinding, SealedContentId, SealedContentKind, SealedResidenceContent,
};
use super::refused;
use crate::Vault;
use crate::authority::{Destination, EffectiveRead};
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncError};
use crate::sync::WindowManager;
use crate::sync::loro_support::{
    doc_version_vector, export_snapshot, export_updates_from, import_doc,
};
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

fn decode_vv(bytes: &[u8]) -> Result<VersionVector> {
    VersionVector::decode(bytes).map_err(|source| {
        Error::Sync(SyncError::CrdtDecodeError {
            context: "decode sealed version vector",
            source,
        })
    })
}

impl WindowManager {
    /// Seals `window` of the private `world` on a machine that may read it, for a
    /// holder that may not. `since` is the holder's encoded Loro version vector;
    /// `None`, or one the mirror does not cover, gets a replacement. Refused unless
    /// this machine may read the world and its sealed copies are not off.
    pub fn export_sealed_residence_content(
        &self,
        world: EntityId,
        window: &WindowKey,
        since: Option<&[u8]>,
    ) -> Result<SealedResidenceContent> {
        if window.world() != Some(world) {
            return Err(refused("the window is not one of the world's"));
        }
        let vault = self.vault();
        vault.require_sealed_copies(world)?;
        let sealer = vault.world_content_sealer(world)?;
        let _sealing = vault
            .world_keys
            .sealing
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (mut mirror, mut fresh) = load_mirror(vault, world, window)?;
        if !fresh && mirror_outlived_rows(vault, &mirror)? {
            mirror = LoroDoc::new();
            fresh = true;
        }
        reverse_rematerialize_for_sealing(vault, &mirror, window)?;
        let to = doc_version_vector(&mirror);
        let covered = match since {
            Some(since) if !fresh => {
                let remote = decode_vv(since)?;
                mirror
                    .oplog_vv()
                    .includes_vv(&remote)
                    .then_some((since, remote))
            }
            _ => None,
        };
        let packet = match covered {
            Some((since, remote)) => sealer.seal(
                window.as_str(),
                SealedContentKind::Update,
                since,
                &to,
                &export_updates_from(&mirror, &remote)?,
            )?,
            None => sealer.seal(
                window.as_str(),
                SealedContentKind::Replacement,
                &[],
                &to,
                &export_snapshot(&mirror)?,
            )?,
        };
        store_mirror(vault, world, window, &mirror)?;
        Ok(packet)
    }

    /// Takes a sealed packet of `window` of `world` back in on a machine that may
    /// read the world now: opens it, merges it into the window's mirror (a
    /// replacement takes the mirror's place) and materializes the mirror's rows
    /// here. An update whose base this machine does not hold is refused; ask for a
    /// replacement. Returns what the packet was bound to.
    pub fn import_sealed_residence_content(
        &self,
        world: EntityId,
        window: &WindowKey,
        packet: &SealedResidenceContent,
    ) -> Result<SealedContentBinding> {
        if window.world() != Some(world) {
            return Err(refused("the window is not one of the world's"));
        }
        let vault = self.vault();
        let opened = vault.open_world_content(world, window.as_str(), packet)?;
        let _sealing = vault
            .world_keys
            .sealing
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mirror = match opened.binding.kind {
            SealedContentKind::Replacement => {
                let doc = LoroDoc::new();
                import_doc(&doc, &opened.payload)?;
                doc
            }
            SealedContentKind::Update => {
                let (doc, _) = load_mirror(vault, world, window)?;
                let status = doc.import(&opened.payload).map_err(|source| {
                    Error::Sync(SyncError::CrdtDecodeError {
                        context: "import sealed update",
                        source,
                    })
                })?;
                if status.pending.is_some() {
                    return Err(refused(
                        "the sealed update needs content this machine does not hold",
                    ));
                }
                doc
            }
        };
        forward_rematerialize(vault, &mirror, self.materializer(), window)?;
        store_mirror(vault, world, window, &mirror)?;
        Ok(opened.binding)
    }

    /// This machine's sealing-mirror version vector for `window`, encoded:
    /// the `since` a sealed request states. Empty of operations when the
    /// window has no mirror yet.
    pub fn sealed_mirror_version_vector(
        &self,
        world: EntityId,
        window: &WindowKey,
    ) -> Result<Vec<u8>> {
        let (mirror, _) = load_mirror(self.vault(), world, window)?;
        Ok(doc_version_vector(&mirror))
    }

    /// A sealed packet of `window` for `destination`, or `None` when this
    /// machine seals nothing for it: the world reads everywhere (its rows
    /// travel readable), the destination may neither read the world nor
    /// hold a sealed copy, or this machine may not read the world itself
    /// (its shelved packets forward through
    /// [`Vault::sealed_window_packets`] instead).
    pub fn sealed_residence_content_for(
        &self,
        world: EntityId,
        window: &WindowKey,
        since: Option<&[u8]>,
        destination: Destination,
    ) -> Result<Option<SealedResidenceContent>> {
        if window.world() != Some(world) {
            return Err(refused("the window is not one of the world's"));
        }
        let vault = self.vault();
        if vault.world_key(world).is_err() {
            return Ok(None);
        }
        let may = {
            let txn = vault.store.env.read_txn()?;
            let fold = vault.authority_view_readonly_in_txn(&txn)?;
            if fold.world_privacy(world).read == EffectiveRead::Everywhere {
                return Ok(None);
            }
            fold.world_readable_on(world, destination)
                || vault.sealed_copy_may_rest_on_in(&txn, world, destination)?
        };
        if !may {
            return Ok(None);
        }
        self.export_sealed_residence_content(world, window, since)
            .map(Some)
    }

    /// Takes one relayed sealed packet in: imported and materialized on a
    /// machine that may read the world now, shelved unread where a sealed
    /// copy may rest here, refused anywhere else. An update ahead of this
    /// reader's mirror shelves too, so it can forward and retry once its
    /// base lands.
    pub fn take_sealed_residence_content(
        &self,
        world: EntityId,
        window: &WindowKey,
        packet: &SealedResidenceContent,
    ) -> Result<SealedTake> {
        if window.world() != Some(world) {
            return Err(refused("the window is not one of the world's"));
        }
        let vault = self.vault();
        if vault.world_key(world).is_ok()
            && let Ok(binding) = self.import_sealed_residence_content(world, window, packet)
        {
            return Ok(SealedTake::Imported(binding));
        }
        {
            let txn = vault.store.env.read_txn()?;
            let here = vault.local_destination_in(&txn)?;
            if !vault.sealed_copy_may_rest_on_in(&txn, world, here)? {
                return Err(refused("a sealed copy of the world may not rest here"));
            }
        }
        let id = vault.store_sealed_world_content(packet)?;
        vault.note_sealed_window_packet(window.as_str(), &id)?;
        Ok(SealedTake::Shelved(id))
    }
}

/// What [`WindowManager::take_sealed_residence_content`] did with a packet.
#[derive(Debug)]
pub enum SealedTake {
    /// Opened under the world's key and materialized here.
    Imported(SealedContentBinding),
    /// Kept unread on this node's shelf, for a reader to fetch.
    Shelved(SealedContentId),
}
