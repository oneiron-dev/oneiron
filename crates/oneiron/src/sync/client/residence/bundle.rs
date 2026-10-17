//! The vault's sealed cloud bundle through the home (DEC-0005 "Sealed copies",
//! FIX 922). Once in each fixed UTC slot a machine of the owner's takes the
//! home's newest generation in when it is newer than the last one it took. An
//! eligible publisher then uploads a fresh generation for the slot when the
//! slot has none yet, changed or not: in parts the home stages, then a commit
//! on the parent it took. A take runs on that cadence only, never on a world
//! opening or changing, and a missed slot is not replayed. The slot and the
//! last generation taken persist across restarts and re-homes.
//!
//! Erase rewrites every kept pad: each upkeep tick strips every world whose
//! keys were destroyed here, and that this machine has not swept yet, from
//! every pad object the home keeps (`Vault::drop_world_from_key_pads`).

use std::collections::BTreeSet;
use std::sync::Arc;

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use super::{ResidenceRpc, SyncClient, refused, residence_budgets};
use crate::side_table::{self, HexId, Raw, SideTable};
use crate::sync::client::{SyncClientConfig, SyncResidenceMode};
use crate::sync::manager::WindowManager;
use crate::sync::residence::{
    SEALED_BUNDLE_PUT_PART_MAX, SEALED_BUNDLE_READ_PART_MAX, SealedBundleObject, SealedBundleTake,
    sealed_digest_from_hex, sealed_digest_hex, sealed_generation_from_hex, sealed_generation_hex,
};
use crate::sync::transport::TransportError;
use crate::world_keys::{
    SEALED_BUNDLE_KEEP, SealedBundleGeneration, SealedKeyPads, SealedVaultBundle,
    sealed_bundle_slot,
};
use crate::{EntityId, Vault};

/// The slot this machine last finished and the generation it last took in.
const CURSOR: SideTable<(), Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_BUNDLE_CURSOR);
/// Each erased world this machine swept from the home's pad objects, or the
/// slot a pad object that did not open here held it back in.
const SWEPT: SideTable<HexId, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_BUNDLE_SWEPT);
/// How many times, in one slot, a publisher whose parent went stale takes the
/// new newest generation in and uploads again.
const STALE_PARENT_RETRIES: usize = 1;

/// The publisher call (FIX 922): every eligible machine tries each slot, and
/// the home's one-generation-per-slot rule lets the first commit win; the rest
/// take that generation in. Eligible: a machine mine here (the caller's check)
/// that syncs everything, not an opened-item machine or a federation lane.
fn may_publish(config: &SyncClientConfig) -> bool {
    config.residence_mode != SyncResidenceMode::Opened && config.federation_peer.is_none()
}

/// What one bundle relay moved.
#[derive(Debug, Clone, Default)]
pub struct SealedBundleRelay {
    /// The newest generation taken in this slot, and what its take moved.
    pub taken: Option<(SealedBundleGeneration, SealedBundleTake)>,
    /// The generation this machine published for the slot.
    pub published: Option<SealedBundleGeneration>,
    /// Erased worlds stripped from every pad object the home keeps.
    pub erased: usize,
}

#[derive(Deserialize)]
struct BundleListReply {
    generations: Vec<BundleListEntry>,
}

#[derive(Deserialize)]
struct BundleListEntry {
    generation: String,
}

#[derive(Deserialize)]
struct BundleGetReply {
    generation: String,
    object: String,
    total: u64,
    digest: String,
    offset: u64,
    last: bool,
    part: String,
}

/// This machine's cursor: the slot it last finished (0 for none) and the
/// generation it last took in.
#[derive(Clone, Copy, Default)]
struct Cursor {
    slot: u64,
    taken: Option<SealedBundleGeneration>,
}

fn storage(error: crate::Error) -> TransportError {
    TransportError::Storage(error.to_string())
}

fn load_cursor(vault: &Vault) -> crate::error::Result<Cursor> {
    let txn = vault.store.env.read_txn()?;
    let Some(raw) = CURSOR.get(&vault.store, &txn, &())? else {
        return Ok(Cursor::default());
    };
    let (slot, taken) = raw.split_at_checked(8).ok_or(crate::Error::InvalidKey)?;
    Ok(Cursor {
        slot: u64::from_be_bytes(slot.try_into().map_err(|_| crate::Error::InvalidKey)?),
        taken: if taken.is_empty() {
            None
        } else {
            Some(SealedBundleGeneration::from_bytes(taken)?)
        },
    })
}

fn store_cursor(vault: &Vault, cursor: Cursor) -> crate::error::Result<()> {
    let mut raw = cursor.slot.to_be_bytes().to_vec();
    if let Some(taken) = cursor.taken {
        raw.extend_from_slice(&taken.to_bytes());
    }
    vault.with_write_txn_grouped(|wtxn| CURSOR.put(&vault.store, wtxn, &(), &raw))
}

/// The worlds erased here this machine still owes a sweep of in slot
/// `now_slot`: never swept, or held back in an earlier slot.
fn erased_due(vault: &Vault, now_slot: u64) -> crate::error::Result<Vec<EntityId>> {
    let destroyed = vault.world_key_destructions()?;
    let txn = vault.store.env.read_txn()?;
    let mut due = Vec::new();
    for receipt in destroyed {
        let Ok(world) = EntityId::from_hex(&receipt.world) else {
            continue;
        };
        let owed = match SWEPT.get(&vault.store, &txn, &HexId(world))? {
            None => true,
            Some(raw) if raw.is_empty() => false,
            Some(raw) => {
                <[u8; 8]>::try_from(raw).map_or(true, |slot| u64::from_be_bytes(slot) < now_slot)
            }
        };
        if owed && !due.contains(&world) {
            due.push(world);
        }
    }
    Ok(due)
}

/// Marks `world` swept, or held back in `held_back_in`.
fn mark_swept(
    vault: &Vault,
    world: EntityId,
    held_back_in: Option<u64>,
) -> crate::error::Result<()> {
    let raw = held_back_in
        .map(|slot| slot.to_be_bytes().to_vec())
        .unwrap_or_default();
    vault.with_write_txn_grouped(|wtxn| SWEPT.put(&vault.store, wtxn, &HexId(world), &raw))
}

impl SyncClient {
    /// Runs this machine's sealed bundle upkeep through the home (FIX 922):
    /// erase's sweep of every kept pad object, then, once per UTC slot, the
    /// take of the home's newest generation and, on an eligible publisher, the
    /// slot's upload. A federation lane and a machine not mine here do
    /// nothing.
    pub async fn relay_sealed_bundle(&self) -> Result<SealedBundleRelay, TransportError> {
        relay_sealed_bundle(&self.manager, &self.config).await
    }

    /// One generation's bundle and pad object as the home keeps them, for a
    /// restore from the cloud copy: `generation` names one, `None` the newest.
    /// `None` when the home keeps no such generation.
    pub async fn fetch_sealed_bundle(
        &self,
        generation: Option<SealedBundleGeneration>,
    ) -> Result<Option<(SealedVaultBundle, SealedKeyPads)>, TransportError> {
        let budgets = residence_budgets(&self.vault)?;
        let Some(mut rpc) = ResidenceRpc::connect(&self.vault, &self.config, budgets).await? else {
            return Err(TransportError::Storage("home node offline".into()));
        };
        fetch_generation(&mut rpc, generation).await
    }
}

/// [`SyncClient::relay_sealed_bundle`] on the window manager and a client
/// config alone, for a task off the live sync loop. A tick with no erase to
/// sweep and its slot finished opens no socket.
pub(crate) async fn relay_sealed_bundle(
    manager: &Arc<WindowManager>,
    config: &SyncClientConfig,
) -> Result<SealedBundleRelay, TransportError> {
    let vault = manager.vault();
    let mut relay = SealedBundleRelay::default();
    if config.federation_peer.is_some()
        || !vault
            .local_machine()
            .map_err(storage)?
            .is_some_and(|machine| machine.mine)
    {
        return Ok(relay);
    }
    let now_slot = sealed_bundle_slot(vault.store.clock.now_recorded_at());
    let cursor = load_cursor(vault).map_err(storage)?;
    let erased = erased_due(vault, now_slot).map_err(storage)?;
    if erased.is_empty() && cursor.slot >= now_slot {
        return Ok(relay);
    }
    let budgets = residence_budgets(vault)?;
    let Some(mut rpc) = ResidenceRpc::connect(vault, config, budgets).await? else {
        return Err(TransportError::Storage("home node offline".into()));
    };
    if !erased.is_empty() {
        relay.erased = sweep_erased(vault, &mut rpc, &erased, now_slot).await?;
    }
    if cursor.slot < now_slot {
        let slot = SlotRelay {
            manager,
            slot: now_slot,
            opened: config.residence_mode == SyncResidenceMode::Opened,
            publisher: may_publish(config),
        };
        slot.run(&mut rpc, cursor, &mut relay).await?;
    }
    Ok(relay)
}

/// One slot's take and upload.
struct SlotRelay<'a> {
    manager: &'a Arc<WindowManager>,
    slot: u64,
    /// An opened-item machine: its take keeps windows in their mirror.
    opened: bool,
    publisher: bool,
}

impl SlotRelay<'_> {
    /// Takes the newest generation in when it is newer than the last taken,
    /// then publishes the slot's generation when the slot has none and this
    /// machine publishes. A take that fails here uploads nothing this slot:
    /// the upload would carry less than the home holds. The slot is finished
    /// once its upload is in, another machine's is, or the take or the
    /// assembly failed here; a refused upload tries again next tick.
    async fn run(
        &self,
        rpc: &mut ResidenceRpc,
        mut cursor: Cursor,
        relay: &mut SealedBundleRelay,
    ) -> Result<(), TransportError> {
        let vault = self.manager.vault();
        // The newest generation's objects, once fetched: an upload carries
        // what this machine cannot read from them.
        let mut held: Option<(SealedVaultBundle, SealedKeyPads)> = None;
        let mut retries = 0;
        loop {
            let latest = list_generations(rpc).await?.first().copied();
            if let Some(newest) =
                latest.filter(|newest| cursor.taken.is_none_or(|taken| *newest > taken))
            {
                let (bundle, pads) = fetch_generation(rpc, Some(newest))
                    .await?
                    .ok_or_else(refused)?;
                let manager = Arc::clone(self.manager);
                let opened = self.opened;
                let (took, bundle, pads) = tokio::task::spawn_blocking(move || {
                    let took = manager.take_sealed_bundle(&bundle, &pads, opened);
                    (took, bundle, pads)
                })
                .await
                .map_err(|error| TransportError::Storage(error.to_string()))?;
                cursor.taken = Some(newest);
                match took {
                    Ok(take) => relay.taken = Some((newest, take)),
                    Err(error) => {
                        cursor.slot = self.slot;
                        store_cursor(vault, cursor).map_err(storage)?;
                        return Err(storage(error));
                    }
                }
                store_cursor(vault, cursor).map_err(storage)?;
                held = Some((bundle, pads));
            }
            if !self.publisher || latest.is_some_and(|newest| newest.slot >= self.slot) {
                break;
            }
            if let Some(newest) = latest
                && held
                    .as_ref()
                    .is_none_or(|(bundle, _)| bundle.generation() != newest)
            {
                held = Some(
                    fetch_generation(rpc, Some(newest))
                        .await?
                        .ok_or_else(refused)?,
                );
            }
            let manager = Arc::clone(self.manager);
            let slot = self.slot;
            let (upload, back) = tokio::task::spawn_blocking(move || {
                let upload = manager.assemble_sealed_bundle(
                    slot,
                    held.as_ref().map(|(bundle, pads)| (bundle, pads)),
                );
                (upload, held)
            })
            .await
            .map_err(|error| TransportError::Storage(error.to_string()))?;
            held = back;
            let upload = match upload {
                Ok(upload) => upload,
                Err(error) => {
                    cursor.slot = self.slot;
                    store_cursor(vault, cursor).map_err(storage)?;
                    return Err(storage(error));
                }
            };
            let generation = upload.bundle.generation();
            if put_object(
                rpc,
                &generation,
                SealedBundleObject::Bundle,
                upload.bundle.as_bytes(),
            )
            .await?
                && put_object(
                    rpc,
                    &generation,
                    SealedBundleObject::Pads,
                    upload.pads.as_bytes(),
                )
                .await?
                && commit_generation(rpc, &generation, latest).await?
            {
                cursor.taken = Some(generation);
                relay.published = Some(generation);
                break;
            }
            // A refused upload: when the newest generation moved meanwhile,
            // the parent went stale.
            let moved = list_generations(rpc).await?.first().copied() != latest;
            if !moved || retries == STALE_PARENT_RETRIES {
                return Err(TransportError::Storage(
                    "home refused the sealed bundle upload".into(),
                ));
            }
            retries += 1;
        }
        cursor.slot = self.slot;
        store_cursor(vault, cursor).map_err(storage)
    }
}

/// Strips each of `erased` from every pad object the home keeps, rewriting
/// every kept object whether it held the world or not; returns how many
/// worlds a kept object held. A world is swept once every kept object is
/// rewritten without it, or once none holds it. A kept object that does not
/// open here holds every world back until the next slot.
async fn sweep_erased(
    vault: &Vault,
    rpc: &mut ResidenceRpc,
    erased: &[EntityId],
    now_slot: u64,
) -> Result<usize, TransportError> {
    let mut kept = Vec::new();
    for generation in list_generations(rpc).await? {
        // A kept object that does not come back is swept on a later tick:
        // a world is never marked swept past an object it did not see.
        let (_, bytes) = read_object(rpc, Some(generation), SealedBundleObject::Pads)
            .await?
            .ok_or_else(refused)?;
        let pads = SealedKeyPads::from_bytes(&bytes).map_err(|_| refused())?;
        if pads.generation() != generation {
            return Err(refused());
        }
        kept.push(pads);
    }
    let mut held = BTreeSet::new();
    for pads in &kept {
        match vault.open_key_pads(pads) {
            Ok(opened) => held.extend(opened.keys().map(|key| key.world)),
            Err(_) => {
                for world in erased {
                    mark_swept(vault, *world, Some(now_slot)).map_err(storage)?;
                }
                return Ok(0);
            }
        }
    }
    let mut stripped = 0;
    for world in erased {
        if held.contains(world) {
            let rewritten = vault
                .drop_world_from_key_pads(*world, &kept, None)
                .map_err(storage)?;
            for (old, new) in kept.iter().zip(&rewritten) {
                if !replace_pads(rpc, old, new).await? {
                    return Err(TransportError::Storage(
                        "home refused a pad object rewrite".into(),
                    ));
                }
            }
            kept = rewritten;
            stripped += 1;
        }
        mark_swept(vault, *world, None).map_err(storage)?;
    }
    Ok(stripped)
}

/// The generations the home keeps, newest first.
async fn list_generations(
    rpc: &mut ResidenceRpc,
) -> Result<Vec<SealedBundleGeneration>, TransportError> {
    let reply = rpc.request("residence.bundle.list", json!({})).await?;
    let list: BundleListReply = serde_json::from_value(reply).map_err(|_| refused())?;
    if list.generations.len() > SEALED_BUNDLE_KEEP {
        return Err(refused());
    }
    let generations = list
        .generations
        .iter()
        .map(|entry| sealed_generation_from_hex(&entry.generation).ok_or_else(refused))
        .collect::<Result<Vec<_>, _>>()?;
    if !generations.windows(2).all(|pair| pair[0] > pair[1]) {
        return Err(refused());
    }
    Ok(generations)
}

/// Reads one kept object in slices: `generation` names one, `None` the newest.
/// `None` when the home keeps no such generation.
async fn read_object(
    rpc: &mut ResidenceRpc,
    generation: Option<SealedBundleGeneration>,
    object: SealedBundleObject,
) -> Result<Option<(SealedBundleGeneration, Vec<u8>)>, TransportError> {
    let mut named = generation;
    let mut bytes = Vec::new();
    let mut whole: Option<(u64, [u8; 32])> = None;
    loop {
        let reply = match rpc
            .request(
                "residence.bundle.get",
                json!({
                    "generation": named.as_ref().map(sealed_generation_hex),
                    "object": object.name(),
                    "offset": bytes.len(),
                }),
            )
            .await
        {
            Ok(reply) => reply,
            Err(TransportError::InvalidPayload(_)) if bytes.is_empty() => return Ok(None),
            Err(error) => return Err(error),
        };
        let reply: BundleGetReply = serde_json::from_value(reply).map_err(|_| refused())?;
        let generation = sealed_generation_from_hex(&reply.generation).ok_or_else(refused)?;
        let digest = sealed_digest_from_hex(&reply.digest).ok_or_else(refused)?;
        if named.is_some_and(|named| named != generation)
            || reply.object != object.name()
            || reply.offset != bytes.len() as u64
            || *whole.get_or_insert((reply.total, digest)) != (reply.total, digest)
        {
            return Err(refused());
        }
        named = Some(generation);
        let part = base64::engine::general_purpose::STANDARD
            .decode(reply.part)
            .map_err(|_| refused())?;
        if part.is_empty()
            || part.len() > SEALED_BUNDLE_READ_PART_MAX
            || bytes.len() as u64 + part.len() as u64 > reply.total
        {
            return Err(refused());
        }
        bytes.extend_from_slice(&part);
        let done = bytes.len() as u64 == reply.total;
        if reply.last != done {
            return Err(refused());
        }
        if done {
            if *blake3::hash(&bytes).as_bytes() != digest {
                return Err(refused());
            }
            return Ok(Some((generation, bytes)));
        }
    }
}

/// One kept generation's bundle and pad object: `generation` names one, `None`
/// the newest. `None` when the home keeps no such generation.
async fn fetch_generation(
    rpc: &mut ResidenceRpc,
    generation: Option<SealedBundleGeneration>,
) -> Result<Option<(SealedVaultBundle, SealedKeyPads)>, TransportError> {
    let Some((generation, bytes)) =
        read_object(rpc, generation, SealedBundleObject::Bundle).await?
    else {
        return Ok(None);
    };
    let bundle = SealedVaultBundle::from_bytes(&bytes).map_err(|_| refused())?;
    drop(bytes);
    let Some((_, bytes)) = read_object(rpc, Some(generation), SealedBundleObject::Pads).await?
    else {
        return Ok(None);
    };
    let pads = SealedKeyPads::from_bytes(&bytes).map_err(|_| refused())?;
    if bundle.generation() != generation || pads.generation() != generation {
        return Err(refused());
    }
    Ok(Some((bundle, pads)))
}

/// Stages one object on the home in parts; `false` when the home refused a
/// part.
async fn put_object(
    rpc: &mut ResidenceRpc,
    generation: &SealedBundleGeneration,
    object: SealedBundleObject,
    bytes: &[u8],
) -> Result<bool, TransportError> {
    let generation = sealed_generation_hex(generation);
    let digest = sealed_digest_hex(blake3::hash(bytes).as_bytes());
    let mut offset = 0;
    for part in bytes.chunks(SEALED_BUNDLE_PUT_PART_MAX) {
        match rpc
            .request(
                "residence.bundle.put",
                json!({
                    "generation": generation.as_str(),
                    "object": object.name(),
                    "total": bytes.len(),
                    "digest": digest.as_str(),
                    "offset": offset,
                    "part": base64::engine::general_purpose::STANDARD.encode(part),
                }),
            )
            .await
        {
            Ok(_) => {}
            Err(TransportError::InvalidPayload(_)) => return Ok(false),
            Err(error) => return Err(error),
        }
        offset += part.len();
    }
    Ok(true)
}

/// Commits the generation staged here on `parent`; `false` when the home
/// refused it.
async fn commit_generation(
    rpc: &mut ResidenceRpc,
    generation: &SealedBundleGeneration,
    parent: Option<SealedBundleGeneration>,
) -> Result<bool, TransportError> {
    match rpc
        .request(
            "residence.bundle.commit",
            json!({
                "generation": sealed_generation_hex(generation),
                "parent": parent.as_ref().map(sealed_generation_hex),
            }),
        )
        .await
    {
        Ok(_) => Ok(true),
        Err(TransportError::InvalidPayload(_)) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Replaces one kept pad object with its rewrite, on the digest of the object
/// it was made from; `false` when the home refused.
async fn replace_pads(
    rpc: &mut ResidenceRpc,
    old: &SealedKeyPads,
    new: &SealedKeyPads,
) -> Result<bool, TransportError> {
    let generation = new.generation();
    if !put_object(rpc, &generation, SealedBundleObject::Pads, new.as_bytes()).await? {
        return Ok(false);
    }
    match rpc
        .request(
            "residence.bundle.pads.replace",
            json!({
                "generation": sealed_generation_hex(&generation),
                "replaces": sealed_digest_hex(&old.digest()),
            }),
        )
        .await
    {
        Ok(_) => Ok(true),
        Err(TransportError::InvalidPayload(_)) => Ok(false),
        Err(error) => Err(error),
    }
}
