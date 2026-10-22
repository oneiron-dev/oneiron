//! Erase's sweep of every pad object the home keeps (FIX 922): each world
//! whose keys were destroyed here leaves every kept object. An object this
//! machine's capsule does not open, as one sealed before it was admitted,
//! opens with a grant an old reader or the kit sealed to it (FIX 4271), or
//! with a kit the owner hands one sweep.
//!
//! A finished sweep records the home's list it was made against (FIX 8885):
//! each kept generation, its commit order and its pad object's digest. A
//! slot may take more than one generation, and one may land after a sweep,
//! so each connected upkeep lists the home again and owes a world anew once
//! the list moved. That re-check never holds back a sweep that was due, nor
//! a publication or a read; 02A's exact-key proofs replace it.

use std::collections::BTreeSet;

use super::access::{self, OwnAsks};
use super::{
    PartSource, ResidenceRpc, SealedBundleRelay, entries, list_generations, read_object, refused,
    replace_pads, storage,
};
use crate::side_table::{self, HexId, Raw, SideTable};
use crate::sync::residence::SealedBundleObject;
use crate::sync::transport::TransportError;
use crate::world_keys::{OpenedKeyPads, RecoveryRootSeed, SealedBundleGeneration, SealedKeyPads};
use crate::{EntityId, Vault};

/// Each erased world this machine swept from the home's pad objects, with the
/// fingerprint of the home's list it was swept against (empty when none was
/// read), or the slot a pad object that did not open here held it back in.
const SWEPT: SideTable<HexId, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_BUNDLE_SWEPT);

/// What a sweep does while a kept pad object opens with no key here (CALLS:
/// SEALED_PAD_GRANT_UNAVAILABLE).
enum GrantUnavailable {
    /// The object's access stays pending with the home, every erase waits
    /// for the next slot, and the relay counts both. Nothing stripped, an
    /// offered grant, an admission or a finished slot is never a swept erase.
    PendingNeverEraseSuccess,
}

const SEALED_PAD_GRANT_UNAVAILABLE: GrantUnavailable = GrantUnavailable::PendingNeverEraseSuccess;

/// The worlds erased here this machine still owes a sweep of in slot
/// `now_slot`: never swept, or held back in an earlier slot.
pub(super) fn erased_due(vault: &Vault, now_slot: u64) -> crate::error::Result<Vec<EntityId>> {
    let destroyed = vault.world_key_destructions()?;
    let txn = vault.store.env.read_txn()?;
    let mut due = Vec::new();
    for receipt in destroyed {
        let Ok(world) = EntityId::from_hex(&receipt.world) else {
            continue;
        };
        let owed = match SWEPT.get(&vault.store, &txn, &HexId(world))? {
            None => true,
            Some(raw) if raw.is_empty() || raw.len() == 32 => false,
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

/// Marks each of `worlds` swept against the home's list `fingerprint` names.
fn mark_swept_against(
    vault: &Vault,
    worlds: &[EntityId],
    fingerprint: &[u8; 32],
) -> crate::error::Result<()> {
    vault.with_write_txn_grouped(|wtxn| {
        for world in worlds {
            SWEPT.put(&vault.store, wtxn, &HexId(*world), &fingerprint.to_vec())?;
        }
        Ok(())
    })
}

/// Each erased world a sweep finished, with the list fingerprint it was
/// swept against, `None` when it read none.
fn swept_worlds(vault: &Vault) -> crate::error::Result<Vec<(EntityId, Option<[u8; 32]>)>> {
    let destroyed = vault.world_key_destructions()?;
    let txn = vault.store.env.read_txn()?;
    let mut swept: Vec<(EntityId, Option<[u8; 32]>)> = Vec::new();
    for receipt in destroyed {
        let Ok(world) = EntityId::from_hex(&receipt.world) else {
            continue;
        };
        if swept.iter().any(|(held, _)| *held == world) {
            continue;
        }
        match SWEPT.get(&vault.store, &txn, &HexId(world))? {
            Some(raw) if raw.is_empty() => swept.push((world, None)),
            Some(raw) => {
                if let Ok(fingerprint) = <[u8; 32]>::try_from(raw) {
                    swept.push((world, Some(fingerprint)));
                }
            }
            None => {}
        }
    }
    Ok(swept)
}

/// `erased`, with each world a sweep finished against another list than the
/// home's now, or against none read, owed again (FIX 8885). A connected
/// upkeep asks; a list or a read that fails adds nothing, so nothing that
/// was due waits on it.
pub(super) async fn with_reowed(
    vault: &Vault,
    rpc: &mut ResidenceRpc,
    mut erased: Vec<EntityId>,
) -> Vec<EntityId> {
    let swept = match swept_worlds(vault) {
        Ok(swept) if !swept.is_empty() => swept,
        _ => return erased,
    };
    let Ok(listed) = entries::list_entries(rpc, None).await else {
        return erased;
    };
    let fingerprint = entries::list_fingerprint(&listed);
    for (world, against) in swept {
        if against != Some(fingerprint) && !erased.contains(&world) {
            erased.push(world);
        }
    }
    erased
}

/// The worlds whose pads `opened` holds.
fn worlds(opened: OpenedKeyPads) -> Vec<EntityId> {
    opened.keys().map(|key| key.world).collect()
}

/// One kept generation's pad object as the home keeps it now.
async fn fetch_pads(
    rpc: &mut ResidenceRpc,
    generation: SealedBundleGeneration,
) -> Result<SealedKeyPads, TransportError> {
    // A kept object that does not come back is swept on a later tick: a world
    // is never marked swept past an object it did not see.
    let (_, bytes) = read_object(
        &mut PartSource::Machine(rpc),
        Some(generation),
        SealedBundleObject::Pads,
    )
    .await?
    .ok_or_else(refused)?;
    let pads = SealedKeyPads::from_bytes(&bytes).map_err(|_| refused())?;
    if pads.generation() != generation {
        return Err(refused());
    }
    Ok(pads)
}

/// Strips each of `erased` from every pad object the home keeps, rewriting
/// every kept object whether it held the world or not, and counts on `relay`
/// how many worlds a kept object held. Each object opens with this machine's
/// key, else a grant the home holds for it, else `kit`, a recovery kit the
/// owner handed this sweep. A world is swept once every kept object is
/// rewritten without it, or once none holds it. A kept object that opens with
/// none holds every world back until the next slot
/// ([`SEALED_PAD_GRANT_UNAVAILABLE`]), and asks the home for its access. A
/// rewrite another erase beat is made again on the object the home holds now:
/// a grant's key outlives a rewrite.
pub(super) async fn sweep_erased(
    vault: &Vault,
    rpc: &mut ResidenceRpc,
    erased: &[EntityId],
    now_slot: u64,
    kit: Option<&RecoveryRootSeed>,
    relay: &mut SealedBundleRelay,
) -> Result<(), TransportError> {
    let mut kept = Vec::new();
    for generation in list_generations(rpc).await? {
        kept.push(fetch_pads(rpc, generation).await?);
    }
    let mut grants = Vec::new();
    let mut asks = OwnAsks::default();
    let mut held = BTreeSet::new();
    let mut unopened = 0;
    for pads in &kept {
        // This machine's capsule first; the home's grant only past it.
        let mut opened = vault
            .open_key_pads_to_erase(pads, None, &[])
            .ok()
            .map(worlds);
        if opened.is_none() {
            if let Some(grant) = access::own_grant(vault, rpc, pads, &mut asks).await? {
                grants.push(grant);
            }
            opened = vault
                .open_key_pads_to_erase(pads, kit, &grants)
                .ok()
                .map(worlds);
        }
        match opened {
            Some(worlds) => held.extend(worlds),
            None => unopened += 1,
        }
    }
    // What this machine lacks is asked for even when the kit opened it: the
    // unattended sweep needs it later.
    let asked = access::ask_own(vault, rpc, &asks).await;
    if unopened > 0 {
        match SEALED_PAD_GRANT_UNAVAILABLE {
            GrantUnavailable::PendingNeverEraseSuccess => {
                for world in erased {
                    mark_swept(vault, *world, Some(now_slot)).map_err(storage)?;
                }
                relay.pending_pad_access += unopened;
                relay.pending_erases += erased.len();
                return asked;
            }
        }
    }
    asked?;
    for world in erased {
        if held.contains(world) {
            let rewritten = vault
                .drop_world_from_key_pads(*world, &kept, kit, &grants)
                .map_err(storage)?;
            let mut next = Vec::with_capacity(rewritten.len());
            for (old, new) in kept.iter().zip(rewritten) {
                if replace_pads(rpc, old, &new).await? {
                    next.push(new);
                    continue;
                }
                // Another erase rewrote the object first: strip the world
                // from the one the home holds now, once.
                let fresh = fetch_pads(rpc, old.generation()).await?;
                let again = vault
                    .drop_world_from_key_pads(*world, std::slice::from_ref(&fresh), kit, &grants)
                    .map_err(storage)?
                    .pop()
                    .ok_or_else(refused)?;
                if !replace_pads(rpc, &fresh, &again).await? {
                    return Err(TransportError::Storage(
                        "home refused a pad object rewrite".into(),
                    ));
                }
                next.push(again);
            }
            kept = next;
            relay.erased += 1;
        }
        mark_swept(vault, *world, None).map_err(storage)?;
    }
    // The list the sweep leaves, read again once it finished: a later one
    // owes each world anew. One that does not come back leaves them swept
    // against none, owed once more on a later upkeep.
    if let Ok(listed) = entries::list_entries(rpc, None).await {
        mark_swept_against(vault, erased, &entries::list_fingerprint(&listed)).map_err(storage)?;
    }
    Ok(())
}
