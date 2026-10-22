//! Erase's sweep of every pad object the home keeps (FIX 922): each world
//! whose keys were destroyed here, and each key a hard erase of its pad row
//! staged (FIX 7192, 7294), leaves every kept object. An object this
//! machine's capsule does not open, as one sealed before it was admitted,
//! opens with a grant an old reader or the kit sealed to it (FIX 4271), or
//! with a kit the owner hands one sweep.
//!
//! Each subject keeps a proof of the kept objects it was swept from
//! (`pad_sweep`, FIX 8868): each connected upkeep lists the home and sweeps
//! each subject from the objects its proof does not name, one committed
//! after an earlier sweep listed the home included. That never holds back a
//! sweep that was due, nor a publication or a read, and the erase itself
//! never waits on it.
//!
//! A kept pad object whose bytes the home lacks is offered back to it when
//! this machine's own store keeps it whole (`refill`, FIX 9362); else it
//! stays owed.

use std::collections::BTreeMap;

use super::access::{self, OwnAsks};
use super::pad_sweep::{Owed, PadSweepProof, record};
use super::refill::{self, ObjectRead};
use super::{
    PartSource, ResidenceRpc, SealedBundleRelay, entries, read_object, refused, replace_pads,
    storage,
};
use crate::authority::PeerMachine;
use crate::sync::residence::SealedBundleObject;
use crate::sync::transport::TransportError;
use crate::world_keys::{
    OpenedKeyPads, PadEraseSubject, RecoveryRootSeed, SealedBundleGeneration, SealedKeyPads,
    SealedPadAdmissionGrant, WorldKeyId,
};
use crate::{EntityId, Vault};

/// What a sweep does while a kept pad object opens with no key here (CALLS:
/// SEALED_PAD_GRANT_UNAVAILABLE).
enum GrantUnavailable {
    /// The object's access stays pending with the home, every erase waits
    /// for the next slot, and the relay counts both. Nothing stripped, an
    /// offered grant, an admission or a finished slot is never a swept erase.
    PendingNeverEraseSuccess,
}

const SEALED_PAD_GRANT_UNAVAILABLE: GrantUnavailable = GrantUnavailable::PendingNeverEraseSuccess;

/// One kept object a sweep fetched.
struct Kept {
    pads: SealedKeyPads,
    /// The keys whose pads it holds, once it opened here.
    keys: Option<Vec<WorldKeyId>>,
    /// Each digest it had in this sweep. Each rewrite only takes pads out,
    /// so a subject swept from any of them is swept from the last.
    seen: Vec<[u8; 32]>,
}

/// The home as the sweep's proofs name it: the machine it proved while its
/// proof stands here, else none (the zero id).
fn home_of(vault: &Vault, home: PeerMachine) -> EntityId {
    match vault.peer_machine_stands(home) {
        PeerMachine::Proven { machine, .. } => machine,
        PeerMachine::Unknown => EntityId::from_bytes_unchecked([0; 16]),
    }
}

/// One kept generation's pad object as the home keeps it now; `None` for
/// one it keeps no more. One whose bytes the home lacks (FIX 7106) is offered
/// back to it under `revision`, the index the sweep listed, when this
/// machine's own store keeps it whole (FIX 9362); else it stays owed.
async fn fetch_pads(
    vault: &Vault,
    rpc: &mut ResidenceRpc,
    generation: SealedBundleGeneration,
    revision: [u8; 32],
) -> Result<Option<SealedKeyPads>, TransportError> {
    let read = read_object(
        &mut PartSource::Machine(rpc),
        Some(generation),
        SealedBundleObject::Pads,
    )
    .await?;
    let bytes = match read {
        ObjectRead::Whole(_, bytes) => bytes,
        ObjectRead::Missing => return Ok(None),
        ObjectRead::PadsUnavailable(unavailable) => {
            // An offer that fails holds nothing back: the object stays owed.
            let refilled = if unavailable.generation == generation {
                refill::refill_held(vault, rpc, &unavailable, revision)
                    .await
                    .unwrap_or_else(|error| {
                        tracing::warn!(%error, "a kept pad object's refill was not offered");
                        None
                    })
            } else {
                None
            };
            if refilled.is_none() {
                tracing::warn!("a kept pad object the home lacks stays owed by erase's sweep");
            }
            return Ok(refilled);
        }
    };
    let pads = SealedKeyPads::from_bytes(&bytes).map_err(|_| refused())?;
    if pads.generation() != generation {
        return Err(refused());
    }
    Ok(Some(pads))
}

/// `subject` stripped from each of `kept`.
fn rewrite(
    vault: &Vault,
    subject: PadEraseSubject,
    kept: &[SealedKeyPads],
    kit: Option<&RecoveryRootSeed>,
    grants: &[SealedPadAdmissionGrant],
) -> Result<Vec<SealedKeyPads>, TransportError> {
    match subject {
        PadEraseSubject::World(world) => vault.drop_world_from_key_pads(world, kept, kit, grants),
        PadEraseSubject::Key(item) => vault.drop_key_from_key_pads(&item, kept, kit, grants),
    }
    .map_err(storage)
}

/// Strips each of `owed` from every pad object the home keeps that its proof
/// does not name, rewriting each such object whether it held the subject or
/// not once one did, and counts on `relay` how many subjects a kept object
/// held. Each object opens with this machine's key, else a grant the home
/// holds for it, else `kit`, a recovery kit the owner handed this sweep. A
/// subject held back in slot `due_from` or later waits; a kept object that
/// opens with none holds every owed subject back in `now_slot`
/// ([`SEALED_PAD_GRANT_UNAVAILABLE`]), and asks the home for its access. A
/// rewrite another erase beat is made again on the object the home holds
/// now: a grant's key outlives a rewrite. Each proof then names the home's
/// list read again once the sweep finished, and only the objects swept.
pub(super) async fn sweep_erased(
    vault: &Vault,
    rpc: &mut ResidenceRpc,
    owed: Vec<Owed>,
    (now_slot, due_from): (u64, u64),
    kit: Option<&RecoveryRootSeed>,
    relay: &mut SealedBundleRelay,
) -> Result<(), TransportError> {
    let due = owed.iter().any(|owed| owed.due_unlisted(due_from));
    let listed = match entries::list_index(rpc, None).await {
        Ok(listed) => listed,
        // With nothing due whatever the home lists, a list that fails holds
        // nothing back.
        Err(_) if !due => return Ok(()),
        Err(error) => return Err(error),
    };
    let home = home_of(vault, rpc.home);
    let work: Vec<_> = owed
        .into_iter()
        .filter_map(|owed| {
            let generations = owed.uncovered(home, &listed.generations, due_from)?;
            Some((owed, generations))
        })
        .collect();
    if work.is_empty() {
        return Ok(());
    }
    let mut kept: BTreeMap<SealedBundleGeneration, Kept> = BTreeMap::new();
    for entry in &listed.generations {
        if !work.iter().any(|(_, owed)| owed.contains(entry)) {
            continue;
        }
        if let Some(pads) =
            fetch_pads(vault, rpc, entry.generation, listed.retained_revision).await?
        {
            let seen = vec![pads.digest()];
            kept.insert(
                entry.generation,
                Kept {
                    pads,
                    keys: None,
                    seen,
                },
            );
        }
    }
    let mut grants = Vec::new();
    let mut asks = OwnAsks::default();
    let mut unopened = 0;
    for object in kept.values_mut() {
        // This machine's capsule first; the home's grant only past it.
        let held = |opened: OpenedKeyPads| -> Vec<WorldKeyId> { opened.keys().copied().collect() };
        object.keys = vault
            .open_key_pads_to_erase(&object.pads, None, &[])
            .ok()
            .map(held);
        if object.keys.is_none() {
            if let Some(grant) = access::own_grant(vault, rpc, &object.pads, &mut asks).await? {
                grants.push(grant);
            }
            object.keys = vault
                .open_key_pads_to_erase(&object.pads, kit, &grants)
                .ok()
                .map(held);
        }
        if object.keys.is_none() {
            unopened += 1;
        }
    }
    // What this machine lacks is asked for even when the kit opened it: the
    // unattended sweep needs it later.
    let asked = access::ask_own(vault, rpc, &asks).await;
    let generations: Vec<_> = listed
        .generations
        .iter()
        .map(|entry| entry.generation)
        .collect();
    if unopened > 0 {
        match SEALED_PAD_GRANT_UNAVAILABLE {
            GrantUnavailable::PendingNeverEraseSuccess => {
                let held: Vec<_> = work
                    .iter()
                    .map(|(owed, _)| {
                        owed.proved(
                            home,
                            listed.retained_revision,
                            &generations,
                            &[],
                            Some(now_slot),
                        )
                    })
                    .collect();
                record(vault, &held).map_err(storage)?;
                relay.pending_pad_access += unopened;
                relay.pending_erases += work.len();
                return asked;
            }
        }
    }
    asked?;
    let mut swept = Vec::with_capacity(work.len());
    for (owed, uncovered) in &work {
        let subject = owed.subject;
        let mine: Vec<_> = uncovered
            .iter()
            .filter(|entry| kept.contains_key(&entry.generation))
            .map(|entry| entry.generation)
            .collect();
        let holds = mine.iter().any(|generation| {
            kept[generation]
                .keys
                .iter()
                .flatten()
                .any(|key| subject.takes(key))
        });
        if holds {
            let objects: Vec<_> = mine
                .iter()
                .map(|generation| kept[generation].pads.clone())
                .collect();
            let rewritten = rewrite(vault, subject, &objects, kit, &grants)?;
            for (generation, new) in mine.iter().zip(rewritten) {
                let Some(object) = kept.get_mut(generation) else {
                    continue;
                };
                let new = if replace_pads(rpc, &object.pads, &new).await? {
                    new
                } else {
                    // Another erase rewrote the object first: strip the
                    // subject from the one the home holds now, once.
                    let fresh = fetch_pads(vault, rpc, *generation, listed.retained_revision)
                        .await?
                        .ok_or_else(refused)?;
                    let again =
                        rewrite(vault, subject, std::slice::from_ref(&fresh), kit, &grants)?
                            .pop()
                            .ok_or_else(refused)?;
                    if !replace_pads(rpc, &fresh, &again).await? {
                        return Err(TransportError::Storage(
                            "home refused a pad object rewrite".into(),
                        ));
                    }
                    object.seen.push(fresh.digest());
                    again
                };
                object.seen.push(new.digest());
                object.pads = new;
                if let Some(keys) = &mut object.keys {
                    keys.retain(|key| !subject.takes(key));
                }
            }
            relay.erased += 1;
        }
        let pairs: Vec<_> = mine
            .iter()
            .map(|generation| (*generation, kept[generation].pads.digest()))
            .collect();
        swept.push((owed, pairs));
    }
    // The list the sweep leaves, read again once it finished: each proof
    // names its revision. One that does not come back leaves the first.
    let (revision, generations) = match entries::list_index(rpc, None).await {
        Ok(after) => (
            after.retained_revision,
            after
                .generations
                .iter()
                .map(|entry| entry.generation)
                .collect(),
        ),
        Err(_) => (listed.retained_revision, generations),
    };
    let proofs: Vec<PadSweepProof> = swept
        .into_iter()
        .map(|(owed, pairs)| {
            // A subject swept from a digest this sweep rewrote since is swept
            // from the last.
            let last: Vec<_> = pairs
                .into_iter()
                .map(|(generation, digest)| match kept.get(&generation) {
                    Some(object) if object.seen.contains(&digest) => {
                        (generation, object.pads.digest())
                    }
                    _ => (generation, digest),
                })
                .collect();
            owed.proved(home, revision, &generations, &last, None)
        })
        .collect();
    record(vault, &proofs).map_err(storage)
}
