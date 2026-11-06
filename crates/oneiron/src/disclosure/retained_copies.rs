//! Retained courtesy copies stay the recipient owner's to read (BIZ-LEGAL-0004
//! B2, Docs Q09). A non-delete answer withholds the copies its worlds and
//! delivery cutoff cover from ordinary shared reads. No row-local marker or
//! requester ask alone changes admission.

use heed::RoTxn;

use crate::claim::{ClaimBody, decode_claim_body};
#[cfg(feature = "sync")]
use crate::deletion::IncomingCooperativeDeletion;
use crate::store::Store;
use crate::{EntityId, Result};

/// Whether the actual revision's copy remains available to a shared read.
/// The caller preserves its owner-only exception and supplies the revision's
/// body; an already decoded CLAIM body names that same read's record position.
pub(crate) fn retained_copy_admits(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    claim_body: Option<&ClaimBody>,
    record_body: &[u8],
) -> Result<bool> {
    let claim = entity_type == crate::registry::ENTITY_TYPE_CLAIM;
    if !(claim
        || entity_type == crate::registry::ENTITY_TYPE_TASK
        || entity_type == crate::registry::ENTITY_TYPE_SUMMARY)
    {
        return Ok(true);
    }
    let world = match claim_body.filter(|_| claim) {
        Some(body) => body.world,
        None if claim => decode_claim_body(record_body, true)?.world,
        None => crate::federation::record_scope::record_world_in(
            store,
            rtxn,
            *id,
            entity_type,
            record_body,
        )?
        .flatten(),
    };
    let Some(world) = world.filter(|world| crate::entity_id::is_foreign_world_id_range(*world))
    else {
        return Ok(true);
    };
    for (pact, asks) in crate::deletion::courtesy_retained_pacts_in(store, rtxn)? {
        if !crate::federation::world_registered_to_pact_in(store, rtxn, &pact, world)? {
            continue;
        }
        // With no sync, no ledger or mapping is read: a retained ask covers
        // every world its pact registered.
        #[cfg(not(feature = "sync"))]
        let covered = !asks.is_empty();
        #[cfg(feature = "sync")]
        let covered = retained_ask_covers(store, rtxn, &pact, &asks, id, world)?;
        if covered {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether one of `asks`, the retained asks under `pact`, covers the copy
/// `id` in `world`, a foreign world `pact` registered (FIX 1322): an ask
/// whose named worlds land in `world` here (one that names none asks about
/// every world the pact delivered), when the pact first delivered `id` at or
/// before the ask's epoch cutoff, as the delivery ledger reads in `rtxn`.
/// What cannot be read covers, as the ask's whole pact did before: a named
/// world that maps to nothing known, or a copy the ledger names no epoch for.
#[cfg(feature = "sync")]
fn retained_ask_covers(
    store: &Store,
    rtxn: &RoTxn<'_>,
    pact: &[u8; 32],
    asks: &[IncomingCooperativeDeletion],
    id: &EntityId,
    world: EntityId,
) -> Result<bool> {
    // Read once, for the first ask that names `world`.
    let mut delivered: Option<Option<u64>> = None;
    for ask in asks.iter().filter(|ask| ask_names_world(ask, world)) {
        let first = match delivered {
            Some(first) => first,
            None => {
                let first = store.federation_first_delivery_epoch_in(rtxn, pact, *id)?;
                delivered = Some(first);
                first
            }
        };
        if first.is_none_or(|epoch| epoch <= ask.epoch_cutoff) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether `ask` names `world`: no world named is every world, and each one
/// named is the requester's own id, landing here in the foreign world its
/// source vault and that id derive ([`crate::federation::foreign_world_for`],
/// as admission placed the requester's content). The requester is the
/// pact's peer, as the ask was checked to be when it was filed. A requester
/// or world that does not decode, or an id that derives no foreign world,
/// names `world` too: an unknown never narrows the ask.
#[cfg(feature = "sync")]
fn ask_names_world(ask: &IncomingCooperativeDeletion, world: EntityId) -> bool {
    if ask.worlds.is_empty() {
        return true;
    }
    let Some(requester) = crate::deletion::parse_hex::<32>(&ask.requester_vault_id) else {
        return true;
    };
    ask.worlds.iter().any(|named| {
        EntityId::from_hex(named)
            .ok()
            .and_then(|named| crate::federation::foreign_world_for(&requester, named).ok())
            .is_none_or(|here| here.entity_id() == world)
    })
}
