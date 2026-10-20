//! Sealed-mirror membership (FIX 536): before a sealed window's mirror is
//! packed again, a carrier it keeps for a row that has since left the window
//! leaves the mirror.
//!
//! The mirror carries rows other machines packed, so only a row held here
//! proves a move: read here, its world or learned month names another window.
//! A row not held here, or one whose world does not decode (a deleted CLAIM's
//! shell among them), stays. Only a CLAIM's world can change; a key pad or
//! wrap outside its window is the local-only scrub's. Each removal is a
//! delete in the mirror's own maps, which merges into every mirror that takes
//! it; no tombstone is written, so the row lives on where it moved. Only the
//! live maps change: the mirror's history and the bundles already kept still
//! hold the old set.

use std::collections::{BTreeSet, HashMap};

use loro::{CommitOptions, LoroDoc};

use super::bridge::{self, BRIDGE_ORIGIN};
use super::loro_support::{map_delete, map_for_each_value_bytes};
use super::reverse::remove_entity_crdt_carriers;
use super::types::{WindowKey, edge_worlds_match, entity_world};

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::Result;

/// What proves a row left a sealed window (CALLS:
/// SEALED_MIRROR_DEPARTURE_PROOF).
enum DepartureProof {
    /// A CLAIM held here whose world or learned month, read here, names
    /// another window. This machine's row decides, so a holder of an older
    /// copy may drop a carrier until a holder of the newer one seals again.
    HeldClaimResidesElsewhere,
}

const SEALED_MIRROR_DEPARTURE_PROOF: DepartureProof = DepartureProof::HeldClaimResidesElsewhere;

/// Where a row held here resides.
#[derive(Clone)]
struct Residence {
    claim: bool,
    world: Option<EntityId>,
    month: WindowKey,
}

/// The residence of `id` read here; `None` when this machine holds no such
/// row or its world does not decode, neither of which proves a move.
fn residence_in(vault: &Vault, rtxn: &heed::RoTxn<'_>, id: &EntityId) -> Result<Option<Residence>> {
    let Some(raw) = vault.get_raw_in(rtxn, id)? else {
        return Ok(None);
    };
    let (Some(header), Ok(world)) = (EntityMetadataHeader::parse(&raw), entity_world(&raw)) else {
        return Ok(None);
    };
    Ok(Some(Residence {
        claim: header.entity_type == crate::registry::ENTITY_TYPE_CLAIM,
        world,
        month: WindowKey::from_timestamp(header.learned_at),
    }))
}

/// Drops from `doc`, the mirror of the sealed world window `window_key`, the
/// carrier of each CLAIM held here that now resides in another window, with
/// its incident edges, birth, peer origin and retained-world witness, and
/// each edge on a CLAIM whose two endpoints, held here, now place it in
/// another window: base→world edges with the world target's month, others
/// with their source's. Commits what it dropped; returns whether any went.
pub(super) fn drop_departed_carriers(
    vault: &Vault,
    doc: &LoroDoc,
    window_key: &WindowKey,
) -> Result<bool> {
    match SEALED_MIRROR_DEPARTURE_PROOF {
        DepartureProof::HeldClaimResidesElsewhere => {}
    }
    let (Some(world), Some(month)) = (window_key.world(), window_key.as_str().get(..7)) else {
        return Ok(false);
    };
    let entities = doc.get_map("entities");
    let edges = doc.get_map("edges");
    let mut carried = BTreeSet::new();
    map_for_each_value_bytes(&entities, |key, _| {
        if let Ok(id) = EntityId::from_hex(key) {
            carried.insert(id);
        }
    });
    let mut edge_keys = Vec::new();
    map_for_each_value_bytes(&edges, |key, _| {
        if let Some((source, _, target)) = bridge::parse_edge_key(key) {
            edge_keys.push((key.to_owned(), source, target));
        }
    });
    let mut departed = BTreeSet::new();
    let mut stale_edges = Vec::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        let mut held: HashMap<EntityId, Option<Residence>> = HashMap::new();
        let mut residence = |id: EntityId| -> Result<Option<Residence>> {
            if let Some(known) = held.get(&id) {
                return Ok(known.clone());
            }
            let found = residence_in(vault, &rtxn, &id)?;
            held.insert(id, found.clone());
            Ok(found)
        };
        for id in carried {
            if residence(id)?.is_some_and(|row| {
                row.claim && (row.world != Some(world) || row.month.as_str() != month)
            }) {
                departed.insert(id);
            }
        }
        for (key, source, target) in edge_keys {
            if departed.contains(&source) || departed.contains(&target) {
                continue;
            }
            let (Some(src), Some(tgt)) = (residence(source)?, residence(target)?) else {
                continue;
            };
            let home = if src.world.is_none() { &tgt } else { &src };
            if (src.claim || tgt.claim)
                && (!edge_worlds_match(src.world, tgt.world, window_key)
                    || home.month.as_str() != month)
            {
                stale_edges.push(key);
            }
        }
    }
    let mut dropped = false;
    for id in &departed {
        dropped |= remove_entity_crdt_carriers(&entities, &edges, id)?;
    }
    for key in &stale_edges {
        map_delete(&edges, key)?;
        dropped = true;
    }
    if !departed.is_empty() {
        // A shell's world witness at a departed id goes with its carrier.
        let witnesses = doc.get_map("retained_claim_worlds");
        for id in &departed {
            if witnesses.get(&id.to_hex()).is_some() {
                map_delete(&witnesses, &id.to_hex())?;
                dropped = true;
            }
        }
        dropped |= crate::sync::ingest::forget_stale_peer_origins(doc, departed)?;
    }
    if dropped {
        doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    }
    Ok(dropped)
}
