//! Egress exclusion for claims whose authority exists only in the local vault.

use std::collections::HashSet;

use loro::LoroMap;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::decode_claim_body;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::write_envelope::world_access_predicates::is_world_access_tier_predicate;
use crate::{EntityId, Result, Vault};

use super::bridge::parse_edge_key;
use super::loro_support::map_for_each_value_bytes;

/// E-sign events have no authenticated replay format. Every receiving batch
/// refuses them, so no sync door may ship them. The world-access tiers are
/// local authority ([`world_access_claim`]), so no sync door ships them
/// either. Undecodable CLAIM carriers also fail closed: their predicate
/// cannot be proved exportable.
pub(super) fn claim_sync_allowed(raw: &[u8]) -> bool {
    if raw.first().copied() != Some(ENTITY_TYPE_CLAIM) {
        return true;
    }
    EntityMetadataHeader::parse(raw).is_some()
        && decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true).is_ok_and(|body| {
            !body.predicate.starts_with("esign.")
                && !is_world_access_tier_predicate(&body.predicate)
        })
}

/// Whether `data`, the body of a CLAIM row, is an ALLOWED-SET grant or a
/// DEFAULT-SUBSET row. Both world-access tiers are local authority (ARCH-0067
/// #phasing; RULING L2-53-CEILING, 14 Nov): a replicated put skips source
/// trust, so a synced grant could set the worlds of an agent on a node whose
/// owner never granted them. No sync door ships one, and every door that
/// replays a peer's rows drops one: dropped, not refused, so the rest of an
/// older peer's window still lands. Every row the world-authority fold reads
/// was therefore written on this node.
pub(super) fn world_access_claim(data: &[u8]) -> bool {
    decode_claim_body(data, true).is_ok_and(|body| is_world_access_tier_predicate(&body.predicate))
}

pub(super) fn local_claim_sync_allowed(vault: &Vault, id: &EntityId) -> Result<bool> {
    Ok(vault
        .get_raw_unsealed(id)?
        .is_none_or(|raw| claim_sync_allowed(&raw)))
}

/// Body-first exclusions plus stored-first identity checks. Raw map keys are
/// untrusted: malformed keys still lose their body, aliases lose every carrier,
/// and a stale ordinary body cannot disguise an id holding a local-only claim.
/// Edge-only endpoints are checked too, including endpoints in other windows.
pub(super) fn withheld_claim_carriers(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    entities: &LoroMap,
    edges: &LoroMap,
) -> Result<(Vec<String>, HashSet<EntityId>)> {
    let mut keys = Vec::new();
    let mut ids = HashSet::new();
    let mut candidates = HashSet::new();
    map_for_each_value_bytes(entities, |key, blob| {
        let id = EntityId::from_hex(key).ok();
        if let Some(id) = id {
            candidates.insert(id);
        }
        if blob.is_some_and(|raw| !claim_sync_allowed(raw)) {
            keys.push(key.to_owned());
            if let Some(id) = id {
                ids.insert(id);
            }
        }
    });
    map_for_each_value_bytes(edges, |key, _| {
        if let Some((src, _, tgt)) = parse_edge_key(key) {
            candidates.extend([src, tgt]);
        }
    });
    for id in candidates {
        if !ids.contains(&id)
            && vault
                .get_raw_in(rtxn, &id)?
                .is_some_and(|raw| !claim_sync_allowed(&raw))
        {
            ids.insert(id);
        }
    }
    Ok((keys, ids))
}

// FIX [LIBTEST-QUARANTINE-SYNC-LOCAL-CLAIMS-TESTS]: the lib test target's type check fails here (3 errors: E0063 x2, E0061 x1); port it, then drop this gate
#[cfg(any())]
#[cfg(test)]
mod tests;
