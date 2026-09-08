//! PPR cache constants, TTL policy, cache IO, and binary codec.

use std::collections::{HashMap, HashSet};

use heed::{RoTxn, RwTxn};

use crate::batch::EntityMetadataHeader;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::pipeline::ScoredEntity;
use crate::store::{GRAPH_VERSION_KEY, ManifestDbs, Store};

use super::query::DeferredPprCacheWrite;
use super::walk::{CachedPprRow, PprCacheState, PprFrontierEntry};

pub(super) const SEED_HASH_LEN: usize = 16;
#[cfg(test)]
pub(super) const LEGACY_SEED_HASH_LEN: usize = 32;
pub(super) const CACHE_HEADER_LEN: usize = 17;
pub(super) const CACHE_STALE_OFFSET: usize = 16;
const CACHE_ENTRY_LEN: usize = 20;
pub(super) const CACHE_STATE_MAGIC: &[u8; 4] = b"FPRS";
const CACHE_STATE_VERSION: u8 = 1;
const CACHE_STATE_PREFIX_LEN: usize = 21;
const CACHE_FRONTIER_ENTRY_LEN: usize = ENTITY_ID_LEN + 8;
pub(super) const CACHE_DEP_KEY_LEN: usize = ENTITY_ID_LEN + SEED_HASH_LEN;
#[cfg(test)]
pub(super) const LEGACY_CACHE_DEP_KEY_LEN: usize = ENTITY_ID_LEN + LEGACY_SEED_HASH_LEN;
pub(super) const CACHE_TTL_ACTIVE_SECS: u64 = 86_400;
pub(super) const CACHE_TTL_RECENT_SECS: u64 = 259_200;
pub(crate) const CACHE_TTL_DORMANT_SECS: u64 = 604_800;
/// Seed recency strictly below this bound is the Active tier (`< 7d`).
const SEED_RECENCY_ACTIVE_LIMIT_SECS: u64 = 7 * 86_400;
/// Seed recency strictly below this bound (and ≥ the Active limit) is the
/// Recent tier (`7–30d`); at or above it is Dormant (`≥ 30d`).
const SEED_RECENCY_RECENT_LIMIT_SECS: u64 = 30 * 86_400;
pub(super) const MAX_PPR_DEPTH: u32 = 10;
/// Version of the PPR propagation math, mixed into the cache key so persisted
/// `ppr_cache` rows computed under an older formula can never be served after
/// an upgrade (the rows are otherwise gated only by graph version + TTL, and a
/// formula change bumps neither). Stale rows are reaped by the regular cache
/// cleanup. v2 = ARCH-0039 Layer-1 normalization + λ_τ table + not-traversed
/// gates + retracted skip (ONE-1100). v3 = ARCH-0039 Layer-2 seed specificity
/// (ONE-1116): `search_ppr` seeds are weighted `1/ln(1 + passage_count)`
/// instead of uniform `1/n`, and the cache key gained a [`SeedWeighting`]
/// byte. v4 = ONE-1236 lexical query hint side claims are skipped during
/// `ClaimOf` traversal so synthetic hint records do not consume transition
/// mass. v5 = stored-edge VAD salience, with both alphas in cache identity.
pub(super) const PPR_FORMULA_VERSION: u32 = 5;
pub(crate) const MAX_PPR_SEEDS: usize = 256;
/// Recency-tiered `ppr_cache` serve TTL (ARCH-0019 "PPR cache TTL" table /
/// ARCH-0014 "TTL strategy"; ONE-1116 pinned decision).
///
/// Recency source: `max(learned_at)` over the SEED SET — the most recently
/// learned seed entity decides the tier, evaluated against `now` at read
/// time. Tiers (boundaries inclusive on the slower side):
///
/// - `< 7d`  → Active  → [`CACHE_TTL_ACTIVE_SECS`] (24 h)
/// - `7–30d` → Recent  → [`CACHE_TTL_RECENT_SECS`] (72 h)
/// - `≥ 30d` → Dormant → [`CACHE_TTL_DORMANT_SECS`] (168 h)
///
/// Fail-closed defaults: seeds WITHOUT an entity record (graph-only ids,
/// which `seed_is_live_for_ppr` recognizes as legitimate) contribute no
/// `learned_at`; if NO seed has one, the SHORTEST tier (Active, 24 h)
/// applies. A present-but-unparsable entity record short-circuits to the
/// shortest tier as well. A `learned_at` in the future saturates to age 0
/// (Active).
///
/// Because the tier is re-evaluated per read while `computed_at` is fixed in
/// the row header, a row's serve window can lengthen as its seeds age across
/// the 7 d / 30 d boundaries — TTL is a freshness heuristic; correctness is
/// owned by the graph-version + stale gates.
pub(super) fn recency_tiered_cache_ttl_secs(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    seeds: &[EntityId],
    now: u64,
) -> Result<u64> {
    let mut max_learned_at: Option<u64> = None;
    for seed in seeds {
        let Some(raw) = store.entities().get(txn, seed.as_bytes())? else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            return Ok(CACHE_TTL_ACTIVE_SECS);
        };
        max_learned_at =
            Some(max_learned_at.map_or(header.learned_at, |seen| seen.max(header.learned_at)));
    }

    let Some(latest_learned_at) = max_learned_at else {
        return Ok(CACHE_TTL_ACTIVE_SECS);
    };

    let seed_recency_secs = now.saturating_sub(latest_learned_at);
    Ok(if seed_recency_secs < SEED_RECENCY_ACTIVE_LIMIT_SECS {
        CACHE_TTL_ACTIVE_SECS
    } else if seed_recency_secs < SEED_RECENCY_RECENT_LIMIT_SECS {
        CACHE_TTL_RECENT_SECS
    } else {
        CACHE_TTL_DORMANT_SECS
    })
}
pub(crate) fn flush_deferred_ppr_cache_writes(
    store: &Store,
    writes: &[DeferredPprCacheWrite],
) -> Result<()> {
    for write in writes {
        if let Some(snapshot) = &write.community_snapshot {
            // Both local caches describe the same read snapshot. Never publish
            // either after a concurrent graph mutation, and never publish a
            // partially replaced logical family.
            let mut txn = store.env.write_txn()?;
            if read_graph_version(store, &txn)? != write.graph_version {
                continue;
            }
            store.replace_ppr_community_cache_in_txn(&mut txn, snapshot)?;
            if let Some(state) = &write.state {
                store_cache_entry(
                    store,
                    &mut txn,
                    &write.seed_hash,
                    write.computed_at,
                    write.graph_version,
                    state,
                )?;
            }
            txn.commit()?;
        } else if let Some(state) = &write.state {
            // Literal legacy write path for beta zero and Specificity.
            write_ppr_cache(
                store,
                &write.seed_hash,
                write.computed_at,
                write.graph_version,
                state,
            )?;
        }
    }
    Ok(())
}
fn write_ppr_cache(
    store: &Store,
    seed_hash: &[u8; SEED_HASH_LEN],
    computed_at: u64,
    graph_version: u64,
    state: &PprCacheState,
) -> Result<()> {
    {
        let rtxn = store.env.read_txn()?;
        if read_graph_version(store, &rtxn)? != graph_version {
            return Ok(());
        }
    }

    let mut wtxn = store.env.write_txn()?;
    if store_cache_entry(
        store,
        &mut wtxn,
        seed_hash,
        computed_at,
        graph_version,
        state,
    )? {
        wtxn.commit()?;
    }
    Ok(())
}
/// SLIM (ONE-1933 / OF-447) concrete PPR drop producer: clears the whole
/// derived cache inside the caller's write transaction.
///
/// Touches ONLY `ppr_cache` and `ppr_cache_deps` — never edges, the graph
/// version, seeds, entities, or any optional external warm tier. No new state
/// flag is needed: the existing cache-miss path (`read_exact_cache_row` →
/// compute/resume → deferred cache write) is the lazy rebuild, so the first
/// query after a shed recomputes and repopulates exactly as a cold vault does.
///
/// The caller commits, in the same write transaction as
/// [`crate::hnsw::drop_rebuildable_hnsw`], so the persisted derived-index half
/// of a shed commits together; any failure aborts and leaves both untouched.
pub(crate) fn drop_rebuildable_ppr_cache(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
) -> Result<crate::slim::HeapDropReport> {
    let mut ppr_cache_rows = 0_u64;
    let mut ppr_dependency_rows = 0_u64;
    let mut estimated_reclaimed_bytes = 0_u64;

    for entry in store.ppr_cache().iter(&*wtxn)? {
        let (key, value) = entry?;
        ppr_cache_rows = ppr_cache_rows
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("ppr cache row count"))?;
        estimated_reclaimed_bytes =
            estimated_reclaimed_bytes.saturating_add((key.len() + value.len()) as u64);
    }
    for entry in store.ppr_cache_deps.iter(&*wtxn)? {
        let (key, value) = entry?;
        ppr_dependency_rows = ppr_dependency_rows
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("ppr cache dep row count"))?;
        estimated_reclaimed_bytes =
            estimated_reclaimed_bytes.saturating_add((key.len() + value.len()) as u64);
    }

    store.ppr_cache().clear(wtxn)?;
    store.ppr_cache_deps.clear(wtxn)?;

    Ok(crate::slim::HeapDropReport {
        ppr_cache_rows,
        ppr_dependency_rows,
        estimated_reclaimed_bytes,
        ..crate::slim::HeapDropReport::default()
    })
}
/// Evicts `ppr_cache` rows that are stale-flagged, malformed, older than
/// `max_age_secs`, or whose seed dependencies are dead.
///
/// `max_age_secs` is a HARD eviction bound and is deliberately independent
/// of the recency-tiered serve TTL (ARCH-0019 / ARCH-0014; see
/// [`recency_tiered_cache_ttl_secs`]): servability is decided exclusively by
/// the read gate in `ppr_query_in_txn_impl`. Callers that do not want to
/// evict rows the tiered read gate could still serve must pass at least
/// [`CACHE_TTL_DORMANT_SECS`] (168 h, the longest tier). Rows in a shorter
/// tier that have outlived their serve TTL are unreachable through the read
/// gate either way and are reaped here once they exceed `max_age_secs`.
pub(crate) fn cleanup_ppr_cache(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    max_age_secs: u64,
    now: u64,
) -> Result<(u64, u64)> {
    let mut cache_keys_to_delete = Vec::new();
    let mut cache_seed_hashes = HashSet::<[u8; SEED_HASH_LEN]>::new();
    for entry in store.ppr_cache().iter(&*wtxn)? {
        let (seed_hash_key, value) = entry?;
        if seed_hash_key.len() != SEED_HASH_LEN {
            cache_keys_to_delete.push(seed_hash_key.to_vec());
            continue;
        }

        let (computed_at, _, stale) = match parse_cache_header(&value) {
            Ok(header) => header,
            Err(Error::CorruptedIndex(_)) => {
                cache_keys_to_delete.push(seed_hash_key.to_vec());
                continue;
            }
            Err(err) => return Err(err),
        };
        if stale != 0 || now.saturating_sub(computed_at) > max_age_secs {
            cache_keys_to_delete.push(seed_hash_key.to_vec());
            continue;
        }

        let mut seed_hash = [0_u8; SEED_HASH_LEN];
        seed_hash.copy_from_slice(&seed_hash_key);
        cache_seed_hashes.insert(seed_hash);
    }

    for key in &cache_keys_to_delete {
        store.ppr_cache().delete(wtxn, key)?;
    }

    let mut seed_liveness = HashMap::<EntityId, bool>::new();
    let mut dead_seed_hashes = HashSet::<[u8; SEED_HASH_LEN]>::new();
    let mut surviving_seed_hashes = HashSet::<[u8; SEED_HASH_LEN]>::new();
    let mut dep_keys_to_delete = Vec::new();
    let mut surviving_dep_rows = Vec::<(Vec<u8>, [u8; SEED_HASH_LEN])>::new();
    for entry in store.ppr_cache_deps.iter(&*wtxn)? {
        let (dep_key, _) = entry?;
        if dep_key.len() != CACHE_DEP_KEY_LEN {
            dep_keys_to_delete.push(dep_key.to_vec());
            continue;
        }

        let (entity_id, seed_hash) = match decode_dep_key(&dep_key) {
            Ok(decoded) => decoded,
            Err(Error::CorruptedIndex(_)) => {
                dep_keys_to_delete.push(dep_key.to_vec());
                continue;
            }
            Err(err) => return Err(err),
        };

        if store.ppr_cache().get(&*wtxn, &seed_hash)?.is_none() {
            dep_keys_to_delete.push(dep_key.to_vec());
            continue;
        }

        let is_live = if let Some(&cached) = seed_liveness.get(&entity_id) {
            cached
        } else {
            let live = seed_is_live_for_ppr(store, &*wtxn, &entity_id)?;
            seed_liveness.insert(entity_id, live);
            live
        };

        if !is_live {
            dead_seed_hashes.insert(seed_hash);
        } else {
            surviving_seed_hashes.insert(seed_hash);
        }

        surviving_dep_rows.push((dep_key.to_vec(), seed_hash));
    }

    for seed_hash in cache_seed_hashes {
        if !dead_seed_hashes.contains(&seed_hash) && !surviving_seed_hashes.contains(&seed_hash) {
            dead_seed_hashes.insert(seed_hash);
        }
    }

    for seed_hash in &dead_seed_hashes {
        store.ppr_cache().delete(wtxn, seed_hash)?;
    }

    for (dep_key, seed_hash) in surviving_dep_rows {
        if dead_seed_hashes.contains(&seed_hash) {
            dep_keys_to_delete.push(dep_key);
        }
    }

    for key in &dep_keys_to_delete {
        store.ppr_cache_deps.delete(wtxn, key)?;
    }

    Ok((
        (cache_keys_to_delete.len() + dead_seed_hashes.len()) as u64,
        dep_keys_to_delete.len() as u64,
    ))
}
fn invalidate_ppr_caches(store: &Store, wtxn: &mut RwTxn<'_>, entity_id: &EntityId) -> Result<()> {
    let mut hashes = HashSet::<[u8; SEED_HASH_LEN]>::new();
    let mut dep_keys_to_delete = Vec::new();
    for entry in store
        .ppr_cache_deps
        .prefix_iter(&*wtxn, entity_id.as_bytes())?
    {
        let (key, _) = entry?;
        if key.len() != CACHE_DEP_KEY_LEN {
            dep_keys_to_delete.push(key.to_vec());
            continue;
        }

        let mut seed_hash = [0_u8; SEED_HASH_LEN];
        seed_hash.copy_from_slice(&key[ENTITY_ID_LEN..CACHE_DEP_KEY_LEN]);
        hashes.insert(seed_hash);
    }

    for key in &dep_keys_to_delete {
        store.ppr_cache_deps.delete(wtxn, key)?;
    }

    for seed_hash in hashes {
        let Some(raw) = store.ppr_cache().get(&*wtxn, &seed_hash)? else {
            continue;
        };
        if raw.len() < CACHE_HEADER_LEN {
            store.ppr_cache().delete(wtxn, &seed_hash)?;
            continue;
        }
        let mut patched = raw.to_vec();
        patched[CACHE_STALE_OFFSET] = 1;
        store.ppr_cache().put(wtxn, &seed_hash, &patched)?;
    }

    Ok(())
}
fn seed_is_live_for_ppr(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    entity_id: &EntityId,
) -> Result<bool> {
    if store.entities().get(txn, entity_id.as_bytes())?.is_some() {
        return Ok(true);
    }

    if store
        .edges_out()
        .prefix_iter(txn, entity_id.as_bytes())?
        .next()
        .transpose()?
        .is_some()
    {
        return Ok(true);
    }

    if store
        .edges_in()
        .prefix_iter(txn, entity_id.as_bytes())?
        .next()
        .transpose()?
        .is_some()
    {
        return Ok(true);
    }

    Ok(false)
}
pub(super) fn store_cache_entry(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    seed_hash: &[u8; SEED_HASH_LEN],
    computed_at: u64,
    graph_version: u64,
    state: &PprCacheState,
) -> Result<bool> {
    if read_graph_version(store, &*wtxn)? != graph_version {
        return Ok(false);
    }

    let encoded = encode_cache_value_with_state(computed_at, graph_version, 0, state)?;
    store.ppr_cache().put(wtxn, seed_hash, &encoded)?;
    delete_dep_rows_for_seed_hash(store, wtxn, seed_hash)?;

    for dependency in &state.dependencies {
        let dep_key = encode_dep_key(dependency, seed_hash);
        store.ppr_cache_deps.put(wtxn, &dep_key, &[])?;
    }

    Ok(true)
}
fn delete_dep_rows_for_seed_hash(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    seed_hash: &[u8; SEED_HASH_LEN],
) -> Result<()> {
    let mut dep_keys = Vec::new();
    for entry in store.ppr_cache_deps.iter(&*wtxn)? {
        let (key, _) = entry?;
        if key.len() == CACHE_DEP_KEY_LEN && &key[ENTITY_ID_LEN..] == seed_hash {
            dep_keys.push(key.to_vec());
        }
    }

    for key in dep_keys {
        store.ppr_cache_deps.delete(wtxn, &key)?;
    }
    Ok(())
}
pub(crate) fn invalidate_ppr_for_edge(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    src: &EntityId,
    tgt: &EntityId,
) -> Result<()> {
    invalidate_ppr_caches(store, wtxn, src)?;
    invalidate_ppr_caches(store, wtxn, tgt)
}
pub(crate) fn invalidate_ppr_for_delete(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    neighbors: &[EntityId],
) -> Result<()> {
    invalidate_ppr_caches(store, wtxn, id)?;
    for neighbor in neighbors {
        invalidate_ppr_caches(store, wtxn, neighbor)?;
    }
    Ok(())
}
pub(crate) fn increment_graph_version(store: &Store, wtxn: &mut RwTxn<'_>) -> Result<()> {
    let current = read_graph_version(store, &*wtxn)?;
    let next = current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("ppr graph version"))?;
    store
        .hnsw_meta
        .put(wtxn, GRAPH_VERSION_KEY, &next.to_le_bytes())?;
    Ok(())
}
pub(super) fn encode_dep_key(
    entity_id: &EntityId,
    seed_hash: &[u8; SEED_HASH_LEN],
) -> [u8; CACHE_DEP_KEY_LEN] {
    let mut key = [0_u8; CACHE_DEP_KEY_LEN];
    key[..ENTITY_ID_LEN].copy_from_slice(entity_id.as_bytes());
    key[ENTITY_ID_LEN..].copy_from_slice(seed_hash);
    key
}
pub(super) fn parse_cache_header(bytes: &[u8]) -> Result<(u64, u64, u8)> {
    if bytes.len() < CACHE_HEADER_LEN {
        return Err(Error::CorruptedIndex("ppr cache header"));
    }

    let computed_at = decode_u64(&bytes[..8], "ppr cache header")?;
    let graph_version = decode_u64(&bytes[8..16], "ppr cache header")?;
    let stale = bytes[CACHE_STALE_OFFSET];
    Ok((computed_at, graph_version, stale))
}
#[cfg(test)]
pub(super) fn decode_cache_scores(payload: &[u8]) -> Result<Vec<ScoredEntity>> {
    let decoded = decode_cache_payload(payload)?;
    Ok(decoded.into_scores())
}
pub(super) fn decode_cache_payload(payload: &[u8]) -> Result<CachedPprRow> {
    if is_state_cache_payload(payload) {
        let state = decode_cache_state(payload)?;
        return Ok(CachedPprRow::State(state));
    }

    Ok(CachedPprRow::Scores(decode_legacy_cache_scores(payload)?))
}
fn decode_legacy_cache_scores(payload: &[u8]) -> Result<Vec<ScoredEntity>> {
    if !payload.len().is_multiple_of(CACHE_ENTRY_LEN) {
        return Err(Error::CorruptedIndex("ppr cache scores"));
    }

    let (chunks, rem) = payload.as_chunks::<CACHE_ENTRY_LEN>();
    debug_assert!(rem.is_empty());
    chunks
        .iter()
        .map(|&[id_bytes @ .., s0, s1, s2, s3]| {
            let id = EntityId::from_bytes(id_bytes)
                .map_err(|_| Error::CorruptedIndex("ppr cache scores"))?;
            let score = f32::from_le_bytes([s0, s1, s2, s3]);
            if !score.is_finite() {
                return Err(Error::CorruptedIndex("ppr cache scores"));
            }
            Ok(ScoredEntity { id, score })
        })
        .collect()
}
fn is_state_cache_payload(payload: &[u8]) -> bool {
    // Legacy score-only rows are exactly `[EntityId | f32] * n`, so their
    // payload length is always a multiple of `CACHE_ENTRY_LEN`. Current state
    // rows start with `FPRS` but have a 21-byte prefix, making that shape
    // impossible; use both checks so a legacy EntityId may safely begin with
    // the state magic bytes.
    payload.starts_with(CACHE_STATE_MAGIC) && !payload.len().is_multiple_of(CACHE_ENTRY_LEN)
}
pub(super) fn decode_cache_state(payload: &[u8]) -> Result<PprCacheState> {
    if payload.len() < CACHE_STATE_PREFIX_LEN {
        return Err(Error::CorruptedIndex("ppr cache state"));
    }
    if &payload[..CACHE_STATE_MAGIC.len()] != CACHE_STATE_MAGIC {
        return Err(Error::CorruptedIndex("ppr cache state"));
    }
    if payload[CACHE_STATE_MAGIC.len()] != CACHE_STATE_VERSION {
        return Err(Error::CorruptedIndex("ppr cache state"));
    }

    let completed_depth = decode_u32(&payload[5..9], "ppr cache state")?;
    let score_count = decode_u32(&payload[9..13], "ppr cache state")? as usize;
    let frontier_count = decode_u32(&payload[13..17], "ppr cache state")? as usize;
    let dependency_count = decode_u32(&payload[17..21], "ppr cache state")? as usize;

    let score_bytes = score_count
        .checked_mul(CACHE_ENTRY_LEN)
        .ok_or(Error::CorruptedIndex("ppr cache state"))?;
    let frontier_bytes = frontier_count
        .checked_mul(CACHE_FRONTIER_ENTRY_LEN)
        .ok_or(Error::CorruptedIndex("ppr cache state"))?;
    let dependency_bytes = dependency_count
        .checked_mul(ENTITY_ID_LEN)
        .ok_or(Error::CorruptedIndex("ppr cache state"))?;
    let expected_len = CACHE_STATE_PREFIX_LEN
        .checked_add(score_bytes)
        .and_then(|len| len.checked_add(frontier_bytes))
        .and_then(|len| len.checked_add(dependency_bytes))
        .ok_or(Error::CorruptedIndex("ppr cache state"))?;
    if payload.len() != expected_len {
        return Err(Error::CorruptedIndex("ppr cache state"));
    }

    let scores_start = CACHE_STATE_PREFIX_LEN;
    let frontier_start = scores_start + score_bytes;
    let dependency_start = frontier_start + frontier_bytes;

    let scores = decode_legacy_cache_scores(&payload[scores_start..frontier_start])?;
    let mut frontier = Vec::with_capacity(frontier_count);
    for chunk in payload[frontier_start..dependency_start].chunks_exact(CACHE_FRONTIER_ENTRY_LEN) {
        let id = EntityId::from_bytes(
            chunk[..ENTITY_ID_LEN]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("ppr cache state"))?,
        )
        .map_err(|_| Error::CorruptedIndex("ppr cache state"))?;
        let structural_hops =
            decode_u32(&chunk[ENTITY_ID_LEN..ENTITY_ID_LEN + 4], "ppr cache state")?;
        let score = f32::from_le_bytes(
            chunk[ENTITY_ID_LEN + 4..ENTITY_ID_LEN + 8]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("ppr cache state"))?,
        );
        if !score.is_finite() {
            return Err(Error::CorruptedIndex("ppr cache state"));
        }
        frontier.push(PprFrontierEntry {
            id,
            structural_hops,
            score,
        });
    }

    let mut dependencies = Vec::with_capacity(dependency_count);
    for chunk in payload[dependency_start..].chunks_exact(ENTITY_ID_LEN) {
        dependencies.push(
            EntityId::from_bytes(
                chunk
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("ppr cache state"))?,
            )
            .map_err(|_| Error::CorruptedIndex("ppr cache state"))?,
        );
    }

    Ok(PprCacheState {
        completed_depth,
        scores,
        frontier,
        dependencies,
    })
}
#[cfg(test)]
pub(super) fn encode_cache_value(
    computed_at: u64,
    graph_version: u64,
    stale: u8,
    scores: &[ScoredEntity],
) -> Vec<u8> {
    let mut value = Vec::with_capacity(CACHE_HEADER_LEN + scores.len() * CACHE_ENTRY_LEN);
    value.extend_from_slice(&computed_at.to_le_bytes());
    value.extend_from_slice(&graph_version.to_le_bytes());
    value.push(stale);
    for scored in scores {
        value.extend_from_slice(scored.id.as_bytes());
        value.extend_from_slice(&scored.score.to_le_bytes());
    }
    value
}
pub(super) fn encode_cache_value_with_state(
    computed_at: u64,
    graph_version: u64,
    stale: u8,
    state: &PprCacheState,
) -> Result<Vec<u8>> {
    let score_count =
        u32::try_from(state.scores.len()).map_err(|_| Error::CorruptedIndex("ppr cache state"))?;
    let frontier_count = u32::try_from(state.frontier.len())
        .map_err(|_| Error::CorruptedIndex("ppr cache state"))?;
    let dependency_count = u32::try_from(state.dependencies.len())
        .map_err(|_| Error::CorruptedIndex("ppr cache state"))?;

    let mut value = Vec::with_capacity(
        CACHE_HEADER_LEN
            + CACHE_STATE_PREFIX_LEN
            + state.scores.len() * CACHE_ENTRY_LEN
            + state.frontier.len() * CACHE_FRONTIER_ENTRY_LEN
            + state.dependencies.len() * ENTITY_ID_LEN,
    );
    value.extend_from_slice(&computed_at.to_le_bytes());
    value.extend_from_slice(&graph_version.to_le_bytes());
    value.push(stale);
    value.extend_from_slice(CACHE_STATE_MAGIC);
    value.push(CACHE_STATE_VERSION);
    value.extend_from_slice(&state.completed_depth.to_le_bytes());
    value.extend_from_slice(&score_count.to_le_bytes());
    value.extend_from_slice(&frontier_count.to_le_bytes());
    value.extend_from_slice(&dependency_count.to_le_bytes());
    for scored in &state.scores {
        value.extend_from_slice(scored.id.as_bytes());
        value.extend_from_slice(&scored.score.to_le_bytes());
    }
    for entry in &state.frontier {
        value.extend_from_slice(entry.id.as_bytes());
        value.extend_from_slice(&entry.structural_hops.to_le_bytes());
        value.extend_from_slice(&entry.score.to_le_bytes());
    }
    for dependency in &state.dependencies {
        value.extend_from_slice(dependency.as_bytes());
    }
    Ok(value)
}
pub(crate) fn read_graph_version(store: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<u64> {
    let Some(raw) = store.hnsw_meta().get(txn, GRAPH_VERSION_KEY)? else {
        return Ok(0);
    };
    decode_u64(&raw, "ppr graph version")
}
fn decode_u64(raw: &[u8], context: &'static str) -> Result<u64> {
    let bytes: [u8; 8] = raw.try_into().map_err(|_| Error::CorruptedIndex(context))?;
    Ok(u64::from_le_bytes(bytes))
}
fn decode_u32(raw: &[u8], context: &'static str) -> Result<u32> {
    let bytes: [u8; 4] = raw.try_into().map_err(|_| Error::CorruptedIndex(context))?;
    Ok(u32::from_le_bytes(bytes))
}
fn decode_dep_key(dep_key: &[u8]) -> Result<(EntityId, [u8; SEED_HASH_LEN])> {
    if dep_key.len() != CACHE_DEP_KEY_LEN {
        return Err(Error::CorruptedIndex("ppr cache dep"));
    }

    let entity_id = EntityId::from_bytes(
        dep_key[..ENTITY_ID_LEN]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("ppr cache dep"))?,
    )
    .map_err(|_| Error::CorruptedIndex("ppr cache dep"))?;
    let seed_hash = dep_key[ENTITY_ID_LEN..]
        .try_into()
        .map_err(|_| Error::CorruptedIndex("ppr cache dep"))?;
    Ok((entity_id, seed_hash))
}
