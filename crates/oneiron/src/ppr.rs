#![cfg_attr(not(test), allow(dead_code))]

use std::collections::{HashMap, HashSet};

use heed::{RoTxn, RwTxn};
use xxhash_rust::xxh32::xxh32;

use crate::error::{Error, Result};
use crate::store::Store;
use crate::types::{EdgeKind, EntityId, ScoredEntity, VaultConfig, ENTITY_ID_LEN};

const EDGE_KEY_LEN: usize = 33;
const EDGE_VALUE_LEN: usize = 12;
const SEED_HASH_LEN: usize = 32;
const CACHE_HEADER_LEN: usize = 17;
const CACHE_STALE_OFFSET: usize = 16;
const CACHE_ENTRY_LEN: usize = 20;
const CACHE_DEP_KEY_LEN: usize = ENTITY_ID_LEN + SEED_HASH_LEN;
const CACHE_TTL_SECS: u64 = 86_400;
const GRAPH_VERSION_KEY: &[u8] = b"graph_version";
const SCORE_EPSILON: f32 = 1e-10;

pub(crate) fn ppr_compute(
    store: &Store,
    txn: &RoTxn<'_>,
    seeds: &[EntityId],
    depth: u32,
    alpha: f32,
) -> Result<Vec<ScoredEntity>> {
    if seeds.is_empty() {
        return Ok(Vec::new());
    }

    let init = 1.0 / seeds.len() as f32;
    let mut scores = HashMap::<EntityId, f32>::new();
    let mut frontier = HashMap::<(EntityId, u32), f32>::new();

    for seed in seeds {
        *scores.entry(*seed).or_default() += init;
        *frontier.entry((*seed, 0)).or_default() += init;
    }

    let edge_dbs = [&store.edges_out, &store.edges_in];

    for _ in 0..depth {
        if frontier.is_empty() {
            break;
        }

        let total: f32 = frontier.values().copied().sum();
        let mut next = HashMap::<(EntityId, u32), f32>::new();

        for (&(node, hops), &score) in &frontier {
            if score < SCORE_EPSILON {
                continue;
            }

            for db in edge_dbs {
                for entry in db.prefix_iter(txn, node.as_bytes())? {
                    let (key, value) = entry?;
                    propagate_edge(key, value, hops, score, alpha, &mut next)?;
                }
            }
        }

        let teleport = total * alpha / seeds.len() as f32;
        for seed in seeds {
            *next.entry((*seed, 0)).or_default() += teleport;
        }

        for (&(node, _), &score) in &next {
            *scores.entry(node).or_default() += score;
        }

        frontier = next;
    }

    let mut ranked: Vec<ScoredEntity> = scores
        .into_iter()
        .map(|(id, score)| ScoredEntity { id, score })
        .collect();
    sort_scores(&mut ranked);
    Ok(ranked)
}

pub(crate) fn ppr_query(
    store: &Store,
    _config: &VaultConfig,
    seeds: &[EntityId],
    depth: u32,
    alpha: f32,
) -> Result<Vec<ScoredEntity>> {
    if seeds.is_empty() {
        return Ok(Vec::new());
    }

    let seed_hash = hash_seeds(seeds);
    let now = crate::unix_seconds_now();

    {
        let rtxn = store.env.read_txn()?;
        if let Some(raw) = store.ppr_cache.get(&rtxn, &seed_hash)? {
            let (computed_at, _, stale) = parse_cache_header(raw)?;
            if stale == 0 && now.saturating_sub(computed_at) <= CACHE_TTL_SECS {
                let mut scores = decode_cache_scores(&raw[CACHE_HEADER_LEN..])?;
                sort_scores(&mut scores);
                return Ok(scores);
            }
        }
    }

    let (scores, graph_version) = {
        let rtxn = store.env.read_txn()?;
        let scores = ppr_compute(store, &rtxn, seeds, depth, alpha)?;
        let version = read_graph_version(store, &rtxn)?;
        (scores, version)
    };

    let encoded = encode_cache_value(now, graph_version, 0, &scores);
    let mut wtxn = store.env.write_txn()?;
    store.ppr_cache.put(&mut wtxn, &seed_hash, &encoded)?;

    for seed in seeds {
        let dep_key = encode_dep_key(seed, &seed_hash);
        store.ppr_cache_deps.put(&mut wtxn, &dep_key, &[])?;
    }

    wtxn.commit()?;
    Ok(scores)
}

fn invalidate_ppr_caches(store: &Store, wtxn: &mut RwTxn<'_>, entity_id: &EntityId) -> Result<()> {
    let mut hashes = HashSet::<[u8; SEED_HASH_LEN]>::new();
    for entry in store
        .ppr_cache_deps
        .prefix_iter(&*wtxn, entity_id.as_bytes())?
    {
        let (key, _) = entry?;
        if key.len() != CACHE_DEP_KEY_LEN {
            return Err(Error::InvalidKey);
        }

        let mut seed_hash = [0_u8; SEED_HASH_LEN];
        seed_hash.copy_from_slice(&key[ENTITY_ID_LEN..CACHE_DEP_KEY_LEN]);
        hashes.insert(seed_hash);
    }

    for seed_hash in hashes {
        if let Some(raw) = store.ppr_cache.get(&*wtxn, &seed_hash)? {
            if raw.len() < CACHE_HEADER_LEN {
                return Err(Error::InvalidKey);
            }
            let mut patched = raw.to_vec();
            patched[CACHE_STALE_OFFSET] = 1;
            store.ppr_cache.put(wtxn, &seed_hash, &patched)?;
        }
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
    invalidate_ppr_caches(store, wtxn, tgt)?;
    increment_graph_version(store, wtxn)
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
    if !neighbors.is_empty() {
        increment_graph_version(store, wtxn)?;
    }
    Ok(())
}

fn increment_graph_version(store: &Store, wtxn: &mut RwTxn<'_>) -> Result<()> {
    let current = read_graph_version(store, &*wtxn)?;
    let next = current.checked_add(1).ok_or(Error::InvalidKey)?;
    store
        .hnsw_meta
        .put(wtxn, GRAPH_VERSION_KEY, &next.to_le_bytes())?;
    Ok(())
}

fn propagate_edge(
    key: &[u8],
    value: &[u8],
    hops: u32,
    score: f32,
    alpha: f32,
    next: &mut HashMap<(EntityId, u32), f32>,
) -> Result<()> {
    if key.len() != EDGE_KEY_LEN || value.len() != EDGE_VALUE_LEN {
        return Err(Error::InvalidKey);
    }

    let kind = EdgeKind::try_from_u8(key[16]).ok_or(Error::InvalidKey)?;
    let neighbor = EntityId::from_bytes(key[17..33].try_into().map_err(|_| Error::InvalidKey)?);
    let weight = f32::from_le_bytes(value[..4].try_into().map_err(|_| Error::InvalidKey)?);
    if weight == 0.0 {
        return Ok(());
    }

    // PartOf edges count as structural hops; cap at 2 to limit hierarchy depth.
    let new_hops = if kind == EdgeKind::PartOf {
        hops.checked_add(1).ok_or(Error::InvalidKey)?
    } else {
        hops
    };
    if new_hops > 2 {
        return Ok(());
    }

    let propagated = score * weight * (1.0 - alpha);
    *next.entry((neighbor, new_hops)).or_default() += propagated;
    Ok(())
}

fn sort_scores(scores: &mut [ScoredEntity]) {
    scores.sort_unstable_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.id.as_bytes().cmp(b.id.as_bytes()))
    });
}

fn hash_seeds(seeds: &[EntityId]) -> [u8; SEED_HASH_LEN] {
    let mut sorted = seeds.to_vec();
    sorted.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

    let bytes: Vec<u8> = sorted.iter().flat_map(|seed| *seed.as_bytes()).collect();

    let mut out = [0_u8; SEED_HASH_LEN];
    out[..4].copy_from_slice(&xxh32(&bytes, 0).to_le_bytes());
    out
}

fn encode_dep_key(
    entity_id: &EntityId,
    seed_hash: &[u8; SEED_HASH_LEN],
) -> [u8; CACHE_DEP_KEY_LEN] {
    let mut key = [0_u8; CACHE_DEP_KEY_LEN];
    key[..ENTITY_ID_LEN].copy_from_slice(entity_id.as_bytes());
    key[ENTITY_ID_LEN..].copy_from_slice(seed_hash);
    key
}

fn parse_cache_header(bytes: &[u8]) -> Result<(u64, u64, u8)> {
    if bytes.len() < CACHE_HEADER_LEN {
        return Err(Error::InvalidKey);
    }

    let computed_at = decode_u64(&bytes[..8])?;
    let graph_version = decode_u64(&bytes[8..16])?;
    let stale = bytes[CACHE_STALE_OFFSET];
    Ok((computed_at, graph_version, stale))
}

fn decode_cache_scores(payload: &[u8]) -> Result<Vec<ScoredEntity>> {
    if !payload.len().is_multiple_of(CACHE_ENTRY_LEN) {
        return Err(Error::InvalidKey);
    }

    payload
        .chunks_exact(CACHE_ENTRY_LEN)
        .map(|chunk| {
            let id = EntityId::from_bytes(
                chunk[..ENTITY_ID_LEN]
                    .try_into()
                    .map_err(|_| Error::InvalidKey)?,
            );
            let score = f32::from_le_bytes(
                chunk[ENTITY_ID_LEN..CACHE_ENTRY_LEN]
                    .try_into()
                    .map_err(|_| Error::InvalidKey)?,
            );
            Ok(ScoredEntity { id, score })
        })
        .collect()
}

fn encode_cache_value(
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

fn read_graph_version(store: &Store, txn: &RoTxn<'_>) -> Result<u64> {
    let Some(raw) = store.hnsw_meta.get(txn, GRAPH_VERSION_KEY)? else {
        return Ok(0);
    };
    decode_u64(raw)
}

fn decode_u64(raw: &[u8]) -> Result<u64> {
    let bytes: [u8; 8] = raw.try_into().map_err(|_| Error::InvalidKey)?;
    Ok(u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::{EdgeKind, Error, HnswConfig, TimeRange, Vault, VaultConfig};

    fn test_config() -> VaultConfig {
        VaultConfig {
            map_size: 16 * 1024 * 1024,
            dimensions: 4,
            embedding_model: None,
            max_readers: 16,
            hnsw: HnswConfig {
                m_max_0: 64,
                ef_construction: 200,
                ef_search: 128,
            },
        }
    }

    fn entity(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; ENTITY_ID_LEN])
    }

    fn score_for(scores: &[ScoredEntity], id: EntityId) -> f32 {
        scores
            .iter()
            .find(|scored| scored.id == id)
            .map_or(0.0, |scored| scored.score)
    }

    fn assert_scores_equal(left: &[ScoredEntity], right: &[ScoredEntity]) {
        assert_eq!(left.len(), right.len());
        for (lhs, rhs) in left.iter().zip(right.iter()) {
            assert_eq!(lhs.id, rhs.id);
            assert!((lhs.score - rhs.score).abs() <= 1e-6);
        }
    }

    fn cache_row(vault: &Vault, seeds: &[EntityId]) -> Result<Vec<u8>> {
        let hash = hash_seeds(seeds);
        let rtxn = vault.store.env.read_txn()?;
        let row = vault
            .store
            .ppr_cache
            .get(&rtxn, &hash)?
            .ok_or(Error::EntityNotFound)?;
        Ok(row.to_vec())
    }

    #[test]
    fn ppr_simple_chain_scores_b_over_c() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(1);
        let b = entity(2);
        let c = entity(3);

        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
        vault.put_edge(&b, EdgeKind::BelongsTo, &c, 1.0)?;

        let rtxn = vault.store.env.read_txn()?;
        let scores = ppr_compute(&vault.store, &rtxn, &[a], 3, 0.15)?;
        assert!(score_for(&scores, b) > score_for(&scores, c));
        Ok(())
    }

    #[test]
    fn ppr_weighted_edges_favor_heavier_neighbor() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(4);
        let b = entity(5);
        let c = entity(6);

        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 0.9)?;
        vault.put_edge(&a, EdgeKind::BelongsTo, &c, 0.1)?;

        let rtxn = vault.store.env.read_txn()?;
        let scores = ppr_compute(&vault.store, &rtxn, &[a], 3, 0.15)?;
        assert!(score_for(&scores, b) >= score_for(&scores, c) * 2.0);
        Ok(())
    }

    #[test]
    fn ppr_opposes_weight_zero_blocks_propagation() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(7);
        let b = entity(8);

        vault.put_edge(&a, EdgeKind::Opposes, &b, 0.0)?;

        let rtxn = vault.store.env.read_txn()?;
        let scores = ppr_compute(&vault.store, &rtxn, &[a], 3, 0.15)?;
        assert!(score_for(&scores, b) <= 1e-6);
        Ok(())
    }

    #[test]
    fn ppr_part_of_hop_limit_blocks_third_hop() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(9);
        let b = entity(10);
        let c = entity(11);
        let d = entity(12);

        vault.put_edge(&a, EdgeKind::PartOf, &b, 1.0)?;
        vault.put_edge(&b, EdgeKind::PartOf, &c, 1.0)?;
        vault.put_edge(&c, EdgeKind::PartOf, &d, 1.0)?;

        let rtxn = vault.store.env.read_txn()?;
        let scores = ppr_compute(&vault.store, &rtxn, &[a], 5, 0.15)?;
        assert!(score_for(&scores, d) <= 1e-6);
        Ok(())
    }

    #[test]
    fn ppr_bidirectional_scan_reaches_inbound_neighbors() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(13);
        let b = entity(14);
        let c = entity(15);

        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
        vault.put_edge(&c, EdgeKind::BelongsTo, &b, 1.0)?;

        let rtxn = vault.store.env.read_txn()?;
        let scores = ppr_compute(&vault.store, &rtxn, &[a], 3, 0.15)?;
        assert!(score_for(&scores, c) > 0.0);
        Ok(())
    }

    #[test]
    fn ppr_query_uses_cache_when_valid() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(16);
        let b = entity(17);

        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;

        let first = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
        let cache_after_first = cache_row(&vault, &[a])?;
        let second = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
        let cache_after_second = cache_row(&vault, &[a])?;

        assert_scores_equal(&first, &second);
        assert_eq!(cache_after_first, cache_after_second);
        Ok(())
    }

    #[test]
    fn ppr_cache_is_marked_stale_and_refreshed_after_edge_write() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(18);
        let b = entity(19);

        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;

        let first = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
        let cache_before = cache_row(&vault, &[a])?;
        assert_eq!(cache_before[16], 0);

        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 0.2)?;
        let cache_stale = cache_row(&vault, &[a])?;
        assert_eq!(cache_stale[16], 1);

        let second = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
        let cache_after = cache_row(&vault, &[a])?;
        assert_eq!(cache_after[16], 0);
        assert_ne!(cache_stale, cache_after);

        let b_score_before = score_for(&first, b);
        let b_score_after = score_for(&second, b);
        assert!((b_score_before - b_score_after).abs() > SCORE_EPSILON);
        Ok(())
    }

    #[test]
    fn ppr_cache_invalidated_on_entity_delete() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(20);
        let b = entity(21);
        let c = entity(22);

        // Build entity records so delete_entity can find them.
        let tr = TimeRange { start: 1, end: 1 };
        vault.put_entity(&a, 1, tr, 1, b"a-data")?;
        vault.put_entity(&b, 1, tr, 1, b"b-data")?;
        vault.put_entity(&c, 1, tr, 1, b"c-data")?;

        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
        vault.put_edge(&b, EdgeKind::BelongsTo, &c, 1.0)?;

        // Populate the cache for seeds [a].
        let _scores = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
        let cache_before = cache_row(&vault, &[a])?;
        assert_eq!(cache_before[CACHE_STALE_OFFSET], 0);

        // Delete entity b — removes a->b and b->c edges.
        vault.delete_entity(&b)?;

        // Cache for seeds [a] must now be stale because a's edge to b was removed.
        let cache_after = cache_row(&vault, &[a])?;
        assert_eq!(cache_after[CACHE_STALE_OFFSET], 1);
        Ok(())
    }
}
