use std::collections::{HashMap, HashSet};

use heed::{RoTxn, RwTxn};
use xxhash_rust::xxh3::xxh3_128;

use crate::batch::EntityMetadataHeader;
use crate::error::{Error, Result};
use crate::store::Store;
#[cfg(test)]
use crate::types::EDGE_VALUE_STRUCTURAL_LEN;
#[cfg(test)]
use crate::types::VaultConfig;
use crate::types::{
    EDGE_KEY_LEN, ENTITY_ID_LEN, EdgeConfirmationStatus, EdgeKind, EntityId, ScoredEntity,
    decode_edge_value_for_kind,
};

const SEED_HASH_LEN: usize = 16;
#[cfg(test)]
const LEGACY_SEED_HASH_LEN: usize = 32;
const CACHE_HEADER_LEN: usize = 17;
const CACHE_STALE_OFFSET: usize = 16;
const CACHE_ENTRY_LEN: usize = 20;
const CACHE_DEP_KEY_LEN: usize = ENTITY_ID_LEN + SEED_HASH_LEN;
#[cfg(test)]
const LEGACY_CACHE_DEP_KEY_LEN: usize = ENTITY_ID_LEN + LEGACY_SEED_HASH_LEN;

// ARCH-0019 "PPR cache TTL" table / ARCH-0014 "TTL strategy" (recency-tiered,
// ONE-1116). The serve-TTL of a `ppr_cache` row is a step function of the
// SEED-SET recency — `max(learned_at)` over the query's seed entities,
// evaluated against `now` at READ time (see
// [`recency_tiered_cache_ttl_secs`]):
//
//   Active  · seed recency <  7 days → 24 h  (86_400 s)   "keep fresh"
//   Recent  · 7 – 30 days            → 72 h  (259_200 s)  "less volatile"
//   Dormant · ≥ 30 days              → 168 h (604_800 s)  "stable, long TTL"
const CACHE_TTL_ACTIVE_SECS: u64 = 86_400;
const CACHE_TTL_RECENT_SECS: u64 = 259_200;
pub(crate) const CACHE_TTL_DORMANT_SECS: u64 = 604_800;
/// Seed recency strictly below this bound is the Active tier (`< 7d`).
const SEED_RECENCY_ACTIVE_LIMIT_SECS: u64 = 7 * 86_400;
/// Seed recency strictly below this bound (and ≥ the Active limit) is the
/// Recent tier (`7–30d`); at or above it is Dormant (`≥ 30d`).
const SEED_RECENCY_RECENT_LIMIT_SECS: u64 = 30 * 86_400;
use crate::store::GRAPH_VERSION_KEY;
const SCORE_EPSILON: f32 = 1e-10;
pub(crate) const MAX_PPR_SEEDS: usize = 256;
const MAX_PPR_DEPTH: u32 = 10;

/// Version of the PPR propagation math, mixed into the cache key so persisted
/// `ppr_cache` rows computed under an older formula can never be served after
/// an upgrade (the rows are otherwise gated only by graph version + TTL, and a
/// formula change bumps neither). Stale rows are reaped by the regular cache
/// cleanup. v2 = ARCH-0039 Layer-1 normalization + λ_τ table + not-traversed
/// gates + retracted skip (ONE-1100). v3 = ARCH-0039 Layer-2 seed specificity
/// (ONE-1116): `search_ppr` seeds are weighted `1/ln(1 + passage_count)`
/// instead of uniform `1/n`, and the cache key gained a [`SeedWeighting`]
/// byte — pre-bump uniform-seeded rows are unreachable under v3 keys.
const PPR_FORMULA_VERSION: u32 = 3;

/// Seed-mass distribution mode (ARCH-0039 Layer 2, "Seed specificity
/// (search_ppr only)").
///
/// The mode is mixed into the `ppr_cache` key (see [`hash_seeds`]) because
/// the two modes produce DIFFERENT scores for the same seed set: a cached
/// `search_ppr` row must never be served to an `expand_ppr` query or vice
/// versa (fail closed on cache identity, not on score similarity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SeedWeighting {
    /// Uniform `1/n` seed mass — `expand_ppr` and the pre-Layer-2 behavior.
    Uniform,
    /// ARCH-0039 Layer 2: weight each seed by
    /// `1/ln(1 + max(passage_count, 1))`, normalized so the total seed mass
    /// is 1.0. `passage_count(seed)` is the number of inbound `mentions`
    /// edges (an `edges_in` prefix scan filtered to kind = `Mentions`),
    /// counted at query time in the same read transaction. Applies ONLY to
    /// `search_ppr`.
    Specificity,
}

impl SeedWeighting {
    /// Cache-key discriminant byte. Pinned: `Uniform` = 0, `Specificity` = 1.
    const fn cache_key_byte(self) -> u8 {
        match self {
            Self::Uniform => 0,
            Self::Specificity => 1,
        }
    }
}

/// Per-kind λ_τ traversal budget (ARCH-0039 Layer 1). The values are the
/// LITERAL `edgeKinds.lambda` column of the pinned contract module
/// (`oneiron-docs` `site/src/data/oneiron-contracts.ts`):
///
/// - `None` — the kind is NEVER traversed by PPR (`child_of`, `assigned_to`;
///   contract `lambda: null`, "Not traversed."). Tree queries go through the
///   dedicated `subtree` / `ancestors` read APIs instead.
/// - `Some(0.0)` — `opposes` blocks propagation at the KIND level regardless
///   of the stored per-edge weight byte (contradiction isolation).
/// - The five world-model kinds carry pinned ARCH-0039 budgets that
///   deliberately DIFFER from their stored-weight priors (`pprWeight`):
///   `employed_by` λ = 0.10 (prior 0.8); `has_facet` / `facet_of` /
///   `in_world` / `set_in` λ = 0.05 (prior 0.7). Do NOT derive this table
///   from `EdgeKind::default_weight`.
pub(crate) const fn lambda_for_kind(kind: EdgeKind) -> Option<f32> {
    match kind {
        EdgeKind::AuthoredBy => Some(0.9),
        EdgeKind::ScopedTo => Some(0.7),
        EdgeKind::PartOf => Some(0.8),
        EdgeKind::Supersedes => Some(0.3),
        EdgeKind::BelongsTo => Some(1.0),
        EdgeKind::ClaimOf => Some(1.0),
        EdgeKind::ChildOf => None,
        EdgeKind::AssignedTo => None,
        EdgeKind::DerivedFrom => Some(0.2),
        EdgeKind::Mentions => Some(0.6),
        EdgeKind::About => Some(0.5),
        EdgeKind::Supports => Some(1.0),
        EdgeKind::Opposes => Some(0.0),
        EdgeKind::ParticipatesIn => Some(1.0),
        EdgeKind::Attached => Some(0.8),
        EdgeKind::EmployedBy => Some(0.10),
        EdgeKind::HasFacet => Some(0.05),
        EdgeKind::FacetOf => Some(0.05),
        EdgeKind::InWorld => Some(0.05),
        EdgeKind::SetIn => Some(0.05),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DeferredPprCacheWrite {
    seed_hash: [u8; SEED_HASH_LEN],
    seeds: Vec<EntityId>,
    computed_at: u64,
    graph_version: u64,
    scores: Vec<ScoredEntity>,
}

/// Personalized PageRank over the edge graph.
///
/// Propagation follows the ARCH-0039 Layer-1 formula pinned by decision D7:
///
/// ```text
/// propagated = score * (λ_τ * w_uv / s_out(u, τ)) * (1 − α)
/// ```
///
/// where `τ` is the edge kind, `w_uv` the stored per-edge weight,
/// `s_out(u, τ)` the sum of the weights of `u`'s outgoing edges of kind `τ`,
/// and `λ_τ` the per-kind budget from [`lambda_for_kind`]. `s_out` is summed
/// on the fly inside the walk's existing prefix scans — there is NO persisted
/// per-type strength database (the pinned 25-DB manifest contains none).
///
/// Engine-defined extension (documented here pending an ARCH-0039 pin): the
/// walk also expands over `edges_in`. Reverse hops use the symmetric
/// `s_in(u, τ)` normalizer (sum of inbound same-kind weights at the node
/// being expanded) with the SAME λ_τ budgets and traversal gates — the kind
/// byte is direction-invariant in the edge key, so every gate applies
/// identically in both directions.
///
/// Traversal gates (all direction-invariant, see [`gate_edge`]):
/// - `child_of` / `assigned_to` are never traversed (contract `lambda: null`).
/// - `opposes` is blocked at the kind level (λ = 0.0) regardless of the
///   stored weight byte.
/// - Provenanced (26 B) edges with `confirmation_status == retracted` are
///   skipped entirely, including their `s_out`/`s_in` contribution (D8);
///   proposed / confirmed / disputed propagate at full weight in v1.
/// - `part_of` hops are capped at 2.
///
/// Seed mass follows the [`SeedWeighting`] mode: UNIFORM `1/n` for
/// `expand_ppr` (and the pre-Layer-2 behavior), or ARCH-0039 Layer-2
/// specificity weights for `search_ppr`. Seed weights scale BOTH the initial
/// seed mass and the per-round teleport mass, so the personalization vector
/// is the normalized weight vector (Σ seed mass = 1.0).
pub(crate) fn ppr_compute_weighted(
    store: &Store,
    txn: &RoTxn<'_>,
    seeds: &[EntityId],
    weighting: SeedWeighting,
    depth: u32,
    alpha: f32,
) -> Result<Vec<ScoredEntity>> {
    if seeds.is_empty() {
        return Ok(Vec::new());
    }

    let seed_weights = seed_weights(store, txn, seeds, weighting)?;
    let mut scores = HashMap::<EntityId, f32>::new();
    let mut frontier = HashMap::<(EntityId, u32), f32>::new();

    for (seed, weight) in seeds.iter().zip(&seed_weights) {
        *scores.entry(*seed).or_default() += *weight;
        *frontier.entry((*seed, 0)).or_default() += *weight;
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

            // Layer-1 normalization is per (node, kind, direction): the
            // forward scan over `edges_out` normalizes by s_out(u, τ) and the
            // reverse scan over `edges_in` by the symmetric s_in(u, τ), so
            // each database scan gates and groups its rows independently.
            for db in edge_dbs {
                let mut groups = HashMap::<EdgeKind, Vec<GatedEdge>>::new();
                for entry in db.prefix_iter(txn, node.as_bytes())? {
                    let (key, value) = entry?;
                    if let Some(edge) = gate_edge(key, value, hops)? {
                        groups.entry(edge.kind).or_default().push(edge);
                    }
                }

                for group in groups.into_values() {
                    // Same-kind strength normalizer (s_out on the forward
                    // scan, s_in on the reverse scan), summed on the fly.
                    // Every gated weight is finite and > 0, so `strength > 0`
                    // for a non-empty group and the division below can never
                    // produce NaN (an f32 overflow of the sum to +inf only
                    // collapses the per-edge shares toward 0.0).
                    let strength: f32 = group.iter().map(|edge| edge.weight).sum();
                    for edge in &group {
                        // ARCH-0039 Layer 1 (D7):
                        //   propagated = score * (λ_τ * w_uv / s(u, τ)) * (1 − α)
                        let propagated =
                            score * (edge.lambda * edge.weight / strength) * (1.0 - alpha);
                        *next.entry((edge.neighbor, edge.new_hops)).or_default() += propagated;
                    }
                }
            }
        }

        let teleport_mass = total * alpha;
        for (seed, weight) in seeds.iter().zip(&seed_weights) {
            *next.entry((*seed, 0)).or_default() += teleport_mass * *weight;
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

/// Test-only uniform-seeded entry point ([`ppr_compute_weighted`] with
/// [`SeedWeighting::Uniform`]); production callers route through
/// `ppr_query_in_txn_with_deferred_cache`, which carries the mode.
#[cfg(test)]
pub(crate) fn ppr_compute(
    store: &Store,
    txn: &RoTxn<'_>,
    seeds: &[EntityId],
    depth: u32,
    alpha: f32,
) -> Result<Vec<ScoredEntity>> {
    ppr_compute_weighted(store, txn, seeds, SeedWeighting::Uniform, depth, alpha)
}

/// Resolves the normalized per-seed mass vector for `weighting`. Always sums
/// to 1.0 (up to f32 rounding) and every entry is strictly positive.
fn seed_weights(
    store: &Store,
    txn: &RoTxn<'_>,
    seeds: &[EntityId],
    weighting: SeedWeighting,
) -> Result<Vec<f32>> {
    match weighting {
        SeedWeighting::Uniform => Ok(vec![1.0 / seeds.len() as f32; seeds.len()]),
        SeedWeighting::Specificity => specificity_seed_weights(store, txn, seeds),
    }
}

/// ARCH-0039 Layer 2 — "Seed specificity (search_ppr only) · Weight seeds by
/// 1/log(1 + passage_count)":
///
/// ```text
/// weight_i = 1 / ln(1 + max(passage_count_i, 1))    (normalized to Σ = 1.0)
/// ```
///
/// The `max(_, 1)` clamp pins the degenerate counts: 0 and 1 both weigh
/// `1/ln(2)` (and `ln(1 + 0·max-clamped)` can never be `ln(1) = 0`, so no
/// division by zero exists). Every raw weight lies in
/// `(0, 1/ln(2)]` and seed counts are capped at [`MAX_PPR_SEEDS`], so the
/// normalizer is finite and strictly positive — the division below cannot
/// produce NaN or infinity.
fn specificity_seed_weights(
    store: &Store,
    txn: &RoTxn<'_>,
    seeds: &[EntityId],
) -> Result<Vec<f32>> {
    let mut raw = Vec::with_capacity(seeds.len());
    for seed in seeds {
        let passage_count = inbound_mentions_count(store, txn, seed)?;
        raw.push(1.0_f64 / (1.0 + passage_count.max(1) as f64).ln());
    }

    let total: f64 = raw.iter().sum();
    Ok(raw
        .into_iter()
        .map(|weight| (weight / total) as f32)
        .collect())
}

/// `passage_count(seed)` for ARCH-0039 Layer 2: the number of inbound
/// `mentions` edges, counted by an `edges_in` prefix scan filtered to
/// kind = [`EdgeKind::Mentions`] at query time in the same read transaction
/// (pinned decision — the count is a literal row count over the index; no
/// persisted counter exists in the 25-DB manifest). Corrupt rows are a typed
/// error, never silently skipped.
fn inbound_mentions_count(store: &Store, txn: &RoTxn<'_>, seed: &EntityId) -> Result<u64> {
    let mut count = 0_u64;
    for entry in store.edges_in.prefix_iter(txn, seed.as_bytes())? {
        let (key, _) = entry?;
        if key.len() != EDGE_KEY_LEN {
            return Err(Error::CorruptedIndex("edge record"));
        }
        let kind = EdgeKind::try_from_u8(key[16]).ok_or(Error::CorruptedIndex("edge record"))?;
        if kind == EdgeKind::Mentions {
            count = count
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("ppr passage count"))?;
        }
    }
    Ok(count)
}

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
fn recency_tiered_cache_ttl_secs(
    store: &Store,
    txn: &RoTxn<'_>,
    seeds: &[EntityId],
    now: u64,
) -> Result<u64> {
    let mut max_learned_at: Option<u64> = None;
    for seed in seeds {
        let Some(raw) = store.entities.get(txn, seed.as_bytes())? else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(raw) else {
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

/// Test-only convenience wrapper. Seeds UNIFORM mass (the `expand_ppr` /
/// pre-Layer-2 path); Layer-2 tests go through
/// [`ppr_query_in_txn_with_deferred_cache`] or the pipeline.
#[cfg(test)]
pub(crate) fn ppr_query(
    store: &Store,
    _config: &VaultConfig,
    seeds: &[EntityId],
    depth: u32,
    alpha: f32,
) -> Result<Vec<ScoredEntity>> {
    let (scores, deferred_write) = {
        let rtxn = store.env.read_txn()?;
        ppr_query_in_txn_impl(
            store,
            &rtxn,
            seeds,
            depth,
            alpha,
            SeedWeighting::Uniform,
            true,
        )?
    };

    if let Some(deferred_write) = deferred_write {
        write_ppr_cache(
            store,
            &deferred_write.seed_hash,
            &deferred_write.seeds,
            deferred_write.computed_at,
            deferred_write.graph_version,
            &deferred_write.scores,
        )?;
    }

    Ok(scores)
}

#[cfg(test)]
pub(crate) fn ppr_query_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    seeds: &[EntityId],
    depth: u32,
    alpha: f32,
) -> Result<Vec<ScoredEntity>> {
    ppr_query_in_txn_impl(
        store,
        txn,
        seeds,
        depth,
        alpha,
        SeedWeighting::Uniform,
        false,
    )
    .map(|(scores, _)| scores)
}

pub(crate) fn ppr_query_in_txn_with_deferred_cache(
    store: &Store,
    txn: &RoTxn<'_>,
    seeds: &[EntityId],
    depth: u32,
    alpha: f32,
    weighting: SeedWeighting,
) -> Result<(Vec<ScoredEntity>, Option<DeferredPprCacheWrite>)> {
    ppr_query_in_txn_impl(store, txn, seeds, depth, alpha, weighting, true)
}

pub(crate) fn flush_deferred_ppr_cache_writes(
    store: &Store,
    writes: &[DeferredPprCacheWrite],
) -> Result<()> {
    for write in writes {
        write_ppr_cache(
            store,
            &write.seed_hash,
            &write.seeds,
            write.computed_at,
            write.graph_version,
            &write.scores,
        )?;
    }
    Ok(())
}

fn ppr_query_in_txn_impl(
    store: &Store,
    txn: &RoTxn<'_>,
    seeds: &[EntityId],
    depth: u32,
    alpha: f32,
    weighting: SeedWeighting,
    defer_cache_writes: bool,
) -> Result<(Vec<ScoredEntity>, Option<DeferredPprCacheWrite>)> {
    validate_ppr_request(seeds, depth)?;

    if seeds.is_empty() {
        return Ok((Vec::new(), None));
    }

    let seed_hash = hash_seeds(seeds, depth, alpha, weighting);
    let now = crate::unix_seconds_now();
    let current_graph_version = read_graph_version(store, txn)?;

    if let Some(raw) = store.ppr_cache.get(txn, &seed_hash)? {
        let (computed_at, cached_graph_version, stale) = parse_cache_header(raw)?;
        if stale == 0 && cached_graph_version == current_graph_version {
            // ARCH-0019 / ARCH-0014 recency-tiered serve TTL: the seed set's
            // max(learned_at) decides the tier at read time (24h / 72h /
            // 168h); see `recency_tiered_cache_ttl_secs` for the contract
            // cite and the fail-closed defaults. Only consulted for rows
            // that already passed the stale + graph-version gates.
            let ttl_secs = recency_tiered_cache_ttl_secs(store, txn, seeds, now)?;
            if now.saturating_sub(computed_at) <= ttl_secs {
                let mut scores = decode_cache_scores(&raw[CACHE_HEADER_LEN..])?;
                sort_scores(&mut scores);
                return Ok((scores, None));
            }
        }
    }

    let scores = ppr_compute_weighted(store, txn, seeds, weighting, depth, alpha)?;
    if !defer_cache_writes {
        return Ok((scores, None));
    }

    let deferred_write = DeferredPprCacheWrite {
        seed_hash,
        seeds: seeds.to_vec(),
        computed_at: now,
        graph_version: current_graph_version,
        scores: scores.clone(),
    };
    Ok((scores, Some(deferred_write)))
}

fn validate_ppr_request(seeds: &[EntityId], depth: u32) -> Result<()> {
    if seeds.len() > MAX_PPR_SEEDS {
        return Err(Error::InvalidConfig(format!(
            "ppr seed count exceeds maximum of {MAX_PPR_SEEDS}"
        )));
    }
    if depth > MAX_PPR_DEPTH {
        return Err(Error::InvalidConfig(format!(
            "ppr depth exceeds maximum of {MAX_PPR_DEPTH}"
        )));
    }
    Ok(())
}

fn write_ppr_cache(
    store: &Store,
    seed_hash: &[u8; SEED_HASH_LEN],
    seeds: &[EntityId],
    computed_at: u64,
    graph_version: u64,
    scores: &[ScoredEntity],
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
        seeds,
        computed_at,
        graph_version,
        scores,
    )? {
        wtxn.commit()?;
    }
    Ok(())
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
    for entry in store.ppr_cache.iter(&*wtxn)? {
        let (seed_hash_key, value) = entry?;
        if seed_hash_key.len() != SEED_HASH_LEN {
            cache_keys_to_delete.push(seed_hash_key.to_vec());
            continue;
        }

        let (computed_at, _, stale) = match parse_cache_header(value) {
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
        seed_hash.copy_from_slice(seed_hash_key);
        cache_seed_hashes.insert(seed_hash);
    }

    for key in &cache_keys_to_delete {
        store.ppr_cache.delete(wtxn, key)?;
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

        let (entity_id, seed_hash) = match decode_dep_key(dep_key) {
            Ok(decoded) => decoded,
            Err(Error::CorruptedIndex(_)) => {
                dep_keys_to_delete.push(dep_key.to_vec());
                continue;
            }
            Err(err) => return Err(err),
        };

        if store.ppr_cache.get(&*wtxn, &seed_hash)?.is_none() {
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
        store.ppr_cache.delete(wtxn, seed_hash)?;
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
        if let Some(raw) = store.ppr_cache.get(&*wtxn, &seed_hash)? {
            if raw.len() < CACHE_HEADER_LEN {
                store.ppr_cache.delete(wtxn, &seed_hash)?;
                continue;
            }
            let mut patched = raw.to_vec();
            patched[CACHE_STALE_OFFSET] = 1;
            store.ppr_cache.put(wtxn, &seed_hash, &patched)?;
        }
    }

    Ok(())
}

fn seed_is_live_for_ppr(store: &Store, txn: &RoTxn<'_>, entity_id: &EntityId) -> Result<bool> {
    if store.entities.get(txn, entity_id.as_bytes())?.is_some() {
        return Ok(true);
    }

    if store
        .edges_out
        .prefix_iter(txn, entity_id.as_bytes())?
        .next()
        .transpose()?
        .is_some()
    {
        return Ok(true);
    }

    if store
        .edges_in
        .prefix_iter(txn, entity_id.as_bytes())?
        .next()
        .transpose()?
        .is_some()
    {
        return Ok(true);
    }

    Ok(false)
}

fn store_cache_entry(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    seed_hash: &[u8; SEED_HASH_LEN],
    seeds: &[EntityId],
    computed_at: u64,
    graph_version: u64,
    scores: &[ScoredEntity],
) -> Result<bool> {
    if read_graph_version(store, &*wtxn)? != graph_version {
        return Ok(false);
    }

    let encoded = encode_cache_value(computed_at, graph_version, 0, scores);
    store.ppr_cache.put(wtxn, seed_hash, &encoded)?;

    for seed in seeds {
        let dep_key = encode_dep_key(seed, seed_hash);
        store.ppr_cache_deps.put(wtxn, &dep_key, &[])?;
    }

    Ok(true)
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

/// An edge row that passed every traversal gate, ready for Layer-1
/// propagation once its same-kind strength normalizer is known.
struct GatedEdge {
    kind: EdgeKind,
    lambda: f32,
    weight: f32,
    neighbor: EntityId,
    new_hops: u32,
}

/// Decodes one raw edge row fail-closed, then applies the traversal gates.
///
/// Returns `Ok(None)` when the edge is valid but must not propagate; corrupt
/// rows are always a typed error (gates never mask corruption — the row is
/// decoded before any gate runs).
fn gate_edge(key: &[u8], value: &[u8], hops: u32) -> Result<Option<GatedEdge>> {
    if key.len() != EDGE_KEY_LEN {
        return Err(Error::CorruptedIndex("edge record"));
    }

    let kind = EdgeKind::try_from_u8(key[16]).ok_or(Error::CorruptedIndex("edge record"))?;
    let neighbor = EntityId::from_bytes(
        key[17..33]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("edge record"))?,
    )
    .map_err(|_| Error::CorruptedIndex("edge record"))?;
    let decoded = decode_edge_value_for_kind(kind, value)
        .map_err(|_| Error::CorruptedIndex("edge record"))?;

    // Gate 1 — not-traversed kinds: `child_of` and `assigned_to` are NEVER
    // traversed, regardless of the stored weight bytes (contract
    // `lambda: null`, "Not traversed.").
    let Some(lambda) = lambda_for_kind(kind) else {
        return Ok(None);
    };

    // Gate 2 — kind-level block: λ_τ = 0.0 (`opposes`) propagates nothing
    // even when the stored weight byte is non-zero (contradiction isolation).
    if lambda == 0.0 {
        return Ok(None);
    }

    // Gate 3 — D8: provenanced edges with confirmation_status == retracted
    // are skipped entirely (factor 0), including their contribution to the
    // same-kind strength normalizer. proposed / confirmed / disputed
    // propagate at full weight in v1.
    if let Some(flags) = decoded.provenance
        && flags.confirmation_status == EdgeConfirmationStatus::Retracted
    {
        return Ok(None);
    }

    // Gate 4 — non-positive weights carry no propagation mass. Stored
    // weights are pinned to [0, 1] at write time (contracts.ts `edgeKinds`
    // pprWeight column / weight pin; `types::validate_edge_weight` on every
    // write path); gating `<= 0.0` keeps the strength normalizer strictly
    // positive for every edge that reaches the formula.
    if decoded.weight <= 0.0 {
        return Ok(None);
    }

    // Gate 5 — PartOf edges count as structural hops; cap at 2 to limit
    // hierarchy depth (contract: "Hop-limited (max 2)").
    let new_hops = if kind == EdgeKind::PartOf {
        hops.checked_add(1)
            .ok_or(Error::ArithmeticOverflow("ppr structural hops"))?
    } else {
        hops
    };
    if new_hops > 2 {
        return Ok(None);
    }

    Ok(Some(GatedEdge {
        kind,
        lambda,
        weight: decoded.weight,
        neighbor,
        new_hops,
    }))
}

fn sort_scores(scores: &mut [ScoredEntity]) {
    scores.sort_unstable_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.id.as_bytes().cmp(b.id.as_bytes()))
    });
}

/// Cache key: `xxh3_128(sorted seeds ‖ depth ‖ alpha ‖ PPR_FORMULA_VERSION ‖
/// seed-weighting byte)`. The weighting byte keeps `search_ppr`
/// (specificity-seeded) and `expand_ppr` (uniform-seeded) rows from ever
/// serving each other (ARCH-0039 Layer 2 is `search_ppr`-only).
fn hash_seeds(
    seeds: &[EntityId],
    depth: u32,
    alpha: f32,
    weighting: SeedWeighting,
) -> [u8; SEED_HASH_LEN] {
    let mut sorted = seeds.to_vec();
    sorted.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

    let mut bytes = Vec::with_capacity(
        sorted.len() * ENTITY_ID_LEN
            + 2 * std::mem::size_of::<u32>()
            + std::mem::size_of::<f32>()
            + 1,
    );
    for seed in &sorted {
        bytes.extend_from_slice(seed.as_bytes());
    }
    bytes.extend_from_slice(&depth.to_le_bytes());
    bytes.extend_from_slice(&alpha.to_le_bytes());
    bytes.extend_from_slice(&PPR_FORMULA_VERSION.to_le_bytes());
    bytes.push(weighting.cache_key_byte());

    xxh3_128(&bytes).to_le_bytes()
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
        return Err(Error::CorruptedIndex("ppr cache header"));
    }

    let computed_at = decode_u64(&bytes[..8], "ppr cache header")?;
    let graph_version = decode_u64(&bytes[8..16], "ppr cache header")?;
    let stale = bytes[CACHE_STALE_OFFSET];
    Ok((computed_at, graph_version, stale))
}

fn decode_cache_scores(payload: &[u8]) -> Result<Vec<ScoredEntity>> {
    if !payload.len().is_multiple_of(CACHE_ENTRY_LEN) {
        return Err(Error::CorruptedIndex("ppr cache scores"));
    }

    payload
        .chunks_exact(CACHE_ENTRY_LEN)
        .map(|chunk| {
            let id = EntityId::from_bytes(
                chunk[..ENTITY_ID_LEN]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("ppr cache scores"))?,
            )
            .map_err(|_| Error::CorruptedIndex("ppr cache scores"))?;
            let score = f32::from_le_bytes(
                chunk[ENTITY_ID_LEN..CACHE_ENTRY_LEN]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("ppr cache scores"))?,
            );
            if !score.is_finite() {
                return Err(Error::CorruptedIndex("ppr cache scores"));
            }
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
    decode_u64(raw, "ppr graph version")
}

fn decode_u64(raw: &[u8], context: &'static str) -> Result<u64> {
    let bytes: [u8; 8] = raw.try_into().map_err(|_| Error::CorruptedIndex(context))?;
    Ok(u64::from_le_bytes(bytes))
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

#[cfg(test)]
mod tests {
    use heed::types::Bytes;
    use tempfile::tempdir;

    use super::*;
    use crate::batch::EdgeValueFields;
    use crate::{
        EdgeActorClass, EdgeKind, EdgeProvenanceFlags, Error, HnswConfig, TimeRange, Vad, Vault,
        VaultConfig,
    };

    fn test_config() -> VaultConfig {
        VaultConfig {
            map_size: 16 * 1024 * 1024,
            dimensions: 4,
            embedding_model: Some("test-model-v1".to_owned()),
            max_readers: 16,
            hnsw: HnswConfig {
                m_max_0: 64,
                ef_construction: 200,
                ef_search: 128,
            },
            text_analyzer: crate::types::TextAnalyzerConfig::default(),
            dict_search_paths: Vec::new(),
            skip_text_index_manifest_check: false,
        }
    }

    fn entity(byte: u8) -> EntityId {
        EntityId::from_bytes_unchecked([byte; ENTITY_ID_LEN])
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

    fn cache_row(vault: &Vault, seeds: &[EntityId], depth: u32, alpha: f32) -> Result<Vec<u8>> {
        let hash = hash_seeds(seeds, depth, alpha, SeedWeighting::Uniform);
        let rtxn = vault.store.env.read_txn()?;
        let row = vault
            .store
            .ppr_cache
            .get(&rtxn, &hash)?
            .ok_or(Error::EntityNotFound)?;
        Ok(row.to_vec())
    }

    /// Plants a `ppr_cache` row directly (header `computed_at` chosen by the
    /// test, current graph version, stale = 0) carrying a sentinel score so
    /// a later query observably distinguishes "served from cache" (sentinel
    /// comes back) from "recomputed" (it does not). Also writes the seed dep
    /// rows so cleanup's liveness pass treats the row like a real one.
    fn plant_cache_row(
        vault: &Vault,
        seeds: &[EntityId],
        depth: u32,
        alpha: f32,
        weighting: SeedWeighting,
        computed_at: u64,
        scores: &[ScoredEntity],
    ) -> Result<[u8; SEED_HASH_LEN]> {
        let hash = hash_seeds(seeds, depth, alpha, weighting);
        let version = graph_version(vault)?;
        let value = encode_cache_value(computed_at, version, 0, scores);
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.ppr_cache.put(&mut wtxn, &hash, &value)?;
        for seed in seeds {
            let dep_key = encode_dep_key(seed, &hash);
            vault.store.ppr_cache_deps.put(&mut wtxn, &dep_key, &[])?;
        }
        wtxn.commit()?;
        Ok(hash)
    }

    fn sentinel_entity() -> EntityId {
        entity(0xEE)
    }

    fn sentinel_scores() -> Vec<ScoredEntity> {
        vec![ScoredEntity {
            id: sentinel_entity(),
            score: 0.25,
        }]
    }

    fn graph_version(vault: &Vault) -> Result<u64> {
        let rtxn = vault.store.env.read_txn()?;
        read_graph_version(&vault.store, &rtxn)
    }

    fn count_entries(db: &heed::Database<Bytes, Bytes>, vault: &Vault) -> Result<usize> {
        let rtxn = vault.store.env.read_txn()?;
        let mut count = 0;
        for entry in db.iter(&rtxn)? {
            entry?;
            count += 1;
        }
        Ok(count)
    }

    fn legacy_cache_key(byte: u8) -> [u8; LEGACY_SEED_HASH_LEN] {
        [byte; LEGACY_SEED_HASH_LEN]
    }

    fn legacy_dep_key(
        entity_id: EntityId,
        seed_hash: [u8; LEGACY_SEED_HASH_LEN],
    ) -> [u8; LEGACY_CACHE_DEP_KEY_LEN] {
        let mut key = [0_u8; LEGACY_CACHE_DEP_KEY_LEN];
        key[..ENTITY_ID_LEN].copy_from_slice(entity_id.as_bytes());
        key[ENTITY_ID_LEN..].copy_from_slice(&seed_hash);
        key
    }

    /// ONE-1116 AC4 — the cache key hashes `sorted seeds ‖ depth ‖ alpha ‖
    /// FORMULA_VERSION ‖ weighting byte` with the LITERAL pinned values:
    /// version 3 and mode bytes Uniform = 0 / Specificity = 1 (hand-built
    /// here, NOT read from the constants, so a wrong bump fails). The two
    /// weighting modes must never collide — `search_ppr` rows are not
    /// servable to `expand_ppr` and vice versa.
    #[test]
    fn hash_seeds_uses_full_xxh3_digest_and_is_order_insensitive() {
        let a = entity(1);
        let b = entity(2);
        let depth: u32 = 3;
        let alpha: f32 = 0.15;

        let mut bytes = Vec::with_capacity(
            ENTITY_ID_LEN * 2 + 2 * std::mem::size_of::<u32>() + std::mem::size_of::<f32>() + 1,
        );
        bytes.extend_from_slice(a.as_bytes());
        bytes.extend_from_slice(b.as_bytes());
        bytes.extend_from_slice(&depth.to_le_bytes());
        bytes.extend_from_slice(&alpha.to_le_bytes());
        bytes.extend_from_slice(&3_u32.to_le_bytes());

        let mut uniform_bytes = bytes.clone();
        uniform_bytes.push(0_u8);
        let expected_uniform = xxh3_128(&uniform_bytes).to_le_bytes();

        let mut specificity_bytes = bytes;
        specificity_bytes.push(1_u8);
        let expected_specificity = xxh3_128(&specificity_bytes).to_le_bytes();

        assert_eq!(PPR_FORMULA_VERSION, 3, "Layer-2 bump must pin version 3");
        assert_eq!(
            hash_seeds(&[a, b], depth, alpha, SeedWeighting::Uniform),
            expected_uniform
        );
        assert_eq!(
            hash_seeds(&[a, b], depth, alpha, SeedWeighting::Specificity),
            expected_specificity
        );
        assert_ne!(
            expected_uniform, expected_specificity,
            "uniform and specificity rows must never share a cache key"
        );
        assert_eq!(
            hash_seeds(&[a, b], depth, alpha, SeedWeighting::Uniform),
            hash_seeds(&[b, a], depth, alpha, SeedWeighting::Uniform)
        );
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

    /// ONE-1100 AC5 — `part_of` hops are capped at exactly 2 (contract:
    /// "Hop-limited (max 2)"): mass MUST arrive at 2 part_of hops and MUST
    /// NOT arrive at 3. Chain: a −part_of(1.0)→ b −part_of(1.0)→ c
    /// −part_of(1.0)→ d, seeds [a], α = 0.15.
    ///
    /// Layer-1 derivation (D7), each hop a single same-kind edge so
    /// w/s_out = 1.0 and λ_part_of = 0.8:
    ///   hop 1: b = 1.0  * (0.8 * 1.0 / 1.0) * 0.85 = 0.68
    ///   hop 2: c = 0.68 * (0.8 * 1.0 / 1.0) * 0.85 = 0.4624
    ///   hop 3: d — gated by the cap, never scored
    /// At depth 2 the hop-2 contribution is c's ONLY one, so c = 0.4624
    /// exactly — an off-by-one cap at 1 hop yields c = 0.0 and fails. The
    /// depth-5 run then proves the CAP (not the depth budget) is what blocks
    /// d: c keeps accumulating while d stays at exactly 0.0 — a cap at 3
    /// hops would score d and fail.
    #[test]
    fn ppr_part_of_hop_limit_allows_second_hop_blocks_third() -> Result<()> {
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

        // ALLOW side — exact Layer-1 value at depth 2 (derivation above).
        let scores = ppr_compute(&vault.store, &rtxn, &[a], 2, 0.15)?;
        let c_score = score_for(&scores, c);
        assert!(
            (c_score - 0.4624).abs() <= 1e-6,
            "mass must arrive at exactly 2 part_of hops: got {c_score}, want 0.4624"
        );
        assert_eq!(score_for(&scores, d), 0.0);

        // BLOCK side — depth budget well beyond the cap.
        let scores = ppr_compute(&vault.store, &rtxn, &[a], 5, 0.15)?;
        assert!(score_for(&scores, c) > 0.0);
        assert_eq!(
            score_for(&scores, d),
            0.0,
            "no mass may arrive at 3 part_of hops"
        );
        Ok(())
    }

    /// ONE-1100 AC2 — the λ_τ table must equal the contract's LITERAL
    /// `edgeKinds.lambda` column (oneiron-contracts.ts). The five world-model
    /// rows deliberately differ from the stored-weight prior (`pprWeight`),
    /// so a copy-the-weight-column implementation fails this test.
    #[test]
    fn lambda_table_matches_contract_literals() {
        let expected: [(EdgeKind, Option<f32>); 20] = [
            (EdgeKind::AuthoredBy, Some(0.9)),
            (EdgeKind::ScopedTo, Some(0.7)),
            (EdgeKind::PartOf, Some(0.8)),
            (EdgeKind::Supersedes, Some(0.3)),
            (EdgeKind::BelongsTo, Some(1.0)),
            (EdgeKind::ClaimOf, Some(1.0)),
            (EdgeKind::ChildOf, None),
            (EdgeKind::AssignedTo, None),
            (EdgeKind::DerivedFrom, Some(0.2)),
            (EdgeKind::Mentions, Some(0.6)),
            (EdgeKind::About, Some(0.5)),
            (EdgeKind::Supports, Some(1.0)),
            (EdgeKind::Opposes, Some(0.0)),
            (EdgeKind::ParticipatesIn, Some(1.0)),
            (EdgeKind::Attached, Some(0.8)),
            (EdgeKind::EmployedBy, Some(0.10)),
            (EdgeKind::HasFacet, Some(0.05)),
            (EdgeKind::FacetOf, Some(0.05)),
            (EdgeKind::InWorld, Some(0.05)),
            (EdgeKind::SetIn, Some(0.05)),
        ];
        for (kind, lambda) in expected {
            assert_eq!(lambda_for_kind(kind), lambda, "λ mismatch for {kind:?}");
        }

        // Pinned ARCH-0039 world-model budgets: employed_by λ = 0.10 vs
        // stored-weight prior 0.8; has_facet / facet_of / in_world / set_in
        // λ = 0.05 vs prior 0.7.
        for kind in [
            EdgeKind::EmployedBy,
            EdgeKind::HasFacet,
            EdgeKind::FacetOf,
            EdgeKind::InWorld,
            EdgeKind::SetIn,
        ] {
            let lambda = lambda_for_kind(kind).expect("world-model kinds are traversed");
            assert_ne!(
                lambda,
                kind.default_weight()
                    .expect("world-model kinds carry a stored-weight prior"),
                "λ for {kind:?} must NOT be copied from the stored-weight prior"
            );
        }
    }

    /// ONE-1100 AC1 — `child_of` and `assigned_to` carry zero PPR mass in
    /// either traversal direction, regardless of the non-zero stored weight
    /// bytes (contract `lambda: null`, "Not traversed.").
    #[test]
    fn child_of_and_assigned_to_are_never_traversed() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let child = entity(70);
        let parent = entity(71);
        let task = entity(72);
        let machine = entity(73);

        vault.put_edge(&child, EdgeKind::ChildOf, &parent, 1.0)?;
        vault.put_edge(&task, EdgeKind::AssignedTo, &machine, 0.8)?;

        let rtxn = vault.store.env.read_txn()?;
        for seed in [child, parent, task, machine] {
            let scores = ppr_compute(&vault.store, &rtxn, &[seed], 5, 0.15)?;
            // The only path from every seed is a child_of / assigned_to edge
            // (forward via edges_out or reverse via edges_in) — zero
            // propagated mass means the seed is the single scored entity.
            assert_eq!(
                scores.len(),
                1,
                "seed {seed:?} must not propagate over child_of/assigned_to"
            );
            assert_eq!(scores[0].id, seed);
        }
        Ok(())
    }

    /// ONE-1100 AC3 — `opposes` blocks at the KIND level: an opposes edge
    /// whose STORED weight byte is 1.0 still propagates zero (λ_opposes =
    /// 0.0 — contradiction isolation must not depend on the weight byte).
    #[test]
    fn opposes_blocks_at_kind_level_with_nonzero_stored_weight() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(74);
        let b = entity(75);

        vault.put_edge(&a, EdgeKind::Opposes, &b, 1.0)?;

        let rtxn = vault.store.env.read_txn()?;
        let scores = ppr_compute(&vault.store, &rtxn, &[a], 3, 0.15)?;
        assert_eq!(scores.len(), 1, "opposes must not propagate");
        assert_eq!(scores[0].id, a);
        assert_eq!(score_for(&scores, b), 0.0);
        Ok(())
    }

    /// ONE-1100 AC4 — Layer-1 normalization (D7), exact values at depth 1:
    ///   propagated = score * (λ_τ * w_uv / s_out(u, τ)) * (1 − α)
    /// Graph: a −mentions(0.6)→ b, a −mentions(0.2)→ c, a −supports(0.5)→ d.
    /// Seeds [a], depth 1, α = 0.15:
    ///   s_out(a, mentions) = 0.6 + 0.2 = 0.8, λ_mentions = 0.6
    ///     b = 1.0 * (0.6 * 0.6 / 0.8) * 0.85 = 0.3825
    ///     c = 1.0 * (0.6 * 0.2 / 0.8) * 0.85 = 0.1275
    ///   s_out(a, supports) = 0.5 (own kind budget), λ_supports = 1.0
    ///     d = 1.0 * (1.0 * 0.5 / 0.5) * 0.85 = 0.85
    ///   a = 1.0 (init) + 1.0 * 0.15 (teleport) = 1.15
    /// A λ·w implementation without s_out yields b = 0.306; the legacy
    /// stored-weight-only formula yields b = 0.51 — both must fail here.
    #[test]
    fn layer1_normalization_matches_derived_values() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(76);
        let b = entity(77);
        let c = entity(78);
        let d = entity(79);

        vault.put_edge(&a, EdgeKind::Mentions, &b, 0.6)?;
        vault.put_edge(&a, EdgeKind::Mentions, &c, 0.2)?;
        vault.put_edge(&a, EdgeKind::Supports, &d, 0.5)?;

        let rtxn = vault.store.env.read_txn()?;
        let scores = ppr_compute(&vault.store, &rtxn, &[a], 1, 0.15)?;

        let cases = [(a, 1.15_f32), (b, 0.3825), (c, 0.1275), (d, 0.85)];
        for (id, expected) in cases {
            let got = score_for(&scores, id);
            assert!(
                (got - expected).abs() <= 1e-6,
                "score for {id:?}: got {got}, want {expected}"
            );
        }
        Ok(())
    }

    /// ONE-1100 AC4 (D7) — reverse hops over `edges_in` use the symmetric
    /// s_in(u, τ) normalizer with the same λ + gates (engine-defined
    /// extension pending the ARCH-0039 pin).
    /// Graph: a −belongs_to(1.0)→ b, c −belongs_to(1.0)→ b. Seeds [b],
    /// depth 1: b has no outgoing edges; the reverse scan at b sees two
    /// inbound belongs_to edges, s_in(b, belongs_to) = 1.0 + 1.0 = 2.0:
    ///   a = c = 1.0 * (1.0 * 1.0 / 2.0) * 0.85 = 0.425
    ///   b = 1.0 (init) + 0.15 (teleport) = 1.15
    /// An implementation reusing s_out (= 0 at b) would divide by zero; one
    /// without reverse normalization would yield 0.85 per neighbor.
    #[test]
    fn reverse_hops_use_symmetric_s_in_normalizer() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(120);
        let b = entity(121);
        let c = entity(122);

        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
        vault.put_edge(&c, EdgeKind::BelongsTo, &b, 1.0)?;

        let rtxn = vault.store.env.read_txn()?;
        let scores = ppr_compute(&vault.store, &rtxn, &[b], 1, 0.15)?;

        let cases = [(a, 0.425_f32), (b, 1.15), (c, 0.425)];
        for (id, expected) in cases {
            let got = score_for(&scores, id);
            assert!(
                (got - expected).abs() <= 1e-6,
                "score for {id:?}: got {got}, want {expected}"
            );
        }
        Ok(())
    }

    /// ONE-1100 AC2/AC4 — the five pinned world-model budgets BIND in
    /// propagation. A single same-kind edge normalizes to w/s = 1.0, so the
    /// neighbor score at depth 1 is exactly λ_τ * (1 − α):
    ///   employed_by: 0.10 * 0.85 = 0.085  (copy-the-weight impl: 0.68)
    ///   has_facet / facet_of / in_world / set_in: 0.05 * 0.85 = 0.0425
    ///   (copy-the-weight impl: 0.595)
    #[test]
    fn world_model_lambda_budgets_bind_in_propagation() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let cases: [(EdgeKind, f32, f32); 5] = [
            (EdgeKind::EmployedBy, 0.8, 0.085),
            (EdgeKind::HasFacet, 0.7, 0.0425),
            (EdgeKind::FacetOf, 0.7, 0.0425),
            (EdgeKind::InWorld, 0.7, 0.0425),
            (EdgeKind::SetIn, 0.7, 0.0425),
        ];

        let mut byte = 80_u8;
        for (kind, stored_weight, expected) in cases {
            let src = entity(byte);
            let tgt = entity(byte + 1);
            byte += 2;
            vault.put_edge(&src, kind, &tgt, stored_weight)?;

            let rtxn = vault.store.env.read_txn()?;
            let scores = ppr_compute(&vault.store, &rtxn, &[src], 1, 0.15)?;
            let got = score_for(&scores, tgt);
            assert!(
                (got - expected).abs() <= 1e-6,
                "{kind:?}: got {got}, want {expected} (λ must bind, not the stored weight)"
            );
        }
        Ok(())
    }

    /// ONE-1100 AC6 (D8) — confirmation_status == retracted (3) skips the
    /// edge entirely, INCLUDING its s_out contribution:
    /// a −mentions(0.6)→ b (bare 24 B), a −mentions(0.6, retracted)→ c (26 B).
    /// s_out(a, mentions) counts only the live edge = 0.6, so at depth 1
    ///   b = 1.0 * (0.6 * 0.6 / 0.6) * 0.85 = 0.51
    ///   (0.255 if the retracted edge still consumed normalizer mass)
    ///   c = 0.0 (skipped entirely — D8 factor 0)
    #[test]
    fn retracted_edges_skip_propagation_and_strength() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(100);
        let b = entity(101);
        let c = entity(102);

        vault.put_edge(&a, EdgeKind::Mentions, &b, 0.6)?;
        vault
            .batch()
            .edge_with_value_fields(
                &a,
                EdgeKind::Mentions,
                &c,
                EdgeValueFields {
                    weight: 0.6,
                    created_at: 1,
                    vad: Vad::NEUTRAL,
                    provenance: Some(EdgeProvenanceFlags {
                        confirmation_status: EdgeConfirmationStatus::Retracted,
                        actor_class: EdgeActorClass::Human,
                    }),
                },
            )
            .commit()?;

        let rtxn = vault.store.env.read_txn()?;

        // The stamped row must really be the 26 B provenanced layout with the
        // contract's retracted discriminant (3) at offset 24.
        let key = Store::encode_edge_key(&a, EdgeKind::Mentions, &c);
        let raw = vault
            .store
            .edges_out
            .get(&rtxn, &key)?
            .ok_or(Error::EntityNotFound)?;
        assert_eq!(raw.len(), 26);
        assert_eq!(raw[24], 3);

        let scores = ppr_compute(&vault.store, &rtxn, &[a], 1, 0.15)?;
        let b_score = score_for(&scores, b);
        assert!(
            (b_score - 0.51).abs() <= 1e-6,
            "live edge must own the full normalizer, got {b_score}"
        );
        assert_eq!(score_for(&scores, c), 0.0, "retracted edge must be skipped");
        Ok(())
    }

    /// ONE-1100 AC6 (D8) — proposed(0) / confirmed(1) / disputed(2)
    /// propagate at FULL weight in v1 (no demotion): each equals the
    /// bare-edge value λ_mentions * (w/s = 1.0) * (1 − 0.15) = 0.51 at
    /// depth 1.
    #[test]
    fn non_retracted_statuses_propagate_at_full_weight() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let statuses = [
            EdgeConfirmationStatus::Proposed,
            EdgeConfirmationStatus::Confirmed,
            EdgeConfirmationStatus::Disputed,
        ];

        let mut byte = 110_u8;
        for status in statuses {
            let src = entity(byte);
            let tgt = entity(byte + 1);
            byte += 2;
            vault
                .batch()
                .edge_with_value_fields(
                    &src,
                    EdgeKind::Mentions,
                    &tgt,
                    EdgeValueFields {
                        weight: 0.6,
                        created_at: 1,
                        vad: Vad::NEUTRAL,
                        provenance: Some(EdgeProvenanceFlags {
                            confirmation_status: status,
                            actor_class: EdgeActorClass::Agent,
                        }),
                    },
                )
                .commit()?;

            let rtxn = vault.store.env.read_txn()?;
            let scores = ppr_compute(&vault.store, &rtxn, &[src], 1, 0.15)?;
            let got = score_for(&scores, tgt);
            assert!(
                (got - 0.51).abs() <= 1e-6,
                "{status:?} must propagate at full weight, got {got}"
            );
        }
        Ok(())
    }

    /// ONE-1100 AC6 (D8) — mixed-status edges from ONE source share ONE
    /// same-kind normalizer at FULL weight. The per-status test above uses
    /// one edge per source, where single-edge Layer-1 normalization cancels
    /// ANY per-status weight factor f (w·f / s_out = w·f / w·f = 1.0); here
    /// the three edges compete inside the same s_out, so any weight scaling
    /// skews the shares and fails.
    /// Graph: a −mentions(0.6, proposed)→ t1, a −mentions(0.6, confirmed)→ t2,
    /// a −mentions(0.6, disputed)→ t3. Seeds [a], depth 1, α = 0.15:
    ///   s_out(a, mentions) = 0.6 + 0.6 + 0.6 = 1.8, λ_mentions = 0.6
    ///   t1 = t2 = t3 = 1.0 * (0.6 * 0.6 / 1.8) * 0.85 = 0.17
    /// e.g. a 0.5 weight demotion on disputed gives s_out = 1.5 →
    /// t1 = t2 = 0.204, t3 = 0.102 — every share moves off 0.17.
    #[test]
    fn same_source_mixed_statuses_share_normalizer_at_full_weight() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(130);
        let targets = [
            (entity(131), EdgeConfirmationStatus::Proposed),
            (entity(132), EdgeConfirmationStatus::Confirmed),
            (entity(133), EdgeConfirmationStatus::Disputed),
        ];

        let mut batch = vault.batch();
        for (target, status) in &targets {
            batch = batch.edge_with_value_fields(
                &a,
                EdgeKind::Mentions,
                target,
                EdgeValueFields {
                    weight: 0.6,
                    created_at: 1,
                    vad: Vad::NEUTRAL,
                    provenance: Some(EdgeProvenanceFlags {
                        confirmation_status: *status,
                        actor_class: EdgeActorClass::Agent,
                    }),
                },
            );
        }
        batch.commit()?;

        let rtxn = vault.store.env.read_txn()?;
        let scores = ppr_compute(&vault.store, &rtxn, &[a], 1, 0.15)?;
        for (target, status) in targets {
            let got = score_for(&scores, target);
            assert!(
                (got - 0.17).abs() <= 1e-6,
                "{status:?} share must be 1.0 * (0.6 * 0.6 / 1.8) * 0.85 = 0.17, got {got}"
            );
        }
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
        let cache_after_first = cache_row(&vault, &[a], 3, 0.15)?;
        let second = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
        let cache_after_second = cache_row(&vault, &[a], 3, 0.15)?;

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
        let c = entity(20);

        // Two same-kind edges so a weight rewrite changes b's NORMALIZED
        // share (a single edge always normalizes to w/s = 1.0, which would
        // make the score weight-invariant):
        //   before: b share = 1.0 / (1.0 + 1.0) = 0.5
        //   after:  b share = 0.2 / (0.2 + 1.0) = 1/6
        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
        vault.put_edge(&a, EdgeKind::BelongsTo, &c, 1.0)?;

        let first = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
        let cache_before = cache_row(&vault, &[a], 3, 0.15)?;
        assert_eq!(cache_before[16], 0);

        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 0.2)?;
        let cache_stale = cache_row(&vault, &[a], 3, 0.15)?;
        assert_eq!(cache_stale[16], 1);

        let second = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
        let cache_after = cache_row(&vault, &[a], 3, 0.15)?;
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
        let cache_before = cache_row(&vault, &[a], 3, 0.15)?;
        assert_eq!(cache_before[CACHE_STALE_OFFSET], 0);

        // Delete entity b — removes a->b and b->c edges.
        vault.delete_entity(&b)?;

        // Cache for seeds [a] must now be stale because a's edge to b was removed.
        let cache_after = cache_row(&vault, &[a], 3, 0.15)?;
        assert_eq!(cache_after[CACHE_STALE_OFFSET], 1);
        Ok(())
    }

    #[test]
    fn ppr_cache_key_changes_with_depth_and_alpha() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(23);
        let b = entity(24);

        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;

        let _ = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
        let _ = ppr_query(&vault.store, &vault.config, &[a], 4, 0.15)?;
        let _ = ppr_query(&vault.store, &vault.config, &[a], 3, 0.25)?;

        let hash_depth_3 = hash_seeds(&[a], 3, 0.15, SeedWeighting::Uniform);
        let hash_depth_4 = hash_seeds(&[a], 4, 0.15, SeedWeighting::Uniform);
        let hash_alpha_25 = hash_seeds(&[a], 3, 0.25, SeedWeighting::Uniform);

        assert_ne!(hash_depth_3, hash_depth_4);
        assert_ne!(hash_depth_3, hash_alpha_25);
        assert_eq!(count_entries(&vault.store.ppr_cache, &vault)?, 3);
        Ok(())
    }

    #[test]
    fn batch_graph_mutations_increment_version_once() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(25);
        let b = entity(26);
        let c = entity(27);

        assert_eq!(graph_version(&vault)?, 0);

        vault
            .batch()
            .edge(&a, EdgeKind::BelongsTo, &b, 1.0)
            .edge(&a, EdgeKind::BelongsTo, &c, 0.5)
            .commit()?;

        assert_eq!(graph_version(&vault)?, 1);
        Ok(())
    }

    #[test]
    fn batch_noop_delete_edge_does_not_bump_version_or_stale_cache() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(28);
        let b = entity(29);
        let missing = entity(30);

        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
        let _ = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
        let seed_hash = hash_seeds(&[a], 3, 0.15, SeedWeighting::Uniform);
        let before = graph_version(&vault)?;

        vault
            .batch()
            .delete_edge(&a, EdgeKind::BelongsTo, &missing)
            .commit()?;

        let after = graph_version(&vault)?;
        assert_eq!(after, before);

        let rtxn = vault.store.env.read_txn()?;
        let raw = vault
            .store
            .ppr_cache
            .get(&rtxn, &seed_hash)?
            .ok_or(Error::InvalidKey)?;
        let (_, _, stale) = parse_cache_header(raw)?;
        assert_eq!(stale, 0);
        Ok(())
    }

    #[test]
    fn delete_entity_increments_graph_version_once_when_edges_removed() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(31);
        let b = entity(32);
        let c = entity(33);
        let tr = TimeRange { start: 1, end: 1 };

        vault.put_entity(&a, 1, tr, 1, b"a-data")?;
        vault.put_entity(&b, 1, tr, 1, b"b-data")?;
        vault.put_entity(&c, 1, tr, 1, b"c-data")?;
        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
        vault.put_edge(&b, EdgeKind::BelongsTo, &c, 1.0)?;

        let before = graph_version(&vault)?;
        assert!(vault.delete_entity(&b)?);
        let after = graph_version(&vault)?;

        assert_eq!(after, before + 1);
        Ok(())
    }

    #[test]
    fn direct_delete_edge_increments_graph_version_and_stales_cache() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(34);
        let b = entity(35);
        let tr = TimeRange { start: 1, end: 1 };

        vault.put_entity(&a, 1, tr, 1, b"a-data")?;
        vault.put_entity(&b, 1, tr, 1, b"b-data")?;
        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
        let _ = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
        let seed_hash = hash_seeds(&[a], 3, 0.15, SeedWeighting::Uniform);

        let before = graph_version(&vault)?;
        assert!(vault.delete_edge(&a, EdgeKind::BelongsTo, &b)?);
        let after = graph_version(&vault)?;
        assert_eq!(after, before + 1);

        let rtxn = vault.store.env.read_txn()?;
        let raw = vault
            .store
            .ppr_cache
            .get(&rtxn, &seed_hash)?
            .ok_or(Error::InvalidKey)?;
        let (_, _, stale) = parse_cache_header(raw)?;
        assert_eq!(stale, 1);
        Ok(())
    }

    #[test]
    fn batch_delete_edge_cleans_inbound_orphans_without_staling_cache() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(50);
        let b = entity(51);
        let tr = TimeRange { start: 1, end: 1 };

        vault.put_entity(&a, 1, tr, 1, b"a-data")?;
        vault.put_entity(&b, 1, tr, 1, b"b-data")?;
        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
        let _ = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
        let seed_hash = hash_seeds(&[a], 3, 0.15, SeedWeighting::Uniform);

        let key_out = Store::encode_edge_key(&a, EdgeKind::BelongsTo, &b);
        let key_in = Store::encode_edge_key(&b, EdgeKind::BelongsTo, &a);
        let mut wtxn = vault.store.env.write_txn()?;
        assert!(vault.store.edges_out.delete(&mut wtxn, &key_out)?);
        wtxn.commit()?;

        let before = graph_version(&vault)?;
        vault
            .batch()
            .delete_edge(&a, EdgeKind::BelongsTo, &b)
            .commit()?;
        let after = graph_version(&vault)?;
        assert_eq!(after, before);

        let rtxn = vault.store.env.read_txn()?;
        assert!(vault.store.edges_in.get(&rtxn, &key_in)?.is_none());
        let raw = vault
            .store
            .ppr_cache
            .get(&rtxn, &seed_hash)?
            .ok_or(Error::EntityNotFound)?;
        let (_, _, stale) = parse_cache_header(raw)?;
        assert_eq!(stale, 0);
        Ok(())
    }

    /// Deleting an isolated entity must bump GRAPH_VERSION exactly once;
    /// a follow-up delete attempt on the now-missing id must not bump it
    /// again. Variants run the delete through different API paths.
    ///
    /// Variants:
    /// - `direct`: `vault.delete_entity(&a)` — returns `bool` for found/missing.
    /// - `batch`: `vault.batch().delete(&a).commit()` — must observe the
    ///   same "second commit is a no-op" guarantee.
    #[test]
    fn delete_isolated_entity_increments_graph_version_once() -> Result<()> {
        #[derive(Clone, Copy)]
        enum Path {
            Direct,
            Batch,
        }

        let cases: Vec<(&str, Path, u8)> =
            vec![("direct", Path::Direct, 36), ("batch", Path::Batch, 37)];

        for (case_name, path, byte) in cases {
            let temp_dir = tempdir()?;
            let vault = Vault::open(temp_dir.path(), test_config())?;
            let a = entity(byte);
            let tr = TimeRange { start: 1, end: 1 };

            vault.put_entity(&a, 1, tr, 1, b"a-data")?;

            let before = graph_version(&vault)?;
            match path {
                Path::Direct => {
                    assert!(
                        vault.delete_entity(&a)?,
                        "case {case_name}: first direct delete should report found"
                    );
                }
                Path::Batch => {
                    vault.batch().delete(&a).commit()?;
                }
            }
            let after_delete = graph_version(&vault)?;
            assert_eq!(
                after_delete,
                before + 1,
                "case {case_name}: first delete should bump GRAPH_VERSION by 1"
            );

            match path {
                Path::Direct => {
                    assert!(
                        !vault.delete_entity(&a)?,
                        "case {case_name}: second direct delete should report missing"
                    );
                }
                Path::Batch => {
                    vault.batch().delete(&a).commit()?;
                }
            }
            let after_missing = graph_version(&vault)?;
            assert_eq!(
                after_missing, after_delete,
                "case {case_name}: redundant delete must not bump GRAPH_VERSION"
            );
        }
        Ok(())
    }

    #[test]
    fn cleanup_conservatively_evicts_cache_for_missing_dep_entities() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(38);
        let b = entity(39);
        let missing = entity(40);
        let tr = TimeRange { start: 1, end: 1 };

        vault.put_entity(&a, 1, tr, 1, b"a-data")?;
        vault.put_entity(&b, 1, tr, 1, b"b-data")?;
        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
        let _ = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
        let seed_hash = hash_seeds(&[a], 3, 0.15, SeedWeighting::Uniform);

        let mut wtxn = vault.store.env.write_txn()?;
        let orphan_dep = encode_dep_key(&missing, &seed_hash);
        vault
            .store
            .ppr_cache_deps
            .put(&mut wtxn, &orphan_dep, &[])?;
        wtxn.commit()?;

        assert_eq!(count_entries(&vault.store.ppr_cache, &vault)?, 1);
        assert_eq!(count_entries(&vault.store.ppr_cache_deps, &vault)?, 2);

        let report = vault
            .maintain()
            .cleanup_ppr_cache(CACHE_TTL_DORMANT_SECS)
            .run()?;
        assert_eq!(report.ppr_caches_evicted, 1);
        assert_eq!(count_entries(&vault.store.ppr_cache, &vault)?, 0);
        assert_eq!(count_entries(&vault.store.ppr_cache_deps, &vault)?, 0);
        Ok(())
    }

    #[test]
    fn cleanup_ppr_cache_removes_legacy_rows() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(37);
        let b = entity(38);
        let tr = TimeRange { start: 1, end: 1 };

        vault.put_entity(&a, 1, tr, 1, b"a-data")?;
        vault.put_entity(&b, 1, tr, 1, b"b-data")?;
        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
        let _ = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;

        let now = crate::unix_seconds_now();
        let legacy_hash = legacy_cache_key(0xAB);
        let legacy_dep = legacy_dep_key(a, legacy_hash);
        let legacy_value = encode_cache_value(now, 0, 0, &[]);

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .ppr_cache
            .put(&mut wtxn, &legacy_hash, &legacy_value)?;
        vault
            .store
            .ppr_cache_deps
            .put(&mut wtxn, &legacy_dep, &[])?;
        wtxn.commit()?;

        assert_eq!(count_entries(&vault.store.ppr_cache, &vault)?, 2);
        assert_eq!(count_entries(&vault.store.ppr_cache_deps, &vault)?, 2);

        let report = vault
            .maintain()
            .cleanup_ppr_cache(CACHE_TTL_DORMANT_SECS)
            .run()?;
        assert!(report.ppr_caches_evicted >= 1);
        assert!(report.ppr_deps_cleaned >= 1);
        assert_eq!(count_entries(&vault.store.ppr_cache, &vault)?, 1);
        assert_eq!(count_entries(&vault.store.ppr_cache_deps, &vault)?, 1);
        Ok(())
    }

    #[test]
    fn cleanup_ppr_cache_prunes_malformed_dep_rows() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(52);
        let b = entity(53);
        let tr = TimeRange { start: 1, end: 1 };

        vault.put_entity(&a, 1, tr, 1, b"a-data")?;
        vault.put_entity(&b, 1, tr, 1, b"b-data")?;
        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
        let _ = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
        let seed_hash = hash_seeds(&[a], 3, 0.15, SeedWeighting::Uniform);

        let mut malformed_dep = [0_u8; CACHE_DEP_KEY_LEN];
        malformed_dep[ENTITY_ID_LEN..].copy_from_slice(&seed_hash);

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .ppr_cache_deps
            .put(&mut wtxn, &malformed_dep, &[])?;
        wtxn.commit()?;

        let report = vault
            .maintain()
            .cleanup_ppr_cache(CACHE_TTL_DORMANT_SECS)
            .run()?;
        assert_eq!(report.ppr_caches_evicted, 0);
        assert!(report.ppr_deps_cleaned >= 1);

        let rtxn = vault.store.env.read_txn()?;
        assert!(vault.store.ppr_cache.get(&rtxn, &seed_hash)?.is_some());
        assert!(
            vault
                .store
                .ppr_cache_deps
                .get(&rtxn, &malformed_dep)?
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn cleanup_ppr_cache_evicts_cache_when_last_dep_row_is_malformed() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(54);
        let b = entity(55);
        let tr = TimeRange { start: 1, end: 1 };

        vault.put_entity(&a, 1, tr, 1, b"a-data")?;
        vault.put_entity(&b, 1, tr, 1, b"b-data")?;
        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
        let _ = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
        let seed_hash = hash_seeds(&[a], 3, 0.15, SeedWeighting::Uniform);
        let dep_key = encode_dep_key(&a, &seed_hash);

        let mut malformed_dep = [0_u8; CACHE_DEP_KEY_LEN];
        malformed_dep[ENTITY_ID_LEN..].copy_from_slice(&seed_hash);

        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.ppr_cache_deps.delete(&mut wtxn, &dep_key)?;
        vault
            .store
            .ppr_cache_deps
            .put(&mut wtxn, &malformed_dep, &[])?;
        wtxn.commit()?;

        let report = vault
            .maintain()
            .cleanup_ppr_cache(CACHE_TTL_DORMANT_SECS)
            .run()?;
        assert_eq!(report.ppr_caches_evicted, 1);
        assert!(report.ppr_deps_cleaned >= 1);

        let rtxn = vault.store.env.read_txn()?;
        assert!(vault.store.ppr_cache.get(&rtxn, &seed_hash)?.is_none());
        assert!(
            vault
                .store
                .ppr_cache_deps
                .get(&rtxn, &malformed_dep)?
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn invalidate_ppr_caches_prunes_malformed_cache_rows() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(60);
        let b = entity(61);
        let seed_hash = hash_seeds(&[a], 3, 0.15, SeedWeighting::Uniform);
        let dep_key = encode_dep_key(&a, &seed_hash);

        vault.put_entity(&a, 1, TimeRange { start: 1, end: 1 }, 1, b"a-data")?;
        vault.put_entity(&b, 1, TimeRange { start: 2, end: 2 }, 2, b"b-data")?;

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .ppr_cache
            .put(&mut wtxn, &seed_hash, &[1, 2, 3])?;
        vault.store.ppr_cache_deps.put(&mut wtxn, &dep_key, &[])?;
        wtxn.commit()?;

        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;

        let rtxn = vault.store.env.read_txn()?;
        assert!(vault.store.ppr_cache.get(&rtxn, &seed_hash)?.is_none());
        drop(rtxn);
        assert!(vault.edge_exists(&a, EdgeKind::BelongsTo, &b)?);
        Ok(())
    }

    #[test]
    fn edge_invalidation_self_heals_legacy_dep_rows() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(39);
        let b = entity(40);
        let legacy_hash = legacy_cache_key(0xCD);
        let legacy_dep = legacy_dep_key(a, legacy_hash);

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .ppr_cache_deps
            .put(&mut wtxn, &legacy_dep, &[])?;
        wtxn.commit()?;

        assert_eq!(count_entries(&vault.store.ppr_cache_deps, &vault)?, 1);

        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;

        assert_eq!(count_entries(&vault.store.ppr_cache_deps, &vault)?, 0);
        Ok(())
    }

    #[test]
    fn cleanup_keeps_graph_only_seed_deps_and_invalidation_still_works() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(41);
        let b = entity(42);
        let c = entity(43);
        let tr = TimeRange { start: 1, end: 1 };

        vault.put_entity(&b, 1, tr, 1, b"b-data")?;
        vault.put_entity(&c, 1, tr, 1, b"c-data")?;
        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;

        let first = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
        assert!(score_for(&first, b) > 0.0);
        assert!(score_for(&first, c) <= SCORE_EPSILON);

        let report = vault
            .maintain()
            .cleanup_ppr_cache(CACHE_TTL_DORMANT_SECS)
            .run()?;
        assert_eq!(report.ppr_caches_evicted, 0);
        assert_eq!(count_entries(&vault.store.ppr_cache_deps, &vault)?, 1);

        vault.put_edge(&a, EdgeKind::BelongsTo, &c, 1.0)?;
        let second = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
        assert!(score_for(&second, c) > 0.0);
        Ok(())
    }

    #[test]
    fn cleanup_evicts_cache_for_dead_seed_without_live_graph_presence() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(44);
        let b = entity(45);

        let first = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
        assert!(score_for(&first, a) > 0.0);
        assert!(score_for(&first, b) <= SCORE_EPSILON);
        assert_eq!(count_entries(&vault.store.ppr_cache, &vault)?, 1);
        assert_eq!(count_entries(&vault.store.ppr_cache_deps, &vault)?, 1);

        let report = vault
            .maintain()
            .cleanup_ppr_cache(CACHE_TTL_DORMANT_SECS)
            .run()?;
        assert_eq!(report.ppr_caches_evicted, 1);
        assert_eq!(count_entries(&vault.store.ppr_cache, &vault)?, 0);
        assert_eq!(count_entries(&vault.store.ppr_cache_deps, &vault)?, 0);

        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
        let second = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
        assert!(score_for(&second, b) > 0.0);
        Ok(())
    }

    #[test]
    fn ppr_query_recomputes_cache_after_graph_version_change() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(46);
        let b = entity(47);

        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
        let first = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
        let cache_before = cache_row(&vault, &[a], 3, 0.15)?;
        let (_, version_before, stale_before) = parse_cache_header(&cache_before)?;
        assert_eq!(stale_before, 0);

        let new_version = version_before + 1;
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .hnsw_meta
            .put(&mut wtxn, GRAPH_VERSION_KEY, &new_version.to_le_bytes())?;
        wtxn.commit()?;

        let second = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
        let cache_after = cache_row(&vault, &[a], 3, 0.15)?;
        let (_, version_after, stale_after) = parse_cache_header(&cache_after)?;

        assert_eq!(stale_after, 0);
        assert_eq!(version_after, new_version);
        assert_eq!(first, second);
        assert_ne!(cache_before, cache_after);
        Ok(())
    }

    #[test]
    fn ppr_query_recomputes_after_downstream_graph_change() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(57);
        let b = entity(58);
        let c = entity(59);

        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;
        let first = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
        assert!(score_for(&first, b) > 0.0);
        assert!(score_for(&first, c) <= SCORE_EPSILON);

        vault.put_edge(&b, EdgeKind::BelongsTo, &c, 1.0)?;
        let second = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
        assert!(score_for(&second, c) > 0.0);
        Ok(())
    }

    #[test]
    fn cache_write_is_skipped_when_graph_version_changes_before_store() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(48);
        let b = entity(49);
        let seed_hash = hash_seeds(&[a], 3, 0.15, SeedWeighting::Uniform);

        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;

        let stale_version = graph_version(&vault)?;
        let mut wtxn = vault.store.env.write_txn()?;
        increment_graph_version(&vault.store, &mut wtxn)?;
        wtxn.commit()?;

        let scores = vec![ScoredEntity { id: b, score: 1.0 }];
        let mut wtxn = vault.store.env.write_txn()?;
        let stored = store_cache_entry(
            &vault.store,
            &mut wtxn,
            &seed_hash,
            &[a],
            crate::unix_seconds_now(),
            stale_version,
            &scores,
        )?;
        wtxn.commit()?;

        assert!(!stored);
        let rtxn = vault.store.env.read_txn()?;
        assert!(vault.store.ppr_cache.get(&rtxn, &seed_hash)?.is_none());
        Ok(())
    }

    #[test]
    fn ppr_query_in_txn_uses_borrowed_snapshot_without_caching_stale_results() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(60);
        let b = entity(61);
        let c = entity(62);

        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;

        let snapshot = vault.store.env.read_txn()?;
        vault.put_edge(&a, EdgeKind::BelongsTo, &c, 1.0)?;

        let borrowed = ppr_query_in_txn(&vault.store, &snapshot, &[a], 3, 0.15)?;
        assert!(score_for(&borrowed, b) > 0.0);
        assert!(score_for(&borrowed, c) <= SCORE_EPSILON);
        drop(snapshot);

        let latest = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
        assert!(score_for(&latest, c) > 0.0);
        Ok(())
    }

    /// `ppr_query` must refuse to produce scores when non-finite values are
    /// persisted in either the edge-weight payload or the cached score
    /// payload. Variants inject the bad value at a different site.
    ///
    /// Variants:
    /// - `persisted_edge_weight`: writes `f32::NAN` into the first 4 bytes
    ///   of an `edges_out` record. Expected error: `CorruptedIndex("edge record")`.
    /// - `cached_scores`: writes `f32::INFINITY` into a `ppr_cache` entry.
    ///   Expected error: `CorruptedIndex("ppr cache scores")`.
    #[test]
    fn ppr_query_rejects_non_finite_inputs() -> Result<()> {
        #[derive(Clone, Copy)]
        enum Site {
            EdgeWeight,
            CachedScores,
        }

        let cases: Vec<(&str, Site, u8, u8, &str)> = vec![
            (
                "persisted_edge_weight",
                Site::EdgeWeight,
                63,
                64,
                "edge record",
            ),
            (
                "cached_scores",
                Site::CachedScores,
                65,
                66,
                "ppr cache scores",
            ),
        ];

        for (case_name, site, a_byte, b_byte, expected_msg) in cases {
            let temp_dir = tempdir()?;
            let vault = Vault::open(temp_dir.path(), test_config())?;
            let a = entity(a_byte);
            let b = entity(b_byte);

            let mut wtxn = vault.store.env.write_txn()?;
            match site {
                Site::EdgeWeight => {
                    let key = Store::encode_edge_key(&a, EdgeKind::BelongsTo, &b);
                    let mut value = [0_u8; EDGE_VALUE_STRUCTURAL_LEN];
                    value[..4].copy_from_slice(&f32::NAN.to_le_bytes());
                    vault.store.edges_out.put(&mut wtxn, &key, &value)?;
                }
                Site::CachedScores => {
                    let seed_hash = hash_seeds(&[a], 3, 0.15, SeedWeighting::Uniform);
                    let cache = encode_cache_value(
                        crate::unix_seconds_now(),
                        0,
                        0,
                        &[ScoredEntity {
                            id: b,
                            score: f32::INFINITY,
                        }],
                    );
                    vault.store.ppr_cache.put(&mut wtxn, &seed_hash, &cache)?;
                }
            }
            wtxn.commit()?;

            let err = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)
                .expect_err("expected corrupted state");
            match err {
                Error::CorruptedIndex(msg) if msg == expected_msg => {}
                other => panic!(
                    "case {case_name}: expected CorruptedIndex({expected_msg:?}), got {other:?}"
                ),
            }
        }
        Ok(())
    }

    /// ONE-1116 AC1 (ARCH-0039 Layer 2) — `search_ppr` seed mass is
    /// `1/ln(1 + max(passage_count, 1))`, normalized to Σ = 1.0, with
    /// `passage_count` = inbound `mentions` edge count. Graph (every
    /// mentions edge stores weight 0.6):
    ///   p1, p2, p3 −mentions→ a   (passage_count(a) = 3)
    ///   (nothing)  −mentions→ b   (passage_count(b) = 0 → clamped to 1)
    ///   q1         −mentions→ c   (passage_count(c) = 1)
    /// Raw weights 1/ln(4) : 1/ln(2) : 1/ln(2) normalize EXACTLY to
    /// 0.2 / 0.4 / 0.4 (ln(4) = 2·ln(2), so the log base cancels).
    ///
    /// Seeds [a, b, c], depth 1, α = 0.15 — hand derivation mirroring the
    /// Layer-1 exact-value test (reverse scan over `edges_in`,
    /// s_in(a, mentions) = 1.8, s_in(c, mentions) = 0.6, λ_mentions = 0.6):
    ///   p_i = 0.2 · (0.6 · 0.6 / 1.8) · 0.85 = 0.034
    ///   q1  = 0.4 · (0.6 · 0.6 / 0.6) · 0.85 = 0.204
    ///   teleport: a += 1.0 · 0.15 · 0.2 ; b, c += 1.0 · 0.15 · 0.4
    ///   a = 0.2 + 0.03 = 0.23 ; b = c = 0.4 + 0.06 = 0.46
    /// UNIFORM seeding instead yields a = b = c = 0.38333, p_i = 0.0566667,
    /// q1 = 0.17 — every value moves, so a uniform implementation fails.
    /// A missing clamp (1/ln(1 + 0) = ∞) sends b's normalized weight to 1.0
    /// and the rest to 0.0 — it fails as well.
    #[test]
    fn seed_specificity_weights_match_derived_values() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(1);
        let b = entity(2);
        let c = entity(3);
        let passages = [entity(10), entity(11), entity(12)];
        let q1 = entity(13);

        for passage in &passages {
            vault.put_edge(passage, EdgeKind::Mentions, &a, 0.6)?;
        }
        vault.put_edge(&q1, EdgeKind::Mentions, &c, 0.6)?;

        let rtxn = vault.store.env.read_txn()?;

        let weights = specificity_seed_weights(&vault.store, &rtxn, &[a, b, c])?;
        let expected_weights = [0.2_f32, 0.4, 0.4];
        for (got, expected) in weights.iter().zip(expected_weights) {
            assert!(
                (got - expected).abs() <= 1e-6,
                "seed weight: got {got}, want {expected}"
            );
        }

        let scores = ppr_compute_weighted(
            &vault.store,
            &rtxn,
            &[a, b, c],
            SeedWeighting::Specificity,
            1,
            0.15,
        )?;
        let cases = [
            (a, 0.23_f32),
            (b, 0.46),
            (c, 0.46),
            (passages[0], 0.034),
            (passages[1], 0.034),
            (passages[2], 0.034),
            (q1, 0.204),
        ];
        for (id, expected) in cases {
            let got = score_for(&scores, id);
            assert!(
                (got - expected).abs() <= 1e-6,
                "score for {id:?}: got {got}, want {expected}"
            );
        }
        Ok(())
    }

    /// ONE-1116 AC2 — single-seed normalization cancels: whatever the
    /// passage count, the lone seed's normalized weight is exactly 1.0, so
    /// specificity seeding equals uniform seeding. Exact values (graph as in
    /// AC1's `a` cluster): a = 1.0 init + 0.15 teleport = 1.15; each
    /// p_i = 1.0 · (0.6 · 0.6 / 1.8) · 0.85 = 0.17.
    #[test]
    fn single_seed_specificity_matches_uniform() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(1);
        let passages = [entity(10), entity(11), entity(12)];

        for passage in &passages {
            vault.put_edge(passage, EdgeKind::Mentions, &a, 0.6)?;
        }

        let rtxn = vault.store.env.read_txn()?;
        let weighted = ppr_compute_weighted(
            &vault.store,
            &rtxn,
            &[a],
            SeedWeighting::Specificity,
            1,
            0.15,
        )?;
        let uniform = ppr_compute(&vault.store, &rtxn, &[a], 1, 0.15)?;

        assert_scores_equal(&weighted, &uniform);
        let cases = [
            (a, 1.15_f32),
            (passages[0], 0.17),
            (passages[1], 0.17),
            (passages[2], 0.17),
        ];
        for (id, expected) in cases {
            let got = score_for(&weighted, id);
            assert!(
                (got - expected).abs() <= 1e-6,
                "score for {id:?}: got {got}, want {expected}"
            );
        }
        Ok(())
    }

    /// ONE-1116 AC3 — `expand_ppr` seeds stay UNIFORM (ARCH-0039 Layer 2 is
    /// `search_ppr`-only). The pipeline's expand pass must write its cache
    /// row under the Uniform key, never the Specificity key, and the cached
    /// scores must equal the hand-derived UNIFORM values for seeds [a, b]
    /// (depth 1, α = 0.15, the AC1 graph where a has 3 inbound mentions and
    /// b has 0):
    ///   weights 0.5 / 0.5 → p_i = 0.5 · (0.6 · 0.6 / 1.8) · 0.85 = 0.085
    ///   a = b = 0.5 + 0.15 · 0.5 = 0.575
    /// Specificity seeding would yield a = 0.3833333, b = 0.7666667,
    /// p_i = 0.0566667 instead — those values must NOT appear.
    #[test]
    fn expand_ppr_pipeline_seeds_stay_uniform() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(1);
        let b = entity(2);
        let passages = [entity(10), entity(11), entity(12)];

        vault
            .batch()
            .put(&a, 1, TimeRange { start: 1, end: 1 }, 1, b"a-data")
            .text(&a, &[("body", "alpha")])
            .commit()?;
        for passage in &passages {
            vault.put_edge(passage, EdgeKind::Mentions, &a, 0.6)?;
        }

        // The text channel ranks [a]; the expand pass dedups it against the
        // explicit seeds, so the PPR seed set is exactly [a, b].
        let _ = vault
            .query()
            .search_text("alpha", 10)
            .expand_ppr(&[a, b], 1)
            .run()?;

        let uniform_hash = hash_seeds(&[a, b], 1, 0.15, SeedWeighting::Uniform);
        let specificity_hash = hash_seeds(&[a, b], 1, 0.15, SeedWeighting::Specificity);
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .ppr_cache
                .get(&rtxn, &specificity_hash)?
                .is_none(),
            "expand_ppr must not write a specificity-keyed cache row"
        );
        let raw = vault
            .store
            .ppr_cache
            .get(&rtxn, &uniform_hash)?
            .ok_or(Error::EntityNotFound)?;
        let scores = decode_cache_scores(&raw[CACHE_HEADER_LEN..])?;

        let cases = [
            (a, 0.575_f32),
            (b, 0.575),
            (passages[0], 0.085),
            (passages[1], 0.085),
            (passages[2], 0.085),
        ];
        for (id, expected) in cases {
            let got = score_for(&scores, id);
            assert!(
                (got - expected).abs() <= 1e-6,
                "expand_ppr cached score for {id:?}: got {got}, want uniform {expected}"
            );
        }
        Ok(())
    }

    /// ONE-1116 AC1/AC4 — the `search_ppr` pipeline pass seeds by
    /// specificity AND keys its cache row with the Specificity byte (never
    /// the Uniform key). Cached scores must equal the weighted derivation
    /// for seeds [a (3 mentions), b (0 mentions)], depth 1, α = 0.15:
    ///   weights 1/3, 2/3 → a = 1/3 + 0.15/3 = 0.3833333,
    ///   b = 2/3 + 0.1 = 0.7666667, p_i = (1/3) · 0.2 · 0.85 = 0.0566667.
    /// A second identical query must be served from that row (round-trip:
    /// identical results, byte-identical cache row).
    #[test]
    fn search_ppr_pipeline_applies_specificity_seeding() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(1);
        let b = entity(2);
        let passages = [entity(10), entity(11), entity(12)];

        for passage in &passages {
            vault.put_edge(passage, EdgeKind::Mentions, &a, 0.6)?;
        }

        let first = vault.query().search_ppr(&[a, b], 1).run()?;

        let uniform_hash = hash_seeds(&[a, b], 1, 0.15, SeedWeighting::Uniform);
        let specificity_hash = hash_seeds(&[a, b], 1, 0.15, SeedWeighting::Specificity);
        let raw = {
            let rtxn = vault.store.env.read_txn()?;
            assert!(
                vault.store.ppr_cache.get(&rtxn, &uniform_hash)?.is_none(),
                "search_ppr must not write a uniform-keyed cache row"
            );
            vault
                .store
                .ppr_cache
                .get(&rtxn, &specificity_hash)?
                .ok_or(Error::EntityNotFound)?
                .to_vec()
        };
        let scores = decode_cache_scores(&raw[CACHE_HEADER_LEN..])?;

        let third = 1.0_f32 / 3.0;
        let cases = [
            (a, third + 0.15 * third),
            (b, 2.0 * third + 0.15 * 2.0 * third),
            (passages[0], third * 0.2 * 0.85),
            (passages[1], third * 0.2 * 0.85),
            (passages[2], third * 0.2 * 0.85),
        ];
        for (id, expected) in cases {
            let got = score_for(&scores, id);
            assert!(
                (got - expected).abs() <= 1e-6,
                "search_ppr cached score for {id:?}: got {got}, want weighted {expected}"
            );
        }

        // Round-trip: the second identical query is served from the row.
        let second = vault.query().search_ppr(&[a, b], 1).run()?;
        assert_scores_equal(&first, &second);
        let rtxn = vault.store.env.read_txn()?;
        let raw_after = vault
            .store
            .ppr_cache
            .get(&rtxn, &specificity_hash)?
            .ok_or(Error::EntityNotFound)?;
        assert_eq!(raw, raw_after, "cache row must be reused, not rewritten");
        Ok(())
    }

    /// ONE-1116 AC4 — PPR_FORMULA_VERSION 2 → 3: a row persisted under the
    /// pre-bump v2 key (seeds ‖ depth ‖ alpha ‖ version 2, NO weighting
    /// byte — the literal pre-ONE-1116 layout) is unreachable even with a
    /// fresh `computed_at`, matching graph version, and stale = 0. The
    /// query recomputes, lands its row under the v3 key, and the orphaned
    /// v2 row is reaped by the existing cleanup (it has no dep rows).
    #[test]
    fn pre_bump_formula_v2_rows_are_never_served() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity(1);
        let b = entity(2);

        vault.put_edge(&a, EdgeKind::BelongsTo, &b, 1.0)?;

        let mut legacy_bytes = Vec::new();
        legacy_bytes.extend_from_slice(a.as_bytes());
        legacy_bytes.extend_from_slice(&3_u32.to_le_bytes());
        legacy_bytes.extend_from_slice(&0.15_f32.to_le_bytes());
        legacy_bytes.extend_from_slice(&2_u32.to_le_bytes());
        let legacy_hash = xxh3_128(&legacy_bytes).to_le_bytes();

        let value = encode_cache_value(
            crate::unix_seconds_now(),
            graph_version(&vault)?,
            0,
            &sentinel_scores(),
        );
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.ppr_cache.put(&mut wtxn, &legacy_hash, &value)?;
        wtxn.commit()?;

        let scores = ppr_query(&vault.store, &vault.config, &[a], 3, 0.15)?;
        assert!(
            !scores.iter().any(|scored| scored.id == sentinel_entity()),
            "pre-bump v2 cache row must never be served"
        );
        assert!(score_for(&scores, b) > 0.0);

        let v3_hash = hash_seeds(&[a], 3, 0.15, SeedWeighting::Uniform);
        {
            let rtxn = vault.store.env.read_txn()?;
            assert!(vault.store.ppr_cache.get(&rtxn, &v3_hash)?.is_some());
        }

        let report = vault
            .maintain()
            .cleanup_ppr_cache(CACHE_TTL_DORMANT_SECS)
            .run()?;
        assert!(report.ppr_caches_evicted >= 1);
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault.store.ppr_cache.get(&rtxn, &legacy_hash)?.is_none(),
            "orphaned v2 row must be reaped by cleanup"
        );
        assert!(
            vault.store.ppr_cache.get(&rtxn, &v3_hash)?.is_some(),
            "live v3 row must survive cleanup"
        );
        Ok(())
    }

    /// ONE-1116 AC5 — recency-tier boundaries, pinned against a FIXED clock
    /// (no real-time dependence) with the contract's LITERAL TTL values
    /// (ARCH-0019 / ARCH-0014): seed recency < 7d → 86 400 s; 7–30 d →
    /// 259 200 s (7 d EXACTLY is Recent); ≥ 30 d → 604 800 s (30 d EXACTLY
    /// is Dormant). Recency = max(learned_at) over the seed set, so the most
    /// recently learned seed wins; future `learned_at` saturates to Active;
    /// record-less seed sets and unparsable records fail closed to Active.
    #[test]
    fn recency_tier_boundaries_match_contract() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let now: u64 = 20_000 * 86_400;
        let day: u64 = 86_400;
        let tr = TimeRange { start: 1, end: 1 };

        // (entity byte, learned_at, expected ttl — LITERAL seconds)
        let cases: [(u8, u64, u64); 8] = [
            (1, now, 86_400),                   // learned this instant
            (2, now - day, 86_400),             // 1 day old
            (3, now - (7 * day - 1), 86_400),   // just inside Active
            (4, now - 7 * day, 259_200),        // exactly 7 d → Recent
            (5, now - (30 * day - 1), 259_200), // just inside Recent
            (6, now - 30 * day, 604_800),       // exactly 30 d → Dormant
            (7, now - 365 * day, 604_800),      // deep dormant
            (8, now + day, 86_400),             // future learned_at saturates
        ];

        for (byte, learned_at, _) in cases {
            vault.put_entity(&entity(byte), 1, tr, learned_at, b"seed")?;
        }

        let rtxn = vault.store.env.read_txn()?;
        for (byte, _, expected_ttl) in cases {
            let ttl = recency_tiered_cache_ttl_secs(&vault.store, &rtxn, &[entity(byte)], now)?;
            assert_eq!(ttl, expected_ttl, "ttl for seed byte {byte}");
        }

        // max(learned_at) over the seed set: dormant + active → ACTIVE wins.
        let mixed =
            recency_tiered_cache_ttl_secs(&vault.store, &rtxn, &[entity(7), entity(2)], now)?;
        assert_eq!(mixed, 86_400, "most recent seed must decide the tier");

        // Record-less seeds contribute nothing; alongside a dormant seed the
        // dormant learned_at still decides.
        let with_unknown =
            recency_tiered_cache_ttl_secs(&vault.store, &rtxn, &[entity(7), entity(200)], now)?;
        assert_eq!(with_unknown, 604_800);

        // An all-record-less seed set fails closed to the shortest tier.
        let unknown_only = recency_tiered_cache_ttl_secs(&vault.store, &rtxn, &[entity(200)], now)?;
        assert_eq!(unknown_only, 86_400);
        drop(rtxn);

        // A present-but-unparsable entity record fails closed to Active,
        // even when a dormant seed is also present.
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .entities
            .put(&mut wtxn, entity(9).as_bytes(), &[1, 2, 3])?;
        wtxn.commit()?;
        let rtxn = vault.store.env.read_txn()?;
        let corrupt =
            recency_tiered_cache_ttl_secs(&vault.store, &rtxn, &[entity(7), entity(9)], now)?;
        assert_eq!(corrupt, 86_400);
        Ok(())
    }

    /// ONE-1116 AC5 — the read gate enforces the recency-tiered TTL: a
    /// planted sentinel row is served while inside its seed-tier TTL and
    /// recomputed past it. One-hour margins keep the cases immune to wall
    /// clock drift during the run. Covers: active rows expiring at 24 h;
    /// recent/dormant rows SURVIVING past 24 h; dormant rows serving up to
    /// (but not beyond) 168 h; record-less seeds failing closed to 24 h;
    /// and max(learned_at) pulling a mixed dormant+active seed set down to
    /// the 24 h tier.
    #[test]
    fn cache_read_gate_applies_recency_tiered_ttl() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let now = crate::unix_seconds_now();
        let day: u64 = 86_400;
        let hour: u64 = 3_600;
        let tr = TimeRange { start: 1, end: 1 };

        // (name, seed learned-ages in days (None = no entity record),
        //  row age, expect served)
        let cases: [(&str, &[Option<u64>], u64, bool); 8] = [
            (
                "active_served_within_24h",
                &[Some(1)],
                CACHE_TTL_ACTIVE_SECS - hour,
                true,
            ),
            (
                "active_expires_past_24h",
                &[Some(1)],
                CACHE_TTL_ACTIVE_SECS + hour,
                false,
            ),
            (
                "recent_survives_past_24h",
                &[Some(10)],
                CACHE_TTL_ACTIVE_SECS + hour,
                true,
            ),
            (
                "recent_expires_past_72h",
                &[Some(10)],
                CACHE_TTL_RECENT_SECS + hour,
                false,
            ),
            (
                "dormant_survives_to_168h",
                &[Some(40)],
                CACHE_TTL_DORMANT_SECS - hour,
                true,
            ),
            (
                "dormant_expires_past_168h",
                &[Some(40)],
                CACHE_TTL_DORMANT_SECS + hour,
                false,
            ),
            (
                "recordless_seed_fails_closed_to_24h",
                &[None],
                CACHE_TTL_ACTIVE_SECS + hour,
                false,
            ),
            (
                "max_learned_at_wins",
                &[Some(40), Some(1)],
                CACHE_TTL_ACTIVE_SECS + hour,
                false,
            ),
        ];

        let mut byte = 1_u8;
        for (name, seed_ages, row_age, expect_served) in cases {
            let mut seeds = Vec::new();
            for seed_age_days in seed_ages {
                let seed = entity(byte);
                byte += 1;
                if let Some(days) = seed_age_days {
                    vault.put_entity(&seed, 1, tr, now - days * day, b"seed")?;
                }
                seeds.push(seed);
            }

            plant_cache_row(
                &vault,
                &seeds,
                3,
                0.15,
                SeedWeighting::Uniform,
                now - row_age,
                &sentinel_scores(),
            )?;

            let scores = ppr_query(&vault.store, &vault.config, &seeds, 3, 0.15)?;
            let served = scores.iter().any(|scored| scored.id == sentinel_entity());
            assert_eq!(served, expect_served, "case {name}");
        }
        Ok(())
    }

    /// ONE-1116 AC6 — cleanup `max_age_secs` is a HARD bound independent of
    /// the tiered serve TTL; with the documented bound (the longest tier,
    /// 168 h) cleanup never evicts a row the read gate could still serve.
    /// Three planted rows: a dormant-seeded and an active-seeded row both
    /// aged 100 h survive cleanup (only the read gate distinguishes them:
    /// the dormant row is still served, the active one is not), while a
    /// dormant-seeded row aged 169 h (> 168 h) is evicted.
    #[test]
    fn cleanup_max_age_bound_is_consistent_with_tiered_ttl() -> Result<()> {
        let temp_dir = tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let now = crate::unix_seconds_now();
        let day: u64 = 86_400;
        let hour: u64 = 3_600;
        let tr = TimeRange { start: 1, end: 1 };

        let dormant_served = entity(1);
        let active_unserved = entity(2);
        let dormant_expired = entity(3);
        vault.put_entity(&dormant_served, 1, tr, now - 40 * day, b"seed")?;
        vault.put_entity(&active_unserved, 1, tr, now - day, b"seed")?;
        vault.put_entity(&dormant_expired, 1, tr, now - 40 * day, b"seed")?;

        let dormant_hash = plant_cache_row(
            &vault,
            &[dormant_served],
            3,
            0.15,
            SeedWeighting::Uniform,
            now - 100 * hour,
            &sentinel_scores(),
        )?;
        let active_hash = plant_cache_row(
            &vault,
            &[active_unserved],
            3,
            0.15,
            SeedWeighting::Uniform,
            now - 100 * hour,
            &sentinel_scores(),
        )?;
        let expired_hash = plant_cache_row(
            &vault,
            &[dormant_expired],
            3,
            0.15,
            SeedWeighting::Uniform,
            now - 169 * hour,
            &sentinel_scores(),
        )?;

        let report = vault
            .maintain()
            .cleanup_ppr_cache(CACHE_TTL_DORMANT_SECS)
            .run()?;
        assert_eq!(report.ppr_caches_evicted, 1, "only the 169h row may go");

        {
            let rtxn = vault.store.env.read_txn()?;
            assert!(vault.store.ppr_cache.get(&rtxn, &dormant_hash)?.is_some());
            assert!(vault.store.ppr_cache.get(&rtxn, &active_hash)?.is_some());
            assert!(vault.store.ppr_cache.get(&rtxn, &expired_hash)?.is_none());
        }

        // Servability is the read gate's call, not cleanup's: the surviving
        // dormant row is still served at 100 h; the surviving active row is
        // past its 24 h tier and recomputes.
        let dormant_scores = ppr_query(&vault.store, &vault.config, &[dormant_served], 3, 0.15)?;
        assert!(
            dormant_scores
                .iter()
                .any(|scored| scored.id == sentinel_entity()),
            "dormant-seeded row aged 100h must still be served"
        );

        let active_scores = ppr_query(&vault.store, &vault.config, &[active_unserved], 3, 0.15)?;
        assert!(
            !active_scores
                .iter()
                .any(|scored| scored.id == sentinel_entity()),
            "active-seeded row aged 100h must NOT be served"
        );
        Ok(())
    }
}
