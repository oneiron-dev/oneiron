use std::collections::{HashMap, HashSet};

use heed::{RoTxn, RwTxn};
use xxhash_rust::xxh3::xxh3_128;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
#[cfg(test)]
use crate::config::VaultConfig;
#[cfg(test)]
use crate::edge::EDGE_VALUE_STRUCTURAL_LEN;
use crate::edge::{
    EdgeConfirmationStatus, EdgeKind, parse_strict_edge_record, parse_strict_edge_record_key,
};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::pipeline::ScoredEntity;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;

const SEED_HASH_LEN: usize = 16;
#[cfg(test)]
const LEGACY_SEED_HASH_LEN: usize = 32;
const CACHE_HEADER_LEN: usize = 17;
const CACHE_STALE_OFFSET: usize = 16;
const CACHE_ENTRY_LEN: usize = 20;
const CACHE_STATE_MAGIC: &[u8; 4] = b"FPRS";
const CACHE_STATE_VERSION: u8 = 1;
const CACHE_STATE_PREFIX_LEN: usize = 21;
const CACHE_FRONTIER_ENTRY_LEN: usize = ENTITY_ID_LEN + 8;
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
/// byte. v4 = ONE-1236 lexical query hint side claims are skipped during
/// `ClaimOf` traversal so synthetic hint records do not consume transition
/// mass. Pre-bump rows are unreachable under v4 keys.
const PPR_FORMULA_VERSION: u32 = 4;

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
    computed_at: u64,
    graph_version: u64,
    state: PprCacheState,
}

#[derive(Debug, Clone)]
struct PprFrontierEntry {
    id: EntityId,
    structural_hops: u32,
    score: f32,
}

#[derive(Debug, Clone)]
struct PprCacheState {
    completed_depth: u32,
    scores: Vec<ScoredEntity>,
    frontier: Vec<PprFrontierEntry>,
    dependencies: Vec<EntityId>,
}

enum CachedPprRow {
    Scores(Vec<ScoredEntity>),
    State(PprCacheState),
}

impl CachedPprRow {
    fn into_scores(self) -> Vec<ScoredEntity> {
        match self {
            Self::Scores(scores) => scores,
            Self::State(state) => state.scores,
        }
    }

    fn into_state(self) -> Option<PprCacheState> {
        match self {
            Self::Scores(_) => None,
            Self::State(state) => Some(state),
        }
    }
}

struct PprRoundContext<'a, 'txn> {
    store: &'a Store,
    txn: &'a RoTxn<'txn>,
    seeds: &'a [EntityId],
    seed_weights: &'a [f32],
    alpha: f32,
}

struct PprCacheReadContext<'a, 'txn> {
    store: &'a Store,
    txn: &'a RoTxn<'txn>,
    seeds: &'a [EntityId],
    alpha: f32,
    weighting: SeedWeighting,
    now: u64,
    current_graph_version: u64,
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
/// per-type strength database (the pinned DB manifest contains none).
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
#[cfg(test)]
pub(crate) fn ppr_compute_weighted(
    store: &Store,
    txn: &RoTxn<'_>,
    seeds: &[EntityId],
    weighting: SeedWeighting,
    depth: u32,
    alpha: f32,
) -> Result<Vec<ScoredEntity>> {
    Ok(ppr_compute_state_weighted(store, txn, seeds, weighting, depth, alpha)?.scores)
}

fn ppr_compute_state_weighted(
    store: &Store,
    txn: &RoTxn<'_>,
    seeds: &[EntityId],
    weighting: SeedWeighting,
    depth: u32,
    alpha: f32,
) -> Result<PprCacheState> {
    if seeds.is_empty() {
        return Ok(PprCacheState {
            completed_depth: 0,
            scores: Vec::new(),
            frontier: Vec::new(),
            dependencies: Vec::new(),
        });
    }

    let seed_weights = seed_weights(store, txn, seeds, weighting)?;
    let mut scores = HashMap::<EntityId, f32>::new();
    let mut frontier = HashMap::<(EntityId, u32), f32>::new();
    let mut dependencies = HashSet::<EntityId>::new();

    for (seed, weight) in seeds.iter().zip(&seed_weights) {
        *scores.entry(*seed).or_default() += *weight;
        *frontier.entry((*seed, 0)).or_default() += *weight;
        dependencies.insert(*seed);
    }

    let round_context = PprRoundContext {
        store,
        txn,
        seeds,
        seed_weights: &seed_weights,
        alpha,
    };
    run_ppr_rounds(
        round_context,
        depth,
        &mut scores,
        &mut frontier,
        &mut dependencies,
    )?;

    Ok(cache_state_from_maps(depth, scores, frontier, dependencies))
}

fn ppr_resume_state_weighted(
    store: &Store,
    txn: &RoTxn<'_>,
    seeds: &[EntityId],
    weighting: SeedWeighting,
    target_depth: u32,
    alpha: f32,
    resume: PprCacheState,
) -> Result<PprCacheState> {
    let seed_weights = seed_weights(store, txn, seeds, weighting)?;
    let mut scores = scores_to_map(resume.scores);
    let mut frontier = frontier_to_map(resume.frontier);
    let mut dependencies: HashSet<EntityId> = resume.dependencies.into_iter().collect();
    for seed in seeds {
        dependencies.insert(*seed);
    }

    let remaining_depth = target_depth
        .checked_sub(resume.completed_depth)
        .ok_or(Error::CorruptedIndex("ppr cache state"))?;
    let round_context = PprRoundContext {
        store,
        txn,
        seeds,
        seed_weights: &seed_weights,
        alpha,
    };
    run_ppr_rounds(
        round_context,
        remaining_depth,
        &mut scores,
        &mut frontier,
        &mut dependencies,
    )?;

    Ok(cache_state_from_maps(
        target_depth,
        scores,
        frontier,
        dependencies,
    ))
}

fn run_ppr_rounds(
    context: PprRoundContext<'_, '_>,
    rounds: u32,
    scores: &mut HashMap<EntityId, f32>,
    frontier: &mut HashMap<(EntityId, u32), f32>,
    dependencies: &mut HashSet<EntityId>,
) -> Result<()> {
    let edge_dbs = [&context.store.edges_out, &context.store.edges_in];

    for _ in 0..rounds {
        if frontier.is_empty() {
            break;
        }

        let total: f32 = frontier.values().copied().sum();
        let mut next = HashMap::<(EntityId, u32), f32>::new();

        for (&(node, hops), &score) in frontier.iter() {
            if score < SCORE_EPSILON {
                continue;
            }
            dependencies.insert(node);

            // Layer-1 normalization is per (node, kind, direction): the
            // forward scan over `edges_out` normalizes by s_out(u, τ) and the
            // reverse scan over `edges_in` by the symmetric s_in(u, τ), so
            // each database scan gates and groups its rows independently.
            for db in edge_dbs {
                let mut groups = HashMap::<EdgeKind, Vec<GatedEdge>>::new();
                for entry in db.prefix_iter(context.txn, node.as_bytes())? {
                    let (key, value) = entry?;
                    if let Some(edge) = gate_edge(context.store, context.txn, key, value, hops)? {
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
                            score * (edge.lambda * edge.weight / strength) * (1.0 - context.alpha);
                        *next.entry((edge.neighbor, edge.new_hops)).or_default() += propagated;
                    }
                }
            }
        }

        let teleport_mass = total * context.alpha;
        for (seed, weight) in context.seeds.iter().zip(context.seed_weights) {
            *next.entry((*seed, 0)).or_default() += teleport_mass * *weight;
        }

        for (&(node, _), &score) in &next {
            *scores.entry(node).or_default() += score;
        }

        *frontier = next;
    }

    Ok(())
}

fn cache_state_from_maps(
    completed_depth: u32,
    scores: HashMap<EntityId, f32>,
    frontier: HashMap<(EntityId, u32), f32>,
    dependencies: HashSet<EntityId>,
) -> PprCacheState {
    let mut ranked: Vec<ScoredEntity> = scores
        .into_iter()
        .map(|(id, score)| ScoredEntity { id, score })
        .collect();
    sort_scores(&mut ranked);

    let mut frontier: Vec<PprFrontierEntry> = frontier
        .into_iter()
        .map(|((id, structural_hops), score)| PprFrontierEntry {
            id,
            structural_hops,
            score,
        })
        .collect();
    sort_frontier(&mut frontier);

    let mut dependencies: Vec<EntityId> = dependencies.into_iter().collect();
    dependencies.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    dependencies.dedup();

    PprCacheState {
        completed_depth,
        scores: ranked,
        frontier,
        dependencies,
    }
}

fn scores_to_map(scores: Vec<ScoredEntity>) -> HashMap<EntityId, f32> {
    let mut out = HashMap::with_capacity(scores.len());
    for scored in scores {
        *out.entry(scored.id).or_default() += scored.score;
    }
    out
}

fn frontier_to_map(frontier: Vec<PprFrontierEntry>) -> HashMap<(EntityId, u32), f32> {
    let mut out = HashMap::with_capacity(frontier.len());
    for entry in frontier {
        *out.entry((entry.id, entry.structural_hops)).or_default() += entry.score;
    }
    out
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
/// persisted counter exists in the DB manifest). Corrupt rows are a typed
/// error, never silently skipped.
fn inbound_mentions_count(store: &Store, txn: &RoTxn<'_>, seed: &EntityId) -> Result<u64> {
    let mut count = 0_u64;
    for entry in store.edges_in.prefix_iter(txn, seed.as_bytes())? {
        let (key, _) = entry?;
        let (_, kind, _) = parse_strict_edge_record_key(key)?;
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
            deferred_write.computed_at,
            deferred_write.graph_version,
            &deferred_write.state,
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
            write.computed_at,
            write.graph_version,
            &write.state,
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
    let cache_context = PprCacheReadContext {
        store,
        txn,
        seeds,
        alpha,
        weighting,
        now,
        current_graph_version,
    };

    if let Some(row) = read_exact_cache_row(&cache_context, &seed_hash, depth)? {
        let mut scores = row.into_scores();
        sort_scores(&mut scores);
        return Ok((scores, None));
    }

    let resume = read_deepest_resume_state(&cache_context, depth)?;
    let state = if let Some(resume) = resume {
        ppr_resume_state_weighted(store, txn, seeds, weighting, depth, alpha, resume)?
    } else {
        ppr_compute_state_weighted(store, txn, seeds, weighting, depth, alpha)?
    };
    let scores = state.scores.clone();
    if !defer_cache_writes {
        return Ok((scores, None));
    }

    let deferred_write = DeferredPprCacheWrite {
        seed_hash,
        computed_at: now,
        graph_version: current_graph_version,
        state,
    };
    Ok((scores, Some(deferred_write)))
}

fn read_deepest_resume_state(
    context: &PprCacheReadContext<'_, '_>,
    target_depth: u32,
) -> Result<Option<PprCacheState>> {
    for completed_depth in (0..target_depth).rev() {
        let seed_hash = hash_seeds(
            context.seeds,
            completed_depth,
            context.alpha,
            context.weighting,
        );
        let Some(row) = read_resume_cache_row(context, &seed_hash, completed_depth)? else {
            continue;
        };
        let Some(state) = row.into_state() else {
            continue;
        };
        return Ok(Some(state));
    }
    Ok(None)
}

fn read_exact_cache_row(
    context: &PprCacheReadContext<'_, '_>,
    seed_hash: &[u8; SEED_HASH_LEN],
    expected_depth: u32,
) -> Result<Option<CachedPprRow>> {
    read_servable_cache_row(context, seed_hash, expected_depth, true)
}

fn read_resume_cache_row(
    context: &PprCacheReadContext<'_, '_>,
    seed_hash: &[u8; SEED_HASH_LEN],
    expected_depth: u32,
) -> Result<Option<CachedPprRow>> {
    read_servable_cache_row(context, seed_hash, expected_depth, false)
}

fn read_servable_cache_row(
    context: &PprCacheReadContext<'_, '_>,
    seed_hash: &[u8; SEED_HASH_LEN],
    expected_depth: u32,
    enforce_ttl: bool,
) -> Result<Option<CachedPprRow>> {
    let Some(raw) = context.store.ppr_cache.get(context.txn, seed_hash)? else {
        return Ok(None);
    };
    let (computed_at, cached_graph_version, stale) = parse_cache_header(raw)?;
    if stale != 0 || cached_graph_version != context.current_graph_version {
        return Ok(None);
    }

    if enforce_ttl {
        // ARCH-0019 / ARCH-0014 recency-tiered serve TTL: the seed set's
        // max(learned_at) decides the tier at read time (24h / 72h / 168h);
        // see `recency_tiered_cache_ttl_secs` for the contract cite and the
        // fail-closed defaults. Only consulted for rows that already passed
        // the stale + graph-version gates, and only for final-score hits.
        let ttl_secs =
            recency_tiered_cache_ttl_secs(context.store, context.txn, context.seeds, context.now)?;
        if context.now.saturating_sub(computed_at) > ttl_secs {
            return Ok(None);
        }
    }

    let row = decode_cache_payload(&raw[CACHE_HEADER_LEN..])?;
    if let CachedPprRow::State(state) = &row
        && state.completed_depth != expected_depth
    {
        return Err(Error::CorruptedIndex("ppr cache state"));
    }

    Ok(Some(row))
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
        let Some(raw) = store.ppr_cache.get(&*wtxn, &seed_hash)? else {
            continue;
        };
        if raw.len() < CACHE_HEADER_LEN {
            store.ppr_cache.delete(wtxn, &seed_hash)?;
            continue;
        }
        let mut patched = raw.to_vec();
        patched[CACHE_STALE_OFFSET] = 1;
        store.ppr_cache.put(wtxn, &seed_hash, &patched)?;
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
    computed_at: u64,
    graph_version: u64,
    state: &PprCacheState,
) -> Result<bool> {
    if read_graph_version(store, &*wtxn)? != graph_version {
        return Ok(false);
    }

    let encoded = encode_cache_value_with_state(computed_at, graph_version, 0, state)?;
    store.ppr_cache.put(wtxn, seed_hash, &encoded)?;
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
fn gate_edge(
    store: &Store,
    txn: &RoTxn<'_>,
    key: &[u8],
    value: &[u8],
    hops: u32,
) -> Result<Option<GatedEdge>> {
    let edge = parse_strict_edge_record(key, value)?;
    let current = edge.source;
    let kind = edge.kind;
    let neighbor = edge.target;
    let decoded = edge.decoded;

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

    // Synthetic lexical-query hint claims use ClaimOf as a local target
    // relation for cleanup/search compatibility, but they are derived text
    // index side records and must not consume PPR transition mass.
    if kind == EdgeKind::ClaimOf
        && (entity_is_lexical_query_hint_claim(store, txn, &current)?
            || entity_is_lexical_query_hint_claim(store, txn, &neighbor)?)
    {
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

fn entity_is_lexical_query_hint_claim(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(false);
    };
    let Some(header) = EntityMetadataHeader::parse(raw) else {
        return Err(Error::CorruptedIndex("entity header"));
    };
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(false);
    }
    let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    Ok(body.predicate == crate::claim::PREDICATE_LEXICAL_QUERY_HINT)
}

fn sort_scores(scores: &mut [ScoredEntity]) {
    scores.sort_unstable_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.id.as_bytes().cmp(b.id.as_bytes()))
    });
}

fn sort_frontier(frontier: &mut [PprFrontierEntry]) {
    frontier.sort_unstable_by(|a, b| {
        a.id.as_bytes()
            .cmp(b.id.as_bytes())
            .then_with(|| a.structural_hops.cmp(&b.structural_hops))
            .then_with(|| b.score.total_cmp(&a.score))
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

#[cfg(test)]
fn decode_cache_scores(payload: &[u8]) -> Result<Vec<ScoredEntity>> {
    let decoded = decode_cache_payload(payload)?;
    Ok(decoded.into_scores())
}

fn decode_cache_payload(payload: &[u8]) -> Result<CachedPprRow> {
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

fn decode_cache_state(payload: &[u8]) -> Result<PprCacheState> {
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

fn encode_cache_value_with_state(
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

#[cfg(test)]
mod tests;
