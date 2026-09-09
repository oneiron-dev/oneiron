//! PPR query dispatch: cache-read context, deferred writes, and VAD evidence scope.

use std::cell::Cell;
use std::rc::Rc;

use heed::RoTxn;
use xxhash_rust::xxh3::xxh3_128;

#[cfg(test)]
use crate::config::VaultConfig;
use crate::config::validate_ppr_vad_alpha;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::pipeline::ScoredEntity;
use crate::retrieval_quality::PprCacheOutcome;
use crate::store::ManifestDbs;
#[cfg(test)]
use crate::store::Store;

use super::VAD_PROPAGATION_EVIDENCE;
#[cfg(test)]
use super::cache_store::flush_deferred_ppr_cache_writes;
use super::cache_store::{
    CACHE_HEADER_LEN, MAX_PPR_DEPTH, MAX_PPR_SEEDS, PPR_FORMULA_VERSION, SEED_HASH_LEN,
    decode_cache_payload, parse_cache_header, read_graph_version, recency_tiered_cache_ttl_secs,
};
use super::community::hash_community_seeds;
use super::policy::{PprAlphas, SeedWeighting, canonical_vad_alpha};
use super::walk::{
    CachedPprRow, PprCacheState, PprNodeVisibility, ppr_compute_state_weighted,
    ppr_resume_state_weighted, sort_scores,
};

struct VadPropagationEvidenceScope {
    previous: Option<Rc<Cell<bool>>>,
}
impl Drop for VadPropagationEvidenceScope {
    fn drop(&mut self) {
        VAD_PROPAGATION_EVIDENCE.with(|active| {
            active.replace(self.previous.take());
        });
    }
}
impl crate::PipelineBuilder<'_> {
    /// Runs retrieval and reports whether stored VAD changed a propagated PPR
    /// mass at the configured coefficient. This is traversal evidence, NOT a
    /// final-ranking improvement or a recall measurement.
    ///
    /// PPR cache reads and writes are bypassed for this diagnostic run so a
    /// cached ranking cannot stand in for observed propagation. All other
    /// query behavior, including the production final rows, is unchanged.
    #[doc(hidden)]
    pub fn run_with_ppr_vad_evidence(self) -> Result<(Vec<ScoredEntity>, bool)> {
        let evidence = Rc::new(Cell::new(false));
        let previous =
            VAD_PROPAGATION_EVIDENCE.with(|active| active.replace(Some(evidence.clone())));
        let _scope = VadPropagationEvidenceScope { previous };
        let rows = self.run()?;
        Ok((rows, evidence.get()))
    }
}
/// Cache diagnostics from the same read that produced the unchanged scores.
#[derive(Debug, Clone)]
pub(crate) struct PprQueryResult {
    pub(crate) scores: Vec<ScoredEntity>,
    pub(crate) cache: PprCacheOutcome,
    pub(crate) deferred_cache_write: Option<DeferredPprCacheWrite>,
}
#[derive(Debug, Clone)]
pub(crate) struct DeferredPprCacheWrite {
    pub(super) seed_hash: [u8; SEED_HASH_LEN],
    pub(super) computed_at: u64,
    pub(super) graph_version: u64,
    pub(super) state: Option<PprCacheState>,
    pub(super) community_snapshot: Option<crate::ppr_community::CommunitySnapshot>,
}
struct PprCacheReadContext<'a, 'txn, D: ManifestDbs> {
    store: &'a D,
    txn: &'a RoTxn<'txn>,
    seeds: &'a [EntityId],
    teleport_alpha: f32,
    ppr_vad_alpha: f32,
    weighting: SeedWeighting,
    now: u64,
    current_graph_version: u64,
    community_identity: Option<[u8; 12]>,
}
/// Test-only convenience wrapper. Seeds UNIFORM mass (the `expand_ppr` /
/// pre-Layer-2 path); Layer-2 tests go through
/// [`ppr_query_in_txn_with_vad_deferred_cache`] or the pipeline.
#[cfg(test)]
pub(super) fn ppr_query(
    store: &Store,
    config: &VaultConfig,
    seeds: &[EntityId],
    depth: u32,
    teleport_alpha: f32,
) -> Result<Vec<ScoredEntity>> {
    let result = {
        let rtxn = store.env.read_txn()?;
        ppr_query_in_txn_impl(
            store,
            &rtxn,
            seeds,
            depth,
            PprAlphas {
                teleport_alpha,
                ppr_vad_alpha: config.ppr_vad_alpha,
            },
            SeedWeighting::Uniform,
            true,
        )?
    };

    if let Some(deferred_write) = result.deferred_cache_write {
        flush_deferred_ppr_cache_writes(store, &[deferred_write])?;
    }

    Ok(result.scores)
}
#[cfg(test)]
pub(super) fn ppr_query_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    seeds: &[EntityId],
    depth: u32,
    teleport_alpha: f32,
) -> Result<Vec<ScoredEntity>> {
    ppr_query_in_txn_impl(
        store,
        txn,
        seeds,
        depth,
        PprAlphas::default_vad(teleport_alpha),
        SeedWeighting::Uniform,
        false,
    )
    .map(|result| result.scores)
}
/// VAD-aware vault-wide query using the owning vault's configured coefficient.
pub(crate) fn ppr_query_in_txn_with_vad_deferred_cache(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    seeds: &[EntityId],
    depth: u32,
    teleport_alpha: f32,
    ppr_vad_alpha: f32,
    weighting: SeedWeighting,
) -> Result<(Vec<ScoredEntity>, Option<DeferredPprCacheWrite>)> {
    ppr_query_in_txn_with_diagnostics(
        store,
        txn,
        seeds,
        depth,
        teleport_alpha,
        ppr_vad_alpha,
        weighting,
    )
    .map(|result| (result.scores, result.deferred_cache_write))
}
/// Cache diagnostics from the same VAD-aware read that produced the scores.
pub(crate) fn ppr_query_in_txn_with_diagnostics(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    seeds: &[EntityId],
    depth: u32,
    teleport_alpha: f32,
    ppr_vad_alpha: f32,
    weighting: SeedWeighting,
) -> Result<PprQueryResult> {
    ppr_query_in_txn_impl(
        store,
        txn,
        seeds,
        depth,
        PprAlphas {
            teleport_alpha,
            ppr_vad_alpha,
        },
        weighting,
        true,
    )
}
fn ppr_query_in_txn_impl(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    seeds: &[EntityId],
    depth: u32,
    alphas: PprAlphas,
    weighting: SeedWeighting,
    defer_cache_writes: bool,
) -> Result<PprQueryResult> {
    ppr_query_in_txn_with_identity(
        store,
        txn,
        seeds,
        depth,
        alphas,
        weighting,
        PprCachePolicy {
            defer_writes: defer_cache_writes,
            community_identity: None,
        },
    )
}
pub(super) fn ppr_query_in_txn_with_identity(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    seeds: &[EntityId],
    depth: u32,
    alphas: PprAlphas,
    weighting: SeedWeighting,
    policy: PprCachePolicy,
) -> Result<PprQueryResult> {
    validate_ppr_request(seeds, depth)?;

    validate_ppr_vad_alpha(alphas.ppr_vad_alpha)?;

    if seeds.is_empty() {
        return Ok(PprQueryResult {
            scores: Vec::new(),
            cache: PprCacheOutcome::Disabled,
            deferred_cache_write: None,
        });
    }

    if VAD_PROPAGATION_EVIDENCE.with(|active| active.borrow().is_some()) {
        let state = ppr_compute_state_weighted(store, txn, seeds, weighting, depth, alphas, None)?;
        return Ok(PprQueryResult {
            scores: state.scores,
            cache: PprCacheOutcome::Disabled,
            deferred_cache_write: None,
        });
    }

    let seed_hash = hash_community_seeds(
        hash_seeds(
            seeds,
            depth,
            alphas.teleport_alpha,
            alphas.ppr_vad_alpha,
            weighting,
        ),
        policy.community_identity,
    );
    let now = crate::unix_seconds_now();
    let current_graph_version = read_graph_version(store, txn)?;
    let cache_context = PprCacheReadContext {
        store,
        txn,
        seeds,
        teleport_alpha: alphas.teleport_alpha,
        ppr_vad_alpha: alphas.ppr_vad_alpha,
        weighting,
        now,
        current_graph_version,
        community_identity: policy.community_identity,
    };

    if let Some(row) = read_exact_cache_row(&cache_context, &seed_hash, depth)? {
        let mut scores = row.into_scores();
        sort_scores(&mut scores);
        return Ok(PprQueryResult {
            scores,
            cache: PprCacheOutcome::Hit,
            deferred_cache_write: None,
        });
    }

    let resume = read_deepest_resume_state(&cache_context, depth)?;
    let state = if let Some(resume) = resume {
        ppr_resume_state_weighted(store, txn, seeds, weighting, depth, alphas, resume)?
    } else {
        ppr_compute_state_weighted(store, txn, seeds, weighting, depth, alphas, None)?
    };
    let scores = state.scores.clone();
    if !policy.defer_writes {
        return Ok(PprQueryResult {
            scores,
            cache: PprCacheOutcome::Miss,
            deferred_cache_write: None,
        });
    }

    let deferred_write = DeferredPprCacheWrite {
        seed_hash,
        computed_at: now,
        graph_version: current_graph_version,
        state: Some(state),
        community_snapshot: None,
    };
    Ok(PprQueryResult {
        scores,
        cache: PprCacheOutcome::Miss,
        deferred_cache_write: Some(deferred_write),
    })
}
fn read_deepest_resume_state(
    context: &PprCacheReadContext<'_, '_, impl ManifestDbs>,
    target_depth: u32,
) -> Result<Option<PprCacheState>> {
    for completed_depth in (0..target_depth).rev() {
        let seed_hash = hash_community_seeds(
            hash_seeds(
                context.seeds,
                completed_depth,
                context.teleport_alpha,
                context.ppr_vad_alpha,
                context.weighting,
            ),
            context.community_identity,
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
    context: &PprCacheReadContext<'_, '_, impl ManifestDbs>,
    seed_hash: &[u8; SEED_HASH_LEN],
    expected_depth: u32,
) -> Result<Option<CachedPprRow>> {
    read_servable_cache_row(context, seed_hash, expected_depth, true)
}
fn read_resume_cache_row(
    context: &PprCacheReadContext<'_, '_, impl ManifestDbs>,
    seed_hash: &[u8; SEED_HASH_LEN],
    expected_depth: u32,
) -> Result<Option<CachedPprRow>> {
    read_servable_cache_row(context, seed_hash, expected_depth, false)
}
fn read_servable_cache_row(
    context: &PprCacheReadContext<'_, '_, impl ManifestDbs>,
    seed_hash: &[u8; SEED_HASH_LEN],
    expected_depth: u32,
    enforce_ttl: bool,
) -> Result<Option<CachedPprRow>> {
    let Some(raw) = context.store.ppr_cache().get(context.txn, seed_hash)? else {
        return Ok(None);
    };
    let (computed_at, cached_graph_version, stale) = parse_cache_header(&raw)?;
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
pub(super) fn validate_ppr_request(seeds: &[EntityId], depth: u32) -> Result<()> {
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
/// ACTOR-SCOPED, COMPUTE-ONLY personalized walk (ONE-1608 / ARCH-0050 R6 L2).
///
/// Same Layer-1 formula, same λ table, same gates as
/// [`ppr_query_in_txn_with_vad_deferred_cache`], plus [`PprNodeVisibility`] as a
/// traversal gate — and three deliberate subtractions:
///
/// 1. NO CACHE READ. `ppr_cache` rows are keyed by `(seeds, depth, teleport_alpha,
///    ppr_vad_alpha, weighting)` and carry no actor, so serving one here would hand an actor
///    a ranking computed over nodes it cannot read (and, in the other
///    direction, a scoped row served to the ordinary path would silently
///    narrow it). The two rankings are different objects; they do not share
///    storage.
/// 2. NO CACHE WRITE and no dependency rows, for the same reason.
/// 3. NO graph-version write. This is a read.
///
/// Seed handling is the scope boundary's first half: unreadable seeds are
/// dropped BEFORE [`seed_weights`] runs, so the personalization vector
/// renormalizes over the readable seeds and still sums to 1.0. An all-denied
/// seed set yields no scores at all rather than an unpersonalized walk.
#[expect(
    clippy::too_many_arguments,
    reason = "scoped PPR carries both configured alphas and visibility"
)]
pub(crate) fn ppr_query_scoped_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    seeds: &[EntityId],
    depth: u32,
    teleport_alpha: f32,
    ppr_vad_alpha: f32,
    weighting: SeedWeighting,
    visibility: &dyn PprNodeVisibility,
) -> Result<Vec<ScoredEntity>> {
    ppr_query_scoped_in_txn_with_diagnostics(
        store,
        txn,
        seeds,
        depth,
        teleport_alpha,
        ppr_vad_alpha,
        weighting,
        visibility,
    )
    .map(|result| result.scores)
}
/// Scoped walks bypass the shared cache, including all-denied seed sets.
#[expect(
    clippy::too_many_arguments,
    reason = "scoped PPR carries both configured alphas and visibility"
)]
pub(crate) fn ppr_query_scoped_in_txn_with_diagnostics(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    seeds: &[EntityId],
    depth: u32,
    teleport_alpha: f32,
    ppr_vad_alpha: f32,
    weighting: SeedWeighting,
    visibility: &dyn PprNodeVisibility,
) -> Result<PprQueryResult> {
    validate_ppr_vad_alpha(ppr_vad_alpha)?;
    validate_ppr_request(seeds, depth)?;

    let mut readable_seeds = Vec::with_capacity(seeds.len());
    for seed in seeds {
        if visibility.ppr_node_visible(txn, seed)? {
            readable_seeds.push(*seed);
        }
    }
    if readable_seeds.is_empty() {
        return Ok(PprQueryResult {
            scores: Vec::new(),
            cache: PprCacheOutcome::Disabled,
            deferred_cache_write: None,
        });
    }

    let state = ppr_compute_state_weighted(
        store,
        txn,
        &readable_seeds,
        weighting,
        depth,
        PprAlphas {
            teleport_alpha,
            ppr_vad_alpha,
        },
        Some(visibility),
    )?;
    Ok(PprQueryResult {
        scores: state.scores,
        cache: PprCacheOutcome::Disabled,
        deferred_cache_write: None,
    })
}
#[derive(Clone, Copy)]
pub(super) struct PprCachePolicy {
    pub(super) defer_writes: bool,
    pub(super) community_identity: Option<[u8; 12]>,
}
/// Cache key: `xxh3_128(sorted seeds ‖ depth ‖ teleport_alpha ‖ ppr_vad_alpha ‖ PPR_FORMULA_VERSION ‖
/// seed-weighting byte)`. The weighting byte keeps `search_ppr`
/// (specificity-seeded) and `expand_ppr` (uniform-seeded) rows from ever
/// serving each other (ARCH-0039 Layer 2 is `search_ppr`-only).
pub(super) fn hash_seeds(
    seeds: &[EntityId],
    depth: u32,
    teleport_alpha: f32,
    ppr_vad_alpha: f32,
    weighting: SeedWeighting,
) -> [u8; SEED_HASH_LEN] {
    let mut sorted = seeds.to_vec();
    sorted.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

    let mut bytes = Vec::with_capacity(
        sorted.len() * ENTITY_ID_LEN
            + 2 * std::mem::size_of::<u32>()
            + 2 * std::mem::size_of::<f32>()
            + 1,
    );
    for seed in &sorted {
        bytes.extend_from_slice(seed.as_bytes());
    }
    bytes.extend_from_slice(&depth.to_le_bytes());
    bytes.extend_from_slice(&teleport_alpha.to_le_bytes());
    bytes.extend_from_slice(&canonical_vad_alpha(ppr_vad_alpha).to_le_bytes());
    bytes.extend_from_slice(&PPR_FORMULA_VERSION.to_le_bytes());
    bytes.push(weighting.cache_key_byte());

    xxh3_128(&bytes).to_le_bytes()
}
