//! Community-boost bridge adapter over ppr_community.

use std::collections::HashSet;

use heed::RoTxn;
use xxhash_rust::xxh3::xxh3_128;

use crate::config::validate_ppr_vad_alpha;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::pipeline::ScoredEntity;
use crate::retrieval_quality::PprCacheOutcome;
use crate::store::Store;

use super::VAD_PROPAGATION_EVIDENCE;
use super::cache_store::{SEED_HASH_LEN, read_graph_version};
use super::policy::{PprAlphas, SeedWeighting};
use super::query::{
    DeferredPprCacheWrite, PprCachePolicy, PprQueryResult, hash_seeds,
    ppr_query_in_txn_with_diagnostics, ppr_query_in_txn_with_identity, validate_ppr_request,
};

/// Inputs captured by the Uniform expansion caller before seed IDs are sorted
/// for the base PPR cache. Session usage is caller-owned and never persisted.
pub(crate) struct CommunityPprRequest<'a> {
    pub seeds: &'a [EntityId],
    pub depth: u32,
    pub teleport_alpha: f32,
    pub weighting: SeedWeighting,
    pub config: &'a crate::config::VaultConfig,
    pub context: &'a crate::ppr_community::CommunityBoostContext<'a>,
}
/// Applies the prior once, to the completed round scores, never to a frontier
/// that will later resume. Shared cache rows always retain the unboosted state.
/// This entry accepts a canonical Store, not a session-composed ManifestDbs or
/// an actor visibility predicate. Scoped PPR keeps its compute-only path.
pub(crate) fn ppr_query_in_txn_with_community_deferred_cache(
    store: &Store,
    txn: &RoTxn<'_>,
    request: CommunityPprRequest<'_>,
) -> Result<(
    Vec<ScoredEntity>,
    Option<DeferredPprCacheWrite>,
    crate::ppr_community::CommunityBoostReport,
)> {
    let output = ppr_community_query_in_txn(store, txn, request, false)?;
    Ok((output.scores, output.write, output.report))
}
/// The same read snapshot and actual boosted IDs survive until final selection.
/// Membership is metadata only: this state can never introduce a candidate.
pub(crate) struct CommunityPprDiversity {
    view: crate::ppr_community::CommunityQueryView,
    boosted: std::collections::BTreeSet<EntityId>,
}
impl CommunityPprDiversity {
    pub(crate) fn apply(
        &self,
        scores: &mut Vec<ScoredEntity>,
        limit: usize,
        config: &crate::config::PprCommunityConfig,
    ) -> Result<()> {
        let cache = self.view.cache();
        crate::ppr_community::apply_community_diversity(
            scores,
            &cache,
            &self.boosted,
            limit,
            config,
        )
        .map_err(|error| Error::InvalidConfig(error.to_string()))?;
        Ok(())
    }
}
/// Uniform-only score adapter: keep the complete PPR channel for fusion.
#[cfg(test)]
pub(crate) fn ppr_expand_in_txn_with_community_deferred_cache(
    store: &Store,
    txn: &RoTxn<'_>,
    request: CommunityPprRequest<'_>,
) -> Result<(
    Vec<ScoredEntity>,
    Option<DeferredPprCacheWrite>,
    Option<CommunityPprDiversity>,
)> {
    let (result, diversity) = ppr_expand_in_txn_with_community_diagnostics(store, txn, request)?;
    Ok((result.scores, result.deferred_cache_write, diversity))
}
pub(crate) fn ppr_expand_in_txn_with_community_diagnostics(
    store: &Store,
    txn: &RoTxn<'_>,
    mut request: CommunityPprRequest<'_>,
) -> Result<(PprQueryResult, Option<CommunityPprDiversity>)> {
    request.weighting = SeedWeighting::Uniform;
    let output = ppr_community_query_in_txn(store, txn, request, true)?;
    Ok((
        PprQueryResult {
            scores: output.scores,
            cache: output.cache,
            deferred_cache_write: output.write,
        },
        output.diversity,
    ))
}
struct CommunityPprOutput {
    cache: PprCacheOutcome,
    scores: Vec<ScoredEntity>,
    write: Option<DeferredPprCacheWrite>,
    report: crate::ppr_community::CommunityBoostReport,
    diversity: Option<CommunityPprDiversity>,
}
fn ppr_community_query_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    request: CommunityPprRequest<'_>,
    defer_diversity: bool,
) -> Result<CommunityPprOutput> {
    use crate::ppr_community::{
        CommunityBoostReport, CommunityQueryView, apply_community_prior, boost_community_scores,
        community_cache_identity,
    };
    let config = &request.config.ppr_community;
    if request.weighting != SeedWeighting::Uniform || config.beta == 0.0 {
        let result = ppr_query_in_txn_with_diagnostics(
            store,
            txn,
            request.seeds,
            request.depth,
            request.teleport_alpha,
            request.config.ppr_vad_alpha,
            request.weighting,
        )?;
        return Ok(CommunityPprOutput {
            cache: result.cache,
            scores: result.scores,
            write: result.deferred_cache_write,
            report: CommunityBoostReport::default(),
            diversity: None,
        });
    }
    crate::config::validate_ppr_community(config)?;
    validate_ppr_request(request.seeds, request.depth)?;
    validate_ppr_vad_alpha(request.config.ppr_vad_alpha)?;
    let evidence_ids: HashSet<_> = request
        .context
        .ordered_seeds
        .iter()
        .map(|seed| seed.id)
        .collect();
    if evidence_ids.len() != request.context.ordered_seeds.len()
        || evidence_ids != request.seeds.iter().copied().collect::<HashSet<EntityId>>()
        || request
            .context
            .ordered_seeds
            .iter()
            .any(|seed| !seed.score.is_finite() || seed.score < 0.0)
        || request
            .context
            .ordered_seeds
            .windows(2)
            .any(|pair| pair[0].score < pair[1].score)
    {
        return Err(Error::InvalidConfig(
            "community seed evidence must match the PPR seed set".to_owned(),
        ));
    }
    let version = read_graph_version(store, txn)?;
    let metadata = store.ppr_community_meta_in_txn(txn)?;
    let needs_refresh = metadata.is_none_or(|(meta, _)| meta.graph_version != version);
    let snapshot = if needs_refresh {
        // Only missing/stale snapshots take the whole-family validation and
        // full graph projection path. Unknown churn cannot use seed frontiers.
        let previous = store.ppr_community_snapshot_in_txn(txn)?;
        Some(
            store
                .compute_ppr_communities_in_txn(
                    txn,
                    previous.as_ref(),
                    &[],
                    crate::unix_seconds_now(),
                    config,
                )?
                .0,
        )
    } else {
        None
    };
    let identity = community_cache_identity(config.beta, version)
        .map_err(|error| Error::InvalidConfig(error.to_string()))?;
    let result = ppr_query_in_txn_with_identity(
        store,
        txn,
        request.seeds,
        request.depth,
        PprAlphas {
            teleport_alpha: request.teleport_alpha,
            ppr_vad_alpha: request.config.ppr_vad_alpha,
        },
        request.weighting,
        PprCachePolicy {
            defer_writes: true,
            community_identity: identity,
        },
    )?;
    let cache_outcome = result.cache;
    let mut scores = result.scores;
    let mut write = result.deferred_cache_write;
    let selected = request
        .context
        .ordered_seeds
        .iter()
        .chain(&scores)
        .map(|row| row.id)
        .collect();
    let view = if let Some(snapshot) = &snapshot {
        CommunityQueryView::from_snapshot(snapshot, &selected)
            .map_err(|_| Error::CorruptedIndex("ppr community cache"))?
    } else {
        store.ppr_community_query_view_in_txn(txn, &selected)?
    };
    let cache = view.cache();
    let (report, boosted) = if defer_diversity {
        boost_community_scores(&mut scores, &cache, request.context, config)
    } else {
        apply_community_prior(&mut scores, &cache, request.context, config)
            .map(|report| (report, std::collections::BTreeSet::new()))
    }
    .map_err(|error| Error::InvalidConfig(error.to_string()))?;
    // Keep the refreshed snapshot for boosting and diversity, but do not
    // reintroduce a cache write after the diagnostic's compute-only PPR path.
    if needs_refresh && !VAD_PROPAGATION_EVIDENCE.with(|active| active.borrow().is_some()) {
        let pending = write.get_or_insert_with(|| DeferredPprCacheWrite {
            seed_hash: hash_community_seeds(
                hash_seeds(
                    request.seeds,
                    request.depth,
                    request.teleport_alpha,
                    request.config.ppr_vad_alpha,
                    request.weighting,
                ),
                identity,
            ),
            computed_at: crate::unix_seconds_now(),
            graph_version: version,
            state: None,
            community_snapshot: None,
        });
        pending.community_snapshot = snapshot;
    }
    let diversity = (defer_diversity && report.activated_communities > 0)
        .then_some(CommunityPprDiversity { view, boosted });
    Ok(CommunityPprOutput {
        cache: cache_outcome,
        scores,
        write,
        report,
        diversity,
    })
}
/// Only base round state is cached. The community namespace separates beta and
/// snapshot version, while ordered scores, limits, session usage and all safety
/// knobs are applied after every cache read and are never stored as boosted rows.
pub(super) fn hash_community_seeds(
    baseline: [u8; SEED_HASH_LEN],
    identity: Option<[u8; 12]>,
) -> [u8; SEED_HASH_LEN] {
    let Some(identity) = identity else {
        return baseline;
    };
    let mut bytes = b"oneiron:ppr:community:v0\0".to_vec();
    bytes.extend_from_slice(&baseline);
    bytes.extend_from_slice(&identity);
    xxh3_128(&bytes).to_le_bytes()
}
