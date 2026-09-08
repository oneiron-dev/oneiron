//! Vault/Store bridge: expand, seed evidence and refresh entry.

use std::collections::{BTreeSet, HashMap};

use crate::entity_id::EntityId;
use crate::pipeline::ScoredEntity;

use super::scoring::validate_scores;
use super::types::{
    CommunityBoostContext, CommunityBoostReport, CommunityMembership, CommunityRefreshReport,
    PprCommunityConfig, Result,
};

/// Executes the canonical-vault Uniform round path with ordered seed evidence.
/// This returns PPR scores, not the pipeline's final fused ranking. It does not
/// replace an actor-scoped read or an off-record session query. Beta zero calls
/// the original PPR path directly, including its existing cache identity.
pub fn expand_ppr(
    vault: &crate::Vault,
    depth: u32,
    context: &CommunityBoostContext<'_>,
) -> crate::error::Result<(Vec<ScoredEntity>, CommunityBoostReport)> {
    let mut seeds: Vec<_> = context.ordered_seeds.iter().map(|seed| seed.id).collect();
    seeds.sort_unstable();
    let (scores, write, report) = {
        let txn = vault.store.env.read_txn()?;
        crate::ppr::ppr_query_in_txn_with_community_deferred_cache(
            &vault.store,
            &txn,
            crate::ppr::CommunityPprRequest {
                seeds: &seeds,
                depth,
                teleport_alpha: 0.15,
                weighting: crate::ppr::SeedWeighting::Uniform,
                config: &vault.config,
                context,
            },
        )?
    };
    if let Some(write) = write {
        crate::ppr::flush_deferred_ppr_cache_writes(&vault.store, &[write])?;
    }
    Ok((scores, report))
}

/// Preserves fused evidence before the base PPR path sorts seed IDs. An explicit
/// seed absent from the fused list has zero evidence, not a fabricated advantage.
pub fn ordered_seed_evidence(
    seeds: &[EntityId],
    fused: &[ScoredEntity],
) -> Result<Vec<ScoredEntity>> {
    validate_scores(fused)?;
    let evidence: HashMap<_, _> = fused.iter().map(|seed| (seed.id, seed.score)).collect();
    let mut ordered: Vec<_> = seeds
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|id| ScoredEntity {
            id,
            score: *evidence.get(&id).unwrap_or(&0.0),
        })
        .collect();
    ordered.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
    Ok(ordered)
}

/// Refreshes the canonical vault cache atomically. `changed` must contain every
/// changed edge endpoint since the previous snapshot, including deleted IDs.
/// An empty frontier at a newer graph version means unknown churn and forces a
/// full recomputation. This cache must never be used for an actor-scoped walk.
pub fn refresh_communities(
    store: &crate::store::Store,
    changed: &[EntityId],
    now: u64,
    config: &PprCommunityConfig,
) -> crate::error::Result<CommunityRefreshReport> {
    store.refresh_ppr_communities(changed, now, config)
}

impl crate::Vault {
    /// Refreshes the local, canonical-vault community cache. This does not enable
    /// boosting; production beta stays zero unless the caller explicitly opts in.
    pub fn refresh_ppr_communities(
        &self,
        changed: &[EntityId],
        now: u64,
    ) -> crate::error::Result<CommunityRefreshReport> {
        refresh_communities(&self.store, changed, now, &self.config.ppr_community)
    }

    /// Reads current canonical-vault membership. Stale snapshots return `None`.
    /// This is not an actor-scoped or session-composed disclosure API.
    pub fn ppr_community_membership(
        &self,
        entity: &EntityId,
    ) -> crate::error::Result<Option<CommunityMembership>> {
        let txn = self.store.env.read_txn()?;
        self.store.ppr_community_membership_in_txn(&txn, entity)
    }
}
