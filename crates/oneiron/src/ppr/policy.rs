//! PPR alphas, seed weighting, specificity counts, and recency policy.

use heed::RoTxn;

#[cfg(test)]
use crate::config::PPR_VAD_ALPHA_DEFAULT;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::scan_check::{EngineScan, ScanCount};
use crate::store::ManifestDbs;
pub(crate) use oneiron_base::edge::kind_tables::lambda_for_kind;
use oneiron_contracts::affect::Vad;

use super::walk::PprNodeVisibility;

#[derive(Clone, Copy)]
pub(super) struct PprAlphas {
    pub(super) teleport_alpha: f32,
    pub(super) ppr_vad_alpha: f32,
}
#[cfg(test)]
impl PprAlphas {
    pub(super) fn default_vad(teleport_alpha: f32) -> Self {
        Self {
            teleport_alpha,
            ppr_vad_alpha: PPR_VAD_ALPHA_DEFAULT,
        }
    }
}
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
    pub(super) const fn cache_key_byte(self) -> u8 {
        match self {
            Self::Uniform => 0,
            Self::Specificity => 1,
        }
    }
}
#[inline]
pub(super) fn vad_salience(vad: Vad) -> f32 {
    vad.valence.abs().max(vad.arousal)
}
#[inline]
pub(super) fn vad_multiplier(vad: Option<Vad>, alpha: f32) -> f32 {
    if alpha == 0.0 {
        1.0
    } else {
        vad.map_or(1.0, |vad| 1.0 + alpha * vad_salience(vad))
    }
}
/// Signed zero has one identity, just as it has one production computation.
pub(crate) fn canonical_vad_alpha(alpha: f32) -> f32 {
    if alpha == 0.0 { 0.0 } else { alpha }
}
pub(super) fn seed_weights_with_deadline(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    seeds: &[EntityId],
    weighting: SeedWeighting,
    visibility: Option<&dyn PprNodeVisibility>,
    deadline: Option<&crate::retrieval_depth::RetrievalDeadline>,
) -> Result<Vec<f32>> {
    match weighting {
        SeedWeighting::Uniform => Ok(vec![1.0 / seeds.len() as f32; seeds.len()]),
        SeedWeighting::Specificity => {
            specificity_seed_weights_with_deadline(store, txn, seeds, visibility, deadline)
        }
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
/// `(0, 1/ln(2)]` and the admitted seed vector is finite, so the normalizer
/// is finite and strictly positive — the division below cannot
/// produce NaN or infinity.
fn specificity_seed_weights_with_deadline(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    seeds: &[EntityId],
    visibility: Option<&dyn PprNodeVisibility>,
    deadline: Option<&crate::retrieval_depth::RetrievalDeadline>,
) -> Result<Vec<f32>> {
    // A seed named twice keeps its mass twice; its mentions are read once.
    let mut counted = std::collections::BTreeMap::new();
    let mut raw = Vec::with_capacity(seeds.len());
    for seed in seeds {
        if let Some(deadline) = deadline {
            deadline.checkpoint()?;
        }
        let passage_count = match counted.get(seed) {
            Some(count) => *count,
            None => {
                let count = inbound_mentions_count(store, txn, seed, visibility, deadline)?;
                counted.insert(*seed, count);
                count
            }
        };
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
/// persisted counter exists in the DB manifest). Scoped reads count only
/// actor-visible sources. Corrupt rows and visibility errors fail closed.
/// Every mention is read, hidden ones too: past the seed's threshold row the
/// scan raises one owner-local check and reads on.
fn inbound_mentions_count(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    seed: &EntityId,
    visibility: Option<&dyn PprNodeVisibility>,
    deadline: Option<&crate::retrieval_depth::RetrievalDeadline>,
) -> Result<u64> {
    let mut rows = ScanCount::start(store, txn, EngineScan::MentionRows, seed.as_bytes())?;
    let mut count = 0_u64;
    for entry in crate::ports::EdgeStoreRead::port_edges(
        store,
        txn,
        seed,
        crate::ports::EdgeDirection::In,
        Some(EdgeKind::Mentions),
        None,
    )? {
        if let Some(deadline) = deadline {
            deadline.checkpoint()?;
        }
        let source = entry?.target;
        rows.row();
        if let Some(visibility) = visibility
            && !visibility.ppr_node_visible(txn, &source)?
        {
            continue;
        }
        count = count
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("ppr passage count"))?;
    }
    rows.defer(store);
    Ok(count)
}
