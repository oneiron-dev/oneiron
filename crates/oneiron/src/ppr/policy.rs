//! PPR alphas, seed weighting, specificity counts, and recency policy.

use heed::RoTxn;

use crate::affect::Vad;
#[cfg(test)]
use crate::config::PPR_VAD_ALPHA_DEFAULT;
use crate::edge::{EdgeKind, parse_strict_edge_record_key};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::ManifestDbs;

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
/// Per-kind λ_τ traversal budget (ARCH-0039 Layer 1). The values are the
/// LITERAL `edgeKinds.lambda` column of the pinned contract module
/// (`oneiron-docs` `site/src/data/oneiron-contracts.ts`):
///
/// - `None` — the kind is NEVER traversed by PPR (`child_of`, `assigned_to`,
///   `blocked_by`; contract `lambda: null`, "Not traversed."). Tree queries go
///   through the dedicated `subtree` / `ancestors` read APIs instead, and
///   TASK readiness is computed at read time over `blocked_by`.
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
        EdgeKind::BlockedBy => None,
        // ONE-1608 (ARCH-0050 R6 L2): the code-memory readiness edge is
        // NEVER an ordinary PPR edge. `None` is the traversal exclusion —
        // strictly stronger than λ = 0.0 — so a note attached to a blocked
        // symbol can never inherit relevance through a readiness dependency.
        EdgeKind::Blocks => None,
        // CMT-4 (ONE-1541): a brief discharging an obligation says nothing
        // about retrieval relevance, so neither ruled direction is traversed.
        EdgeKind::Fulfills | EdgeKind::DischargedBy => None,
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
        // ARCH-0055 redirect edges: traversed like `supersedes` (λ 0.3) so
        // shell mass reaches the canonical head.
        EdgeKind::MergedInto => Some(0.3),
        EdgeKind::SplitInto => Some(0.3),
        // ONE-1414 cross-vault coreference: `None` IS the no-pooling
        // contract. A `same_as` link asserts that two PERSON entities are one
        // person; it does NOT merge their claim sets, so no PPR mass may
        // cross it in either direction. Gate 1 below drops the hop outright,
        // which is strictly stronger than λ = 0.0 (`opposes`): the edge also
        // contributes nothing to the `s_out`/`s_in` normalizers, so its mere
        // presence cannot even reweight a node's other hops. A traversable
        // λ here — however small — would be exactly the claim pooling this
        // ticket exists to prevent.
        EdgeKind::SameAs => None,
    }
}
/// Signed zero has one identity, just as it has one production computation.
pub(crate) fn canonical_vad_alpha(alpha: f32) -> f32 {
    if alpha == 0.0 { 0.0 } else { alpha }
}
/// Resolves the normalized per-seed mass vector for `weighting`. Always sums
/// to 1.0 (up to f32 rounding) and every entry is strictly positive.
pub(super) fn seed_weights(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    seeds: &[EntityId],
    weighting: SeedWeighting,
    visibility: Option<&dyn PprNodeVisibility>,
) -> Result<Vec<f32>> {
    match weighting {
        SeedWeighting::Uniform => Ok(vec![1.0 / seeds.len() as f32; seeds.len()]),
        SeedWeighting::Specificity => specificity_seed_weights(store, txn, seeds, visibility),
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
pub(super) fn specificity_seed_weights(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    seeds: &[EntityId],
    visibility: Option<&dyn PprNodeVisibility>,
) -> Result<Vec<f32>> {
    let mut raw = Vec::with_capacity(seeds.len());
    for seed in seeds {
        let passage_count = inbound_mentions_count(store, txn, seed, visibility)?;
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
fn inbound_mentions_count(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    seed: &EntityId,
    visibility: Option<&dyn PprNodeVisibility>,
) -> Result<u64> {
    let mut count = 0_u64;
    for entry in store.edges_in().prefix_iter(txn, seed.as_bytes())? {
        let (key, _) = entry?;
        let (_, kind, source) = parse_strict_edge_record_key(&key)?;
        if kind == EdgeKind::Mentions {
            if let Some(visibility) = visibility
                && !visibility.ppr_node_visible(txn, &source)?
            {
                continue;
            }
            count = count
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("ppr passage count"))?;
        }
    }
    Ok(count)
}
