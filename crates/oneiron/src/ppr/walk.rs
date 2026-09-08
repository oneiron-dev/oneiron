//! PPR walk math: frontier rounds, visibility gating, and edge gates.

use std::collections::{HashMap, HashSet};

use heed::RoTxn;

use crate::affect::Vad;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::config::validate_ppr_vad_alpha;
use crate::edge::{EdgeConfirmationStatus, EdgeKind, parse_strict_edge_record};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::pipeline::ScoredEntity;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::ManifestDbs;

use super::VAD_PROPAGATION_EVIDENCE;
use super::policy::{PprAlphas, SeedWeighting, lambda_for_kind, seed_weights, vad_multiplier};

/// Per-node read visibility for an ACTOR-SCOPED walk (ONE-1608 / ARCH-0050
/// R6 L2).
///
/// The walk consults this before a node may hold or carry mass, so policy
/// decides STRUCTURE rather than being applied to a ranking that already
/// crossed hidden nodes. Filtering results afterwards cannot undo that: mass
/// which already flowed through a denied bridge has changed which permitted
/// items rank where, and at [`MAX_PPR_DEPTH`] hops a caller can read the
/// hidden graph off the scores of the nodes it IS allowed to see.
///
/// Implementations answer for one actor and must be pure with respect to the
/// caller's transaction: the walk hands them the SAME `RoTxn` it is reading
/// from, and an error is propagated (fail closed), never treated as "visible".
pub(crate) trait PprNodeVisibility {
    fn ppr_node_visible(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool>;
}
struct PprRoundContext<'a, 'txn, D: ManifestDbs> {
    store: &'a D,
    txn: &'a RoTxn<'txn>,
    seeds: &'a [EntityId],
    seed_weights: &'a [f32],
    teleport_alpha: f32,
    ppr_vad_alpha: f32,
    /// `None` for the ordinary vault-wide walk — the cached, unscoped ranking
    /// every landed caller shares. `Some` only on the compute-only scoped
    /// entry, which never reads or writes the shared cache.
    visibility: Option<&'a dyn PprNodeVisibility>,
}
#[derive(Debug, Clone)]
pub(super) struct PprFrontierEntry {
    pub(super) id: EntityId,
    pub(super) structural_hops: u32,
    pub(super) score: f32,
}
#[derive(Debug, Clone)]
pub(super) struct PprCacheState {
    pub(super) completed_depth: u32,
    pub(super) scores: Vec<ScoredEntity>,
    pub(super) frontier: Vec<PprFrontierEntry>,
    pub(super) dependencies: Vec<EntityId>,
}
pub(super) enum CachedPprRow {
    Scores(Vec<ScoredEntity>),
    State(PprCacheState),
}
impl CachedPprRow {
    pub(super) fn into_scores(self) -> Vec<ScoredEntity> {
        match self {
            Self::Scores(scores) => scores,
            Self::State(state) => state.scores,
        }
    }

    pub(super) fn into_state(self) -> Option<PprCacheState> {
        match self {
            Self::Scores(_) => None,
            Self::State(state) => Some(state),
        }
    }
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
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    seeds: &[EntityId],
    weighting: SeedWeighting,
    depth: u32,
    teleport_alpha: f32,
) -> Result<Vec<ScoredEntity>> {
    Ok(ppr_compute_state_weighted(
        store,
        txn,
        seeds,
        weighting,
        depth,
        PprAlphas::default_vad(teleport_alpha),
        None,
    )?
    .scores)
}
pub(super) fn ppr_compute_state_weighted(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    seeds: &[EntityId],
    weighting: SeedWeighting,
    depth: u32,
    alphas: PprAlphas,
    visibility: Option<&dyn PprNodeVisibility>,
) -> Result<PprCacheState> {
    validate_ppr_vad_alpha(alphas.ppr_vad_alpha)?;

    if seeds.is_empty() {
        return Ok(PprCacheState {
            completed_depth: 0,
            scores: Vec::new(),
            frontier: Vec::new(),
            dependencies: Vec::new(),
        });
    }

    let seed_weights = seed_weights(store, txn, seeds, weighting, visibility)?;
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
        teleport_alpha: alphas.teleport_alpha,
        ppr_vad_alpha: alphas.ppr_vad_alpha,
        visibility,
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
pub(super) fn ppr_resume_state_weighted(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    seeds: &[EntityId],
    weighting: SeedWeighting,
    target_depth: u32,
    alphas: PprAlphas,
    resume: PprCacheState,
) -> Result<PprCacheState> {
    let seed_weights = seed_weights(store, txn, seeds, weighting, None)?;
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
        teleport_alpha: alphas.teleport_alpha,
        ppr_vad_alpha: alphas.ppr_vad_alpha,
        // Resume replays a SHARED cached state, which only the unscoped walk
        // ever writes; the scoped entry never reads or resumes that cache.
        visibility: None,
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
pub(super) const SCORE_EPSILON: f32 = 1e-10;
fn run_ppr_rounds(
    context: PprRoundContext<'_, '_, impl ManifestDbs>,
    rounds: u32,
    scores: &mut HashMap<EntityId, f32>,
    frontier: &mut HashMap<(EntityId, u32), f32>,
    dependencies: &mut HashSet<EntityId>,
) -> Result<()> {
    let edge_dbs = [context.store.edges_out(), context.store.edges_in()];
    let vad_evidence = VAD_PROPAGATION_EVIDENCE.with(|active| active.borrow().clone());

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
                    if let Some(edge) = gate_edge(context.store, context.txn, &key, &value, hops)? {
                        // Gate 6 — actor visibility, on scoped walks only.
                        // Applied HERE, with the other gates and before the
                        // same-kind strength normalizer sums the group, so a
                        // denied node's edge cannot even reweight this node's
                        // permitted hops — the "strictly stronger than
                        // λ = 0.0" placement `same_as` already gets. The walk
                        // starts from visible seeds and only ever adds visible
                        // nodes, so gating the neighbour keeps BOTH endpoints
                        // of every traversed edge readable.
                        if visible_neighbor(&context, &edge)? {
                            groups.entry(edge.kind).or_default().push(edge);
                        }
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
                        // Normalize within kind before applying ONE-215 VAD
                        // salience. Zero VAD alpha returns the literal 1.0.
                        let share = edge.lambda * edge.weight / strength;
                        let propagated = score
                            * share
                            * vad_multiplier(edge.vad, context.ppr_vad_alpha)
                            * (1.0 - context.teleport_alpha);
                        if let Some(evidence) = &vad_evidence {
                            let neutral = score * share * (1.0 - context.teleport_alpha);
                            // Observe an actual f32 mass change, not merely a
                            // nonzero VAD on an edge below SCORE_EPSILON or a
                            // multiplier that rounds to 1.0 / underflows away.
                            if propagated > neutral {
                                evidence.set(true);
                            }
                        }
                        *next.entry((edge.neighbor, edge.new_hops)).or_default() += propagated;
                    }
                }
            }
        }

        let teleport_mass = total * context.teleport_alpha;
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
/// Whether a gated edge's far endpoint may carry mass for this walk.
///
/// Always `true` for the unscoped walk, so the landed ranking is byte-identical
/// to what it was before the scoped entry existed. A visibility error is
/// returned as-is: the walk fails closed rather than treating an undecidable
/// node as readable.
fn visible_neighbor(
    context: &PprRoundContext<'_, '_, impl ManifestDbs>,
    edge: &GatedEdge,
) -> Result<bool> {
    match context.visibility {
        Some(visibility) => visibility.ppr_node_visible(context.txn, &edge.neighbor),
        None => Ok(true),
    }
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
/// `ppr_query_in_txn_with_vad_deferred_cache`, which carries the mode.
#[cfg(test)]
pub(crate) fn ppr_compute(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    seeds: &[EntityId],
    depth: u32,
    teleport_alpha: f32,
) -> Result<Vec<ScoredEntity>> {
    ppr_compute_weighted(
        store,
        txn,
        seeds,
        SeedWeighting::Uniform,
        depth,
        teleport_alpha,
    )
}
/// An edge row that passed every traversal gate, ready for Layer-1
/// propagation once its same-kind strength normalizer is known.
pub(super) struct GatedEdge {
    pub(super) kind: EdgeKind,
    pub(super) lambda: f32,
    pub(super) weight: f32,
    pub(super) vad: Option<Vad>,
    pub(super) neighbor: EntityId,
    pub(super) new_hops: u32,
}
/// Decodes one raw edge row fail-closed, then applies the traversal gates.
///
/// Returns `Ok(None)` when the edge is valid but must not propagate; corrupt
/// rows are always a typed error (gates never mask corruption — the row is
/// decoded before any gate runs).
pub(super) fn gate_edge(
    store: &impl ManifestDbs,
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
        vad: decoded.vad,
        neighbor,
        new_hops,
    }))
}
fn entity_is_lexical_query_hint_claim(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let Some(raw) = store.entities().get(txn, id.as_bytes())? else {
        return Ok(false);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("entity header"));
    };
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(false);
    }
    let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    Ok(body.predicate == crate::claim::PREDICATE_LEXICAL_QUERY_HINT)
}
pub(super) fn sort_scores(scores: &mut [ScoredEntity]) {
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
