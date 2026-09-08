//! PPR-VAD sweep arm, sampling, and gates.

use super::load::load_fixture_dataset;
use super::model::{ArmKind, BeamFixture, FixtureCase, RunManifest};
use super::report_model::{ArmOutcome, ArmReport, CaseReport, LoadedDataset};
use super::scorer::BeamArmAdapter;
use super::util::{beam_vault_config, invalid_fixture};
use super::{BeamError, BeamResult};
use oneiron::{EntityId, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::time::Instant;

pub(super) const PPR_VAD_RECALL_K: usize = 15;
pub(super) const PPR_VAD_LATENCY_REPETITIONS: usize = 20;
pub(super) const PPR_VAD_MIN_SALIENT_GAIN_PERCENT: f64 = 2.0;
pub(super) const PPR_VAD_MAX_NEUTRAL_REGRESSION_PP: f64 = 0.0;
pub(super) const PPR_VAD_MAX_P95_INCREASE_PERCENT: f64 = 5.0;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PprVadSubset {
    EmotionallySalient,
    Neutral,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct PprVadQuery {
    pub(super) subset: PprVadSubset,
    pub(super) seeds: Vec<String>,
    pub(super) depth: u32,
    /// Judged non-seed results; recall uses the production final top-15 rows.
    pub(super) relevant_ids: Vec<String>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct PprVadFixtureEdge {
    pub(super) source: String,
    pub(super) target: String,
    /// Pinned edge-kind storage discriminant.
    pub(super) kind: u8,
    pub(super) weight: f32,
    /// Omit for structural edges; semantic edges may supply canonical full VAD.
    #[serde(default)]
    pub(super) vad: Option<oneiron::Vad>,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PprVadCaseSample {
    pub(super) alpha: f32,
    pub(super) recall_at_15: f64,
    pub(super) latency_ms: Vec<f64>,
    pub(super) result_ids: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PprVadAlphaReport {
    pub(super) alpha: f32,
    pub(super) salient_recall_at_15: f64,
    pub(super) neutral_recall_at_15: f64,
    pub(super) p95_latency_ms: f64,
    pub(super) salient_gain_percent_vs_zero: Option<f64>,
    pub(super) neutral_delta_pp_vs_zero: f64,
    pub(super) p95_increase_percent_vs_zero: Option<f64>,
    pub(super) gate_passed: bool,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PprVadSweepReport {
    pub(super) baseline_alpha: f32,
    pub(super) production_default_alpha: f32,
    pub(super) min_salient_gain_percent: f64,
    pub(super) max_neutral_regression_pp: f64,
    pub(super) max_p95_increase_percent: f64,
    pub(super) latency_protocol: String,
    pub(super) salient_queries: usize,
    pub(super) neutral_queries: usize,
    pub(super) alphas: Vec<PprVadAlphaReport>,
}
pub(super) fn ppr_vad_gate(
    salient_gain: Option<f64>,
    neutral_delta_pp: f64,
    p95_increase: Option<f64>,
) -> bool {
    salient_gain.is_some_and(|gain| gain.is_finite() && gain >= PPR_VAD_MIN_SALIENT_GAIN_PERCENT)
        && neutral_delta_pp.is_finite()
        && neutral_delta_pp >= -PPR_VAD_MAX_NEUTRAL_REGRESSION_PP
        && p95_increase.is_some_and(|increase| {
            increase.is_finite() && increase <= PPR_VAD_MAX_P95_INCREASE_PERCENT
        })
}
pub(super) fn ppr_vad_percent_change(value: f64, baseline: f64) -> Option<f64> {
    if baseline <= 0.0 || !baseline.is_finite() || !value.is_finite() {
        return None;
    }
    let percent = (value - baseline) / baseline * 100.0;
    percent.is_finite().then_some(percent)
}
pub(super) fn ppr_vad_p95(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);
    values[(values.len() * 95).div_ceil(100) - 1]
}
pub(super) fn ppr_vad_sweep_report(cases: &[CaseReport]) -> Option<PprVadSweepReport> {
    let outcomes: Vec<_> = cases
        .iter()
        .flat_map(|case| &case.arms)
        .filter_map(|arm| {
            if let ArmOutcome::RetrievalSweep { subset, samples } = &arm.outcome {
                Some((*subset, samples))
            } else {
                None
            }
        })
        .collect();
    if outcomes.is_empty() {
        return None;
    }
    let salient_queries = outcomes
        .iter()
        .filter(|(subset, _)| *subset == PprVadSubset::EmotionallySalient)
        .count();
    let neutral_queries = outcomes.len() - salient_queries;
    // Missing subsets never yield a gate claim (manifest validation rejects them).
    if salient_queries == 0 || neutral_queries == 0 {
        return None;
    }
    let mut alphas = Vec::<PprVadAlphaReport>::new();
    for (index, &alpha) in oneiron::config::PPR_VAD_ALPHA_SWEEP.iter().enumerate() {
        let mut salient = 0.0;
        let mut neutral = 0.0;
        let mut latencies = Vec::new();
        for (subset, samples) in &outcomes {
            let sample = &samples[index];
            match subset {
                PprVadSubset::EmotionallySalient => salient += sample.recall_at_15,
                PprVadSubset::Neutral => neutral += sample.recall_at_15,
            }
            latencies.extend_from_slice(&sample.latency_ms);
        }
        let salient = salient / salient_queries as f64;
        let neutral = neutral / neutral_queries as f64;
        let p95 = ppr_vad_p95(&mut latencies);
        let baseline = alphas.first();
        let salient_gain = baseline.map_or(Some(0.0), |base| {
            ppr_vad_percent_change(salient, base.salient_recall_at_15)
        });
        let neutral_delta =
            baseline.map_or(0.0, |base| (neutral - base.neutral_recall_at_15) * 100.0);
        let p95_increase = baseline.map_or(Some(0.0), |base| {
            ppr_vad_percent_change(p95, base.p95_latency_ms)
        });
        alphas.push(PprVadAlphaReport {
            alpha,
            salient_recall_at_15: salient,
            neutral_recall_at_15: neutral,
            p95_latency_ms: p95,
            salient_gain_percent_vs_zero: salient_gain,
            neutral_delta_pp_vs_zero: neutral_delta,
            p95_increase_percent_vs_zero: p95_increase,
            gate_passed: alpha != 0.0 && ppr_vad_gate(salient_gain, neutral_delta, p95_increase),
        });
    }
    Some(PprVadSweepReport {
        baseline_alpha: 0.0,
        production_default_alpha: oneiron::config::PPR_VAD_ALPHA_DEFAULT,
        min_salient_gain_percent: PPR_VAD_MIN_SALIENT_GAIN_PERCENT,
        max_neutral_regression_pp: PPR_VAD_MAX_NEUTRAL_REGRESSION_PP,
        max_p95_increase_percent: PPR_VAD_MAX_P95_INCREASE_PERCENT,
        latency_protocol: concat!(
            "20 fresh-vault, empty-PPR-cache queries per case/alpha; ",
            "production final top-15 rows, without seed filtering or re-ranking; ",
            "nearest-rank p95 times query execution including deferred cache writes; ",
            "corpus and graph setup excluded"
        )
        .to_owned(),
        salient_queries,
        neutral_queries,
        alphas,
    })
}
pub(super) struct PprVadSweepArm;
impl BeamArmAdapter for PprVadSweepArm {
    fn kind(&self) -> ArmKind {
        ArmKind::PprVadSweep
    }

    fn run(
        &self,
        _vault: &Vault,
        loaded: &LoadedDataset,
        case: &FixtureCase,
    ) -> BeamResult<ArmReport> {
        let fixture = loaded
            .ppr_vad_fixture
            .as_ref()
            .ok_or_else(|| BeamError::InvalidFixture {
                fixture_id: loaded.fixture_id.clone(),
                reason: "ppr_vad_sweep requires a stored-VAD fixture".to_owned(),
            })?;
        let query = case.ppr_vad_query.as_ref().ok_or_else(|| {
            invalid_fixture(
                fixture,
                "ppr_vad_sweep requires pprVadQuery labels and seeds",
            )
        })?;
        let seeds = query
            .seeds
            .iter()
            .map(|id| EntityId::from_hex(id))
            .collect::<Result<Vec<_>, _>>()?;
        let relevant = query
            .relevant_ids
            .iter()
            .map(|id| EntityId::from_hex(id))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let mut samples = Vec::new();
        for &alpha in oneiron::config::PPR_VAD_ALPHA_SWEEP {
            let mut latency_ms = Vec::with_capacity(PPR_VAD_LATENCY_REPETITIONS);
            let mut result_ids: Option<Vec<EntityId>> = None;
            for _ in 0..PPR_VAD_LATENCY_REPETITIONS {
                let (rows, elapsed_ms) =
                    ppr_vad_retrieval_sample(fixture, &seeds, query.depth, alpha)?;
                latency_ms.push(elapsed_ms);
                let ids: Vec<_> = rows.iter().map(|row| row.id).collect();
                // One recorded ranking must explain recall for every repetition.
                // Do not hide differing final results behind averaged recall.
                if result_ids.as_ref().is_some_and(|first| first != &ids) {
                    return Err(invalid_fixture(
                        fixture,
                        "sweep final result ids changed between latency repetitions",
                    ));
                }
                result_ids = Some(ids);
            }
            let result_ids = result_ids.unwrap_or_default();
            let hits = result_ids
                .iter()
                .filter(|id| relevant.contains(*id))
                .count();
            samples.push(PprVadCaseSample {
                alpha,
                recall_at_15: hits as f64 / relevant.len() as f64,
                latency_ms,
                result_ids: result_ids.iter().map(EntityId::to_hex).collect(),
            });
        }
        Ok(ArmReport {
            arm: self.kind(),
            outcome: ArmOutcome::RetrievalSweep {
                subset: query.subset,
                samples,
            },
        })
    }
}
/// A fresh vault gives every timed query an empty PPR cache. Measure the
/// production pipeline's final top-15 rows, with no post-filtering or re-ranking.
/// PPR contributes candidate membership, not its raw scores, to the final blend;
/// a VAD-sensitive PPR score need not improve final recall. Timing includes query
/// execution and deferred cache writes, but excludes corpus/graph construction.
/// Warm-cache hits cannot hide VAD cost. No trace channel feeds the empirical gate.
pub(super) fn ppr_vad_retrieval_sample(
    fixture: &BeamFixture,
    seeds: &[EntityId],
    depth: u32,
    alpha: f32,
) -> BeamResult<(Vec<oneiron::ScoredEntity>, f64)> {
    let (_dir, vault) = ppr_vad_fixture_vault(fixture, alpha)?;
    let start = Instant::now();
    let rows = vault
        .query()
        .search_ppr(seeds, depth)
        .limit(PPR_VAD_RECALL_K)
        .run()?;
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    Ok((rows, elapsed_ms))
}
/// Validation and timed retrieval load the same stored graph through the same
/// public write doors. Only query execution belongs in the latency sample.
pub(super) fn ppr_vad_fixture_vault(
    fixture: &BeamFixture,
    alpha: f32,
) -> BeamResult<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir()?;
    let mut config = beam_vault_config();
    config.ppr_vad_alpha = alpha;
    let vault = Vault::open(dir.path(), config)?;
    load_fixture_dataset(&vault, fixture)?;
    for edge in &fixture.ppr_vad_edges {
        let source = EntityId::from_hex(&edge.source)?;
        let target = EntityId::from_hex(&edge.target)?;
        let kind = oneiron::EdgeKind::try_from_u8(edge.kind)
            .ok_or_else(|| invalid_fixture(fixture, "unknown sweep edge kind"))?;
        vault.put_edge(&source, kind, &target, edge.weight)?;
        if let Some(vad) = edge.vad {
            vault.set_edge_vad(&source, kind, &target, vad)?;
        }
    }
    Ok((dir, vault))
}
pub(super) fn validate_ppr_vad_fixture(
    manifest: &RunManifest,
    fixture: &BeamFixture,
) -> BeamResult<()> {
    if !manifest.arms.contains(&ArmKind::PprVadSweep) {
        return Ok(());
    }
    let ids = fixture
        .records
        .iter()
        .map(|record| EntityId::from_hex(&record.id))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mut salient = false;
    let mut neutral = false;
    for case in fixture
        .cases
        .iter()
        .filter(|case| manifest.case_ids.contains(&case.case_id))
    {
        let query = case
            .ppr_vad_query
            .as_ref()
            .ok_or_else(|| invalid_fixture(fixture, "selected sweep cases require pprVadQuery"))?;
        if query.seeds.is_empty()
            || query.seeds.len() > 256
            || query.depth == 0
            || query.depth > 10
            || query.relevant_ids.is_empty()
        {
            return Err(invalid_fixture(
                fixture,
                "sweep needs 1..=256 seeds, depth 1..=10 and nonempty relevance judgments",
            ));
        }
        let seeds = query
            .seeds
            .iter()
            .map(|id| EntityId::from_hex(id))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let relevant = query
            .relevant_ids
            .iter()
            .map(|id| EntityId::from_hex(id))
            .collect::<Result<BTreeSet<_>, _>>()?;
        for (unique, list) in [(&seeds, &query.seeds), (&relevant, &query.relevant_ids)] {
            if unique.len() != list.len() || !unique.is_subset(&ids) {
                return Err(invalid_fixture(
                    fixture,
                    "sweep ids must be unique and present in the corpus",
                ));
            }
        }
        if !seeds.is_disjoint(&relevant) {
            return Err(invalid_fixture(
                fixture,
                "sweep relevance judgments must exclude seeds",
            ));
        }
        match query.subset {
            PprVadSubset::EmotionallySalient => salient = true,
            PprVadSubset::Neutral => neutral = true,
        }
    }
    if !salient || !neutral {
        return Err(invalid_fixture(
            fixture,
            "sweep requires both emotionally_salient and neutral selected subsets",
        ));
    }
    validate_ppr_vad_fixture_edges(fixture, &ids)?;
    // Nonnegative propagation makes the largest sweep coefficient the widest
    // reachable frontier. Observe a real mass change there, not graph-only
    // connectivity. This diagnostic is separate from final-retrieval samples.
    let alpha = oneiron::config::PPR_VAD_ALPHA_SWEEP
        .iter()
        .copied()
        .max_by(f32::total_cmp)
        .ok_or_else(|| invalid_fixture(fixture, "sweep has no coefficients"))?;
    let (_dir, vault) = ppr_vad_fixture_vault(fixture, alpha)?;
    for case in fixture
        .cases
        .iter()
        .filter(|case| manifest.case_ids.contains(&case.case_id))
    {
        let query = case
            .ppr_vad_query
            .as_ref()
            .ok_or_else(|| invalid_fixture(fixture, "selected sweep cases require pprVadQuery"))?;
        if query.subset == PprVadSubset::EmotionallySalient
            && !ppr_vad_reaches_salient_edge(query, &vault)?
        {
            return Err(invalid_fixture(
                fixture,
                format!(
                    "salient sweep case `{}` must reach a positive-weight traversed semantic edge with nonzero VAD within depth",
                    case.case_id
                ),
            ));
        }
    }
    Ok(())
}
pub(super) fn validate_ppr_vad_fixture_edges(
    fixture: &BeamFixture,
    ids: &BTreeSet<EntityId>,
) -> BeamResult<()> {
    if fixture.ppr_vad_edges.is_empty() {
        return Err(invalid_fixture(
            fixture,
            "sweep requires stored-VAD graph edges",
        ));
    }
    let mut edges = BTreeSet::new();
    for edge in &fixture.ppr_vad_edges {
        let source = EntityId::from_hex(&edge.source)?;
        let target = EntityId::from_hex(&edge.target)?;
        if !ids.contains(&source) || !ids.contains(&target) {
            return Err(invalid_fixture(
                fixture,
                "sweep edge endpoints must exist in the corpus",
            ));
        }
        let kind = oneiron::EdgeKind::try_from_u8(edge.kind)
            .ok_or_else(|| invalid_fixture(fixture, "unknown sweep edge kind"))?;
        if edge.vad.is_some() && !ppr_vad_semantic_kind(kind) {
            return Err(invalid_fixture(
                fixture,
                "structural sweep edges cannot carry VAD",
            ));
        }
        if !edges.insert((source, edge.kind, target))
            || !(0.0..=1.0).contains(&edge.weight)
            || edge
                .vad
                .is_some_and(|vad| !vad.is_finite() || !vad.is_in_range())
        {
            return Err(invalid_fixture(
                fixture,
                "sweep edges must be unique with valid kind, weight and VAD",
            ));
        }
    }
    Ok(())
}
pub(super) fn ppr_vad_semantic_kind(kind: oneiron::EdgeKind) -> bool {
    use oneiron::EdgeKind::*;
    matches!(
        kind,
        Mentions
            | About
            | Supports
            | Opposes
            | ParticipatesIn
            | Attached
            | EmployedBy
            | HasFacet
            | FacetOf
            | InWorld
            | SetIn
    )
}
/// Use the production search pipeline, bypassing PPR caches only for this
/// diagnostic. Its own frontier cutoff, per-direction strength normalization,
/// seed specificity, teleport mass and PartOf cap decide effective reachability.
/// The returned final rows are not substituted for the timed recall samples.
pub(super) fn ppr_vad_reaches_salient_edge(query: &PprVadQuery, vault: &Vault) -> BeamResult<bool> {
    let seeds = query
        .seeds
        .iter()
        .map(|id| EntityId::from_hex(id))
        .collect::<Result<Vec<_>, _>>()?;
    let (_, effective) = vault
        .query()
        .search_ppr(&seeds, query.depth)
        .limit(PPR_VAD_RECALL_K)
        .run_with_ppr_vad_evidence()?;
    Ok(effective)
}
