//! Community-beam run, timing loop, and aggregate gating.

use super::load::load_fixture_dataset;
use super::model::{BeamFixture, FixtureRecord};
use super::ppr_vad::{PprVadFixtureEdge, ppr_vad_p95, ppr_vad_percent_change};
use super::util::{beam_vault_config, hex_lower};
use super::{BeamError, BeamResult, SCHEMA_VERSION};
use oneiron::{EntityId, Vault};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::Path;
use std::time::Instant;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CommunityBeamFixture {
    pub(super) dataset_id: String,
    pub(super) held_out: bool,
    pub(super) records: Vec<FixtureRecord>,
    pub(super) edges: Vec<PprVadFixtureEdge>,
    pub(super) cases: Vec<CommunityBeamCase>,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CommunityBeamCase {
    pub(super) case_id: String,
    pub(super) subset: CommunityBeamSubset,
    pub(super) text_query: String,
    pub(super) channel_limit: usize,
    pub(super) ordered_seeds: Vec<CommunityBeamSeed>,
    pub(super) depth: u32,
    pub(super) relevant_ids: Vec<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CommunityBeamSubset {
    Preference,
    LifeArea,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CommunityBeamSeed {
    pub(super) id: String,
    pub(super) score: f32,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CommunityBeamSample {
    pub(super) case_id: String,
    pub(super) subset: CommunityBeamSubset,
    pub(super) beta: f32,
    pub(super) recall_at_10: f64,
    pub(super) fine_entropy_bits: f64,
    pub(super) coarse_entropy_bits: f64,
    pub(super) max_fine_fraction: f64,
    pub(super) p95_latency_ms: f64,
    pub(super) recall_gain_percent_vs_zero: Option<f64>,
    pub(super) p95_increase_percent_vs_zero: Option<f64>,
    pub(super) latency_ms: Vec<f64>,
    pub(super) refresh_latency_ms: Vec<f64>,
    pub(super) result_ids: Vec<String>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CommunityBeamReport {
    pub(super) dataset_id: String,
    pub(super) fixture_sha256: String,
    pub(super) declared_held_out: bool,
    pub(super) measurement_scope: &'static str,
    pub(super) latency_protocol: &'static str,
    pub(super) production_default_beta: f32,
    pub(super) recall_gain_percent_vs_zero: Option<f64>,
    pub(super) p95_increase_percent_vs_zero: Option<f64>,
    // Measured gate on this declared held-out fixture, not default-on approval.
    pub(super) final_pipeline_acceptance: Option<bool>,
    pub(super) remaining_gate: &'static str,
    pub(super) samples: Vec<CommunityBeamSample>,
}
pub(super) fn run_community_beam(path: &Path) -> BeamResult<CommunityBeamReport> {
    let bytes = std::fs::read(path)?;
    let fixture: CommunityBeamFixture = serde_json::from_slice(&bytes)?;
    let invalid = |reason: &str| BeamError::InvalidFixture {
        fixture_id: fixture.dataset_id.clone(),
        reason: reason.to_owned(),
    };
    if fixture.dataset_id.trim().is_empty()
        || !fixture.held_out
        || !fixture
            .cases
            .iter()
            .any(|case| case.subset == CommunityBeamSubset::Preference)
        || !fixture
            .cases
            .iter()
            .any(|case| case.subset == CommunityBeamSubset::LifeArea)
    {
        return Err(invalid(
            "community arms require a named, declared held-out preference/life-area fixture",
        ));
    }
    let ids = fixture
        .records
        .iter()
        .map(|record| EntityId::from_hex(&record.id))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if ids.len() != fixture.records.len() || ids.is_empty() {
        return Err(invalid("community corpus IDs must be nonempty and unique"));
    }
    let mut edge_keys = BTreeSet::new();
    for edge in &fixture.edges {
        let source = EntityId::from_hex(&edge.source)?;
        let target = EntityId::from_hex(&edge.target)?;
        if !ids.contains(&source)
            || !ids.contains(&target)
            || !edge_keys.insert((source, edge.kind, target))
            || oneiron::EdgeKind::try_from_u8(edge.kind).is_none()
            || !(0.0..=1.0).contains(&edge.weight)
            || edge
                .vad
                .is_some_and(|vad| !vad.is_finite() || !vad.is_in_range())
        {
            return Err(invalid(
                "community edges require unique, valid stored rows and corpus endpoints",
            ));
        }
    }
    let mut samples = Vec::<CommunityBeamSample>::new();
    let mut case_ids = BTreeSet::new();
    for case in &fixture.cases {
        let seeds = case
            .ordered_seeds
            .iter()
            .map(|seed| {
                EntityId::from_hex(&seed.id).map(|id| oneiron::ScoredEntity {
                    id,
                    score: seed.score,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let seed_ids: BTreeSet<_> = seeds.iter().map(|seed| seed.id).collect();
        let relevant = case
            .relevant_ids
            .iter()
            .map(|id| EntityId::from_hex(id))
            .collect::<Result<BTreeSet<_>, _>>()?;
        if !case_ids.insert(&case.case_id)
            || case.case_id.trim().is_empty()
            || case.text_query.trim().is_empty()
            || !(1..=1000).contains(&case.channel_limit)
            || seeds.is_empty()
            || seeds.len() > 256
            || seed_ids.len() != seeds.len()
            || !seed_ids.is_subset(&ids)
            || relevant.is_empty()
            || relevant.len() != case.relevant_ids.len()
            || !relevant.is_subset(&ids)
            || !relevant.is_disjoint(&seed_ids)
            || !(1..=10).contains(&case.depth)
            || seeds
                .iter()
                .any(|seed| !seed.score.is_finite() || seed.score < 0.0)
            || seeds.windows(2).any(|pair| pair[0].score < pair[1].score)
        {
            return Err(invalid(
                "community queries require unique ordered seed evidence and non-seed relevance judgments",
            ));
        }
        for beta in [0.0, oneiron::ppr_community::PPR_COMMUNITY_BETA_EXPERIMENT] {
            let mut latency_ms = Vec::new();
            let mut refresh_latency_ms = Vec::new();
            let mut observed = None;
            for _ in 0..20 {
                let dir = tempfile::tempdir()?;
                let mut config = beam_vault_config();
                config.ppr_community.beta = beta;
                let vault = Vault::open(dir.path(), config)?;
                let corpus = BeamFixture {
                    schema_version: SCHEMA_VERSION,
                    fixture_id: fixture.dataset_id.clone(),
                    description: "community diagnostic corpus".to_owned(),
                    records: fixture.records.clone(),
                    cases: Vec::new(),
                    ppr_vad_edges: Vec::new(),
                };
                load_fixture_dataset(&vault, &corpus)?;
                for edge in &fixture.edges {
                    let source = EntityId::from_hex(&edge.source)?;
                    let target = EntityId::from_hex(&edge.target)?;
                    let kind = oneiron::EdgeKind::try_from_u8(edge.kind)
                        .ok_or_else(|| invalid("unknown community edge kind"))?;
                    vault.put_edge(&source, kind, &target, edge.weight)?;
                    if let Some(vad) = edge.vad {
                        vault.set_edge_vad(&source, kind, &target, vad)?;
                    }
                }
                let refresh_started = Instant::now();
                vault.refresh_ppr_communities(&[], 0)?;
                refresh_latency_ms.push(refresh_started.elapsed().as_secs_f64() * 1000.0);
                let usage = std::collections::HashMap::new();
                let explicit_seeds: Vec<_> = seeds.iter().map(|seed| seed.id).collect();
                let start = Instant::now();
                let rows = vault
                    .query()
                    .search_text(&case.text_query, case.channel_limit)
                    .expand_ppr(&explicit_seeds, case.depth)
                    .with_community_session_usage(&usage)
                    .with_temporal_now(1)
                    .limit(10)
                    .run()?;
                // Measure only final returned rows: no trace/raw-PPR substitution,
                // seed removal, post-hoc diversification, or reranking in the bench.
                latency_ms.push(start.elapsed().as_secs_f64() * 1000.0);
                let mut fine = BTreeMap::new();
                let mut coarse = BTreeMap::new();
                for row in &rows {
                    let membership = vault.ppr_community_membership(&row.id)?;
                    let fine_key = membership.map_or_else(
                        || format!("node:{}", row.id.to_hex()),
                        |m| format!("community:{}", m.fine.to_hex()),
                    );
                    let coarse_key = membership.map_or_else(
                        || format!("node:{}", row.id.to_hex()),
                        |m| format!("community:{}", m.coarse.to_hex()),
                    );
                    *fine.entry(fine_key).or_insert(0usize) += 1;
                    *coarse.entry(coarse_key).or_insert(0usize) += 1;
                }
                let result_ids: Vec<_> = rows.iter().map(|row| row.id.to_hex()).collect();
                let hits = rows.iter().filter(|row| relevant.contains(&row.id)).count();
                let metrics = (
                    result_ids,
                    hits as f64 / relevant.len() as f64,
                    community_beam_entropy(&fine),
                    community_beam_entropy(&coarse),
                    fine.values().copied().max().unwrap_or(0) as f64 / rows.len().max(1) as f64,
                );
                if observed.as_ref().is_some_and(|first| first != &metrics) {
                    return Err(invalid(
                        "community result IDs or diversity changed between repetitions",
                    ));
                }
                observed = Some(metrics);
            }
            let (
                result_ids,
                recall_at_10,
                fine_entropy_bits,
                coarse_entropy_bits,
                max_fine_fraction,
            ) = observed.ok_or_else(|| invalid("missing community measurements"))?;
            let p95_latency_ms = ppr_vad_p95(&mut latency_ms.clone());
            let baseline = samples
                .last()
                .filter(|sample| sample.case_id == case.case_id && sample.beta == 0.0);
            let recall_gain_percent_vs_zero = baseline
                .and_then(|sample| ppr_vad_percent_change(recall_at_10, sample.recall_at_10));
            let p95_increase_percent_vs_zero = baseline
                .and_then(|sample| ppr_vad_percent_change(p95_latency_ms, sample.p95_latency_ms));
            samples.push(CommunityBeamSample {
                case_id: case.case_id.clone(),
                subset: case.subset,
                beta,
                recall_at_10,
                fine_entropy_bits,
                coarse_entropy_bits,
                max_fine_fraction,
                p95_latency_ms,
                recall_gain_percent_vs_zero,
                p95_increase_percent_vs_zero,
                latency_ms,
                refresh_latency_ms,
                result_ids,
            });
        }
    }
    let baseline: Vec<_> = samples.iter().filter(|sample| sample.beta == 0.0).collect();
    let experiment: Vec<_> = samples.iter().filter(|sample| sample.beta != 0.0).collect();
    let mean_recall = |rows: &[&CommunityBeamSample]| {
        rows.iter().map(|sample| sample.recall_at_10).sum::<f64>() / rows.len() as f64
    };
    let recall_gain_percent_vs_zero =
        ppr_vad_percent_change(mean_recall(&experiment), mean_recall(&baseline));
    let mut baseline_latencies: Vec<_> = baseline
        .iter()
        .flat_map(|sample| sample.latency_ms.iter().copied())
        .collect();
    let mut experiment_latencies: Vec<_> = experiment
        .iter()
        .flat_map(|sample| sample.latency_ms.iter().copied())
        .collect();
    let p95_increase_percent_vs_zero = ppr_vad_percent_change(
        ppr_vad_p95(&mut experiment_latencies),
        ppr_vad_p95(&mut baseline_latencies),
    );
    let minimum_entropy = experiment
        .iter()
        .map(|sample| sample.coarse_entropy_bits)
        .fold(f64::INFINITY, f64::min);
    let maximum_fraction = experiment
        .iter()
        .map(|sample| sample.max_fine_fraction)
        .fold(0.0, f64::max);
    let accepted = community_beam_gate(
        recall_gain_percent_vs_zero,
        p95_increase_percent_vs_zero,
        minimum_entropy,
        maximum_fraction,
    );
    Ok(CommunityBeamReport {
        dataset_id: fixture.dataset_id,
        fixture_sha256: hex_lower(&Sha256::digest(&bytes)),
        declared_held_out: fixture.held_out,
        measurement_scope: "final PipelineBuilder text + Uniform expand_ppr top-10; actual fused seed evidence; no post-processing",
        latency_protocol: "20 fresh-vault empty-PPR-cache queries per case/beta at frozen time 1; maintained community snapshot refreshed before timing and reported separately; query timing includes fusion, filters, diversity, telemetry and deferred cache writes",
        production_default_beta: oneiron::ppr_community::PPR_COMMUNITY_BETA_DEFAULT,
        recall_gain_percent_vs_zero,
        p95_increase_percent_vs_zero,
        final_pipeline_acceptance: Some(accepted),
        remaining_gate: "Verify held-out dataset provenance independently; measured fixture gates never authorize a nonzero production default",
        samples,
    })
}
pub(super) fn community_beam_gate(
    recall_gain: Option<f64>,
    p95_increase: Option<f64>,
    minimum_entropy: f64,
    maximum_fraction: f64,
) -> bool {
    recall_gain.is_some_and(|gain| gain.is_finite() && gain >= 5.0)
        && p95_increase.is_some_and(|increase| increase.is_finite() && increase <= 5.0)
        && minimum_entropy.is_finite()
        && minimum_entropy >= 2.0
        && maximum_fraction.is_finite()
        && (0.0..=0.7).contains(&maximum_fraction)
}
pub(super) fn community_beam_entropy(counts: &BTreeMap<String, usize>) -> f64 {
    let total: usize = counts.values().sum();
    counts
        .values()
        .map(|&count| {
            let p = count as f64 / total as f64;
            -p * p.log2()
        })
        .sum()
}
