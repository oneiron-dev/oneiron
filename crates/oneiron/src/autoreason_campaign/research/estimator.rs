//! The engine's parent-selection estimator (OF-351, ARCH-0053 "DECIDE
//! reward").
//!
//! "Each branch holds a Beta posterior over beating the incumbent." A
//! branch's evidence is every node of its subtree: a measured node whose
//! search reward beats the incumbent root's is a success; any other measured
//! node, and every buggy one, is a failure ("A failure is evidence").
//! Posteriors warm start from the incumbent's side of the tree (a child
//! starts from its parents' belief, at the root's prior strength), from the
//! cold-start ladder at the root (user, then persona, then global data), and
//! from the reliability of the knobs a node touched.
//!
//! "The DGM parent formula ships as the selection floor. Expected information
//! gain is the earned bet behind it. It becomes default only after it beats
//! that formula on a held-out selection benchmark." Every round receipts each
//! branch's belief and information gain; the gain ranks parents only while
//! this estimator version holds a recorded benchmark win.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{ExperimentNode, bounded, bounded_refs, invalid};
use crate::autoreason_campaign::CampaignDatasetRef;
use crate::side_table::{self, Named, SideTable};
use crate::{AttemptId, Result, Vault};

/// The engine estimator's version. A benchmark names the version it
/// measured, so a changed estimator must win again.
pub const ENGINE_ESTIMATOR_VERSION: &str = "beta-eig/1";

/// A benchmark with fewer cases records, but never admits its estimator.
pub const MIN_SELECTION_BENCHMARK_CASES: u64 = 30;

/// The root's prior when the campaign pinned no ladder rung: uniform.
const UNINFORMED_PRIOR: (f64, f64) = (1.0, 1.0);

/// One held-out selection benchmark per estimator version, keyed by version.
const BENCHMARK: SideTable<String, SelectionBenchmark, Named> =
    SideTable::new(&side_table::AUTORESEARCH_ESTIMATOR);

/// A rung of the cold-start ladder, in the order it seeds a new posterior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorRung {
    User,
    Persona,
    Global,
}

/// One rung's Beta pseudo-counts, read from that level's data, and the
/// receipt naming where they came from. Pinned at bind.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriorSeed {
    pub rung: PriorRung,
    pub alpha: f64,
    pub beta: f64,
    pub source_ref: String,
}

/// One branch's belief at a round.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BranchBelief {
    pub alpha: f64,
    pub beta: f64,
    /// Posterior mean chance that a child of this branch beats the incumbent.
    pub p_beat: f64,
    /// The expected information, in nats, one more child outcome carries
    /// about that chance.
    pub information_gain: f64,
}

/// Which formula ranked a round's parents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SelectionRanking {
    /// The DGM parent formula, the shipped floor.
    Dgm,
    /// Information gain first, DGM breaking ties, under an admitted version.
    InformationGain { estimator_version: String },
}

/// One held-out selection benchmark of an estimator version against the DGM
/// parent formula.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionBenchmark {
    pub estimator_version: String,
    /// The held-out benchmark: frozen campaign trees neither formula was
    /// tuned on.
    pub benchmark: CampaignDatasetRef,
    pub cases: u64,
    /// Each formula's score on the benchmark, on one scale, higher better.
    pub dgm_score: f64,
    pub estimator_score: f64,
    pub receipt_refs: Vec<String>,
    pub recorded_at: u64,
}

impl SelectionBenchmark {
    /// A win: enough cases, and the estimator strictly beats DGM.
    #[must_use]
    pub fn won(&self) -> bool {
        self.cases >= MIN_SELECTION_BENCHMARK_CASES && self.estimator_score > self.dgm_score
    }
}

pub(super) fn validate_ladder(ladder: &[PriorSeed]) -> Result<()> {
    let mut rungs = Vec::new();
    for seed in ladder {
        bounded(&seed.source_ref, "a prior seed names its source")?;
        if !seed.alpha.is_finite()
            || !seed.beta.is_finite()
            || seed.alpha <= 0.0
            || seed.beta <= 0.0
            || !(seed.alpha + seed.beta).is_finite()
            || rungs.contains(&seed.rung)
        {
            return Err(invalid(
                "a prior ladder holds one positive, finite seed per rung",
            ));
        }
        rungs.push(seed.rung);
    }
    Ok(())
}

/// Record a held-out selection benchmark for an estimator version. Recorded
/// once: a second look at the held-out benchmark would tune on it.
/// # Errors
/// Unbounded names or refs, non-finite scores, a version already
/// benchmarked, or storage errors.
pub fn record_selection_benchmark(
    vault: &Vault,
    record: SelectionBenchmark,
) -> Result<SelectionBenchmark> {
    bounded(
        &record.estimator_version,
        "a benchmark names its estimator version",
    )?;
    bounded(
        &record.benchmark.dataset_id,
        "a benchmark names its dataset",
    )?;
    bounded(
        &record.benchmark.revision,
        "a benchmark names its dataset revision",
    )?;
    bounded_refs(&record.receipt_refs, true)?;
    if !record.dgm_score.is_finite() || !record.estimator_score.is_finite() {
        return Err(invalid("benchmark scores are finite"));
    }
    vault.with_write_txn_grouped(|txn| {
        if BENCHMARK.contains(&vault.store, txn, &record.estimator_version)? {
            return Err(invalid("an estimator version is benchmarked once"));
        }
        BENCHMARK.put(&vault.store, txn, &record.estimator_version, &record)?;
        Ok(record)
    })
}

/// The benchmark recorded for an estimator version, if any.
/// # Errors
/// Storage errors.
pub fn selection_benchmark(vault: &Vault, version: &str) -> Result<Option<SelectionBenchmark>> {
    let txn = vault.store.env.read_txn()?;
    BENCHMARK.get(&vault.store, &txn, &version.to_owned())
}

/// Whether an estimator version has earned parent ranking.
pub(super) fn estimator_admitted(vault: &Vault, version: &str) -> Result<bool> {
    Ok(selection_benchmark(vault, version)?
        .as_ref()
        .is_some_and(SelectionBenchmark::won))
}

/// Every reachable node's belief, keyed by attempt bytes, or `None` while
/// the incumbent root has no search reward to beat.
pub(super) fn branch_beliefs(
    nodes: &BTreeMap<[u8; 16], ExperimentNode>,
    root: AttemptId,
    ladder: &[PriorSeed],
) -> Option<BTreeMap<[u8; 16], BranchBelief>> {
    let root_key = *root.as_bytes();
    let incumbent = nodes.get(&root_key)?.search.as_ref()?.reward();
    // Each outcome counts toward its own node and every ancestor once.
    let mut counts: BTreeMap<[u8; 16], (f64, f64)> = BTreeMap::new();
    for node in nodes.values() {
        if node.attempt == root {
            continue;
        }
        let beat = match (&node.search, &node.invalid) {
            (_, Some(_)) => false,
            (Some(search), None) => search.reward() > incumbent,
            (None, None) => continue,
        };
        for key in lineage(nodes, *node.attempt.as_bytes()) {
            let entry = counts.entry(key).or_default();
            if beat {
                entry.0 += 1.0;
            } else {
                entry.1 += 1.0;
            }
        }
    }
    let (alpha0, beta0) = ladder
        .iter()
        .min_by_key(|seed| seed.rung)
        .map_or(UNINFORMED_PRIOR, |seed| (seed.alpha, seed.beta));
    let strength = alpha0 + beta0;
    let mut children: BTreeMap<[u8; 16], Vec<[u8; 16]>> = BTreeMap::new();
    let mut waiting: BTreeMap<[u8; 16], usize> = BTreeMap::new();
    for node in nodes.values().filter(|node| node.attempt != root) {
        let key = *node.attempt.as_bytes();
        waiting.insert(key, node.parents.len());
        for parent in &node.parents {
            children.entry(*parent.as_bytes()).or_default().push(key);
        }
    }
    let count = |key: &[u8; 16]| counts.get(key).copied().unwrap_or_default();
    let (wins, losses) = count(&root_key);
    let mut posterior = BTreeMap::from([(root_key, (alpha0 + wins, beta0 + losses))]);
    let mut ready = vec![root_key];
    while let Some(parent) = ready.pop() {
        for child in children.get(&parent).into_iter().flatten() {
            let Some(left) = waiting.get_mut(child) else {
                continue;
            };
            *left = left.saturating_sub(1);
            if *left > 0 {
                continue;
            }
            let node = &nodes[child];
            let (child_wins, child_losses) = count(child);
            // The parents' belief without this child's own subtree, so its
            // outcomes are not counted twice.
            let means: Vec<f64> = node
                .parents
                .iter()
                .filter_map(|parent| posterior.get(parent.as_bytes()))
                .map(|(alpha, beta)| {
                    let (alpha, beta) = (alpha - child_wins, beta - child_losses);
                    alpha / (alpha + beta)
                })
                .collect();
            if means.len() != node.parents.len() {
                continue;
            }
            let mut mean = means.iter().sum::<f64>() / means.len() as f64;
            if let Some(reliability) = node
                .search
                .as_ref()
                .and_then(|search| search.knob_reliability)
            {
                mean = f64::midpoint(mean, reliability);
            }
            posterior.insert(
                *child,
                (
                    mean * strength + child_wins,
                    (1.0 - mean) * strength + child_losses,
                ),
            );
            ready.push(*child);
        }
    }
    Some(
        posterior
            .into_iter()
            .map(|(key, (alpha, beta))| {
                (
                    key,
                    BranchBelief {
                        alpha,
                        beta,
                        p_beat: alpha / (alpha + beta),
                        information_gain: information_gain(alpha, beta),
                    },
                )
            })
            .collect(),
    )
}

/// `attempt` and every ancestor, each once.
fn lineage(nodes: &BTreeMap<[u8; 16], ExperimentNode>, attempt: [u8; 16]) -> BTreeSet<[u8; 16]> {
    let mut seen = BTreeSet::new();
    let mut stack = vec![attempt];
    while let Some(next) = stack.pop() {
        if !seen.insert(next) {
            continue;
        }
        if let Some(node) = nodes.get(&next) {
            stack.extend(node.parents.iter().map(|parent| *parent.as_bytes()));
        }
    }
    seen
}

/// The mutual information between one more Bernoulli outcome and a
/// Beta(alpha, beta) belief about its rate: H(mean) - E[H(p)], in nats.
fn information_gain(alpha: f64, beta: f64) -> f64 {
    let total = alpha + beta;
    let mean = alpha / total;
    let entropy = |p: f64| {
        if p <= 0.0 || p >= 1.0 {
            0.0
        } else {
            -p * p.ln() - (1.0 - p) * (1.0 - p).ln()
        }
    };
    let expected = -mean * (digamma(alpha + 1.0) - digamma(total + 1.0))
        - (1.0 - mean) * (digamma(beta + 1.0) - digamma(total + 1.0));
    (entropy(mean) - expected).max(0.0)
}

/// The digamma function for positive arguments: the recurrence up to 6,
/// then its asymptotic series.
fn digamma(mut x: f64) -> f64 {
    let mut shift = 0.0;
    while x < 6.0 {
        shift -= x.recip();
        x += 1.0;
    }
    let inv = x.recip();
    let inv2 = inv * inv;
    shift + x.ln()
        - 0.5 * inv
        - inv2
            * (1.0 / 12.0
                - inv2 * (1.0 / 120.0 - inv2 * (1.0 / 252.0 - inv2 * (1.0 / 240.0 - inv2 / 132.0))))
}
