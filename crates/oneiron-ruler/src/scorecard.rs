//! The `oneiron.retrieval_scorecard.v1` scorecard: one retrieval run, graded (RESEARCH-0651 Tier 0).
//!
//! The engine run itself happens in oneiron-bench, which hands this crate the
//! ranked record ids and the search timings; this crate computes every number,
//! so the grading code depends on no engine crate.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::metrics::{abstention_f1, ndcg_at, nearest_rank, recall_at, reciprocal_rank};
use crate::pack::{PackSlice, Query, Slice, sha256_hex};

/// The contract string every scorecard carries.
pub const SCORECARD_CONTRACT: &str = "oneiron.retrieval_scorecard.v1";

/// The ranked metrics, in report order.
pub const RANKED_METRICS: [&str; 5] = [
    "ndcg_at_10",
    "mrr",
    "recall_at_5",
    "recall_at_20",
    "recall_at_budget",
];

/// One ranked hit: the record and the exact engine score.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hit {
    /// The record id.
    pub record_id: String,
    /// `f32::to_bits` of the engine score: exact, no float in JSON.
    pub score_bits: u32,
}

/// One repeat of one query: the ranking and its search time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepeatRun {
    /// Ranked hits, best first.
    pub hits: Vec<Hit>,
    /// Search time of this repeat only, in microseconds.
    pub search_us: u64,
}

/// Every repeat of one query.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryRun {
    /// The pack query id.
    pub query_id: String,
    /// One entry per repeat, in repeat order.
    pub repeats: Vec<RepeatRun>,
}

/// The run header: which engine and parameters produced the run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunHeader {
    /// The engine commit.
    pub engine_commit: String,
    /// 64 lowercase hex: the digest of the parameter set.
    pub params_digest: String,
    /// How many rows the engine was allowed to return.
    pub budget_rows: u32,
}

/// One graded retrieval run.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scorecard {
    /// Must equal [`SCORECARD_CONTRACT`].
    pub contract: String,
    /// The engine commit.
    pub engine_commit: String,
    /// 64 lowercase hex: the digest of the parameter set.
    pub params_digest: String,
    /// The pack id.
    pub pack_id: String,
    /// The pack revision.
    pub revision: String,
    /// The pack digest of the graded manifest.
    pub pack_digest: String,
    /// Which slice was graded.
    pub slice: Slice,
    /// The embedder, from the pack's [`EmbeddingPin`](crate::pack::EmbeddingPin).
    pub model_id: String,
    /// How many rows the engine was allowed to return.
    pub budget_rows: u32,
    /// How many repeats each query ran.
    pub repeats: u32,
    /// How many pack queries were graded.
    pub query_count: u32,
    /// The means over the non-abstention queries.
    pub metrics: Metrics,
    /// One entry per category with a non-abstention query.
    pub per_category: BTreeMap<String, CategoryMetrics>,
    /// For each ranked metric, the weakest category.
    pub per_category_min: BTreeMap<String, CategoryMin>,
    /// The search-time percentiles.
    pub latency: Latency,
    /// True when every repeat matches the first exactly.
    pub repeat_digest_equal: bool,
    /// Pack query order; empty on the sealed slice.
    pub per_query: Vec<QueryScore>,
}

/// The means over the non-abstention queries.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metrics {
    /// Mean `ndcg_at(10)`.
    pub ndcg_at_10: f64,
    /// Mean reciprocal rank.
    pub mrr: f64,
    /// Mean `recall_at(5)`.
    pub recall_at_5: f64,
    /// Mean `recall_at(20)`.
    pub recall_at_20: f64,
    /// Mean `recall_at(budget_rows)`.
    pub recall_at_budget: f64,
    /// Abstention F1 over every query.
    pub abstention_f1: f64,
}

/// One category's means over its non-abstention queries.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CategoryMetrics {
    /// How many non-abstention queries the category holds.
    pub queries: u32,
    /// Mean `ndcg_at(10)`.
    pub ndcg_at_10: f64,
    /// Mean reciprocal rank.
    pub mrr: f64,
    /// Mean `recall_at(5)`.
    pub recall_at_5: f64,
    /// Mean `recall_at(20)`.
    pub recall_at_20: f64,
    /// Mean `recall_at(budget_rows)`.
    pub recall_at_budget: f64,
}

/// The weakest category for one ranked metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CategoryMin {
    /// The weakest category.
    pub category: String,
    /// Its mean for the metric.
    pub value: f64,
}

/// The search-time percentiles, in microseconds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Latency {
    /// p50 over every `search_us` sample.
    pub search_p50_us: u64,
    /// p95 over every `search_us` sample.
    pub search_p95_us: u64,
    /// With 2+ repeats, the max-minus-min of the per-repeat p95s.
    pub aa_p95_spread_us: Option<u64>,
}

/// One query's grades. The five ranked metrics are `None` on abstention.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryScore {
    /// The pack query id.
    pub query_id: String,
    /// The question category.
    pub category: String,
    /// Whether the query expects no result.
    pub expect_empty: bool,
    /// How many hits the first repeat returned.
    pub returned: u32,
    /// `ndcg_at(10)` of the first repeat.
    pub ndcg_at_10: Option<f64>,
    /// Reciprocal rank of the first repeat.
    pub mrr: Option<f64>,
    /// `recall_at(5)` of the first repeat.
    pub recall_at_5: Option<f64>,
    /// `recall_at(20)` of the first repeat.
    pub recall_at_20: Option<f64>,
    /// `recall_at(budget_rows)` of the first repeat.
    pub recall_at_budget: Option<f64>,
    /// The ranking digest (search slice only).
    pub ranked_digest: Option<String>,
}

/// Every way a scorecard can fail to build, write or load.
#[derive(Debug, Error)]
pub enum ScorecardError {
    /// The pack has no embedding pin, so no model id.
    #[error("pack has no vectors")]
    PackHasNoVectors,
    /// The budget allows no rows.
    #[error("budget rows must be positive")]
    BadBudget,
    /// A digest field is not 64 lowercase hex.
    #[error("bad digest in {field}")]
    BadDigest {
        /// Which field is bad.
        field: String,
    },
    /// A run names a query the pack does not hold.
    #[error("unknown query run: {query_id}")]
    UnknownQueryRun {
        /// The unknown query.
        query_id: String,
    },
    /// Two runs name one query.
    #[error("duplicate query run: {query_id}")]
    DuplicateQueryRun {
        /// The repeated query.
        query_id: String,
    },
    /// A pack query has no run.
    #[error("missing query run: {query_id}")]
    MissingQueryRun {
        /// The missing query.
        query_id: String,
    },
    /// A run carries no repeats.
    #[error("query run has no repeats: {query_id}")]
    NoRepeats {
        /// The empty run.
        query_id: String,
    },
    /// Runs carry different repeat counts.
    #[error("repeat count mismatch for {query_id}: expected {expected}, found {found}")]
    RepeatCountMismatch {
        /// The mismatching run.
        query_id: String,
        /// The first run's repeat count.
        expected: usize,
        /// The count at hand.
        found: usize,
    },
    /// A hit names a record outside the query's corpus.
    #[error("query {query_id} hits {record_id} outside its corpus")]
    HitOutsideCorpus {
        /// The query.
        query_id: String,
        /// The outside record.
        record_id: String,
    },
    /// One repeat names a record twice.
    #[error("query {query_id} hits {record_id} twice in one repeat")]
    DuplicateHit {
        /// The query.
        query_id: String,
        /// The repeated record.
        record_id: String,
    },
    /// A scorecard file could not be read or written.
    #[error("io error at {path:?}: {source}")]
    Io {
        /// The file path.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The scorecard is not valid JSON for this shape.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// A ranking has no canonical JSON form.
    #[error("canonical JSON error: {0}")]
    Canonical(String),
    /// The scorecard names another contract.
    #[error("wrong contract: {found}")]
    WrongContract {
        /// The contract the file carries.
        found: String,
    },
}

/// Grade one retrieval run of one pack slice under one parameter set.
///
/// The graded ranking of a query is its first repeat's hits. Refusals run in
/// contract order: no vectors, bad budget, bad digest, unknown run, duplicate
/// run, missing run, no repeats, repeat mismatch, hit outside the corpus,
/// duplicate hit.
pub fn build_scorecard(
    pack: &PackSlice,
    pack_digest: &str,
    header: &RunHeader,
    runs: &[QueryRun],
) -> Result<Scorecard, ScorecardError> {
    let model_id = pack
        .embedding
        .as_ref()
        .ok_or(ScorecardError::PackHasNoVectors)?
        .model_id
        .clone();
    if header.budget_rows == 0 {
        return Err(ScorecardError::BadBudget);
    }
    if !is_digest(&header.params_digest) {
        return Err(ScorecardError::BadDigest {
            field: "params_digest".to_owned(),
        });
    }
    let mut pack_ids = BTreeSet::new();
    for query in &pack.queries {
        pack_ids.insert(query.query_id.as_str());
    }
    for run in runs {
        if !pack_ids.contains(run.query_id.as_str()) {
            return Err(ScorecardError::UnknownQueryRun {
                query_id: run.query_id.clone(),
            });
        }
    }
    let mut run_ids = BTreeSet::new();
    for run in runs {
        if !run_ids.insert(run.query_id.as_str()) {
            return Err(ScorecardError::DuplicateQueryRun {
                query_id: run.query_id.clone(),
            });
        }
    }
    for query in &pack.queries {
        if !run_ids.contains(query.query_id.as_str()) {
            return Err(ScorecardError::MissingQueryRun {
                query_id: query.query_id.clone(),
            });
        }
    }
    for run in runs {
        if run.repeats.is_empty() {
            return Err(ScorecardError::NoRepeats {
                query_id: run.query_id.clone(),
            });
        }
    }
    if let Some(first) = runs.first() {
        let expected = first.repeats.len();
        for run in runs.iter().skip(1) {
            if run.repeats.len() != expected {
                return Err(ScorecardError::RepeatCountMismatch {
                    query_id: run.query_id.clone(),
                    expected,
                    found: run.repeats.len(),
                });
            }
        }
    }
    let mut corpus_records: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for corpus in &pack.corpora {
        let mut named = BTreeSet::new();
        for session in &corpus.sessions {
            for record_id in &session.record_ids {
                named.insert(record_id.as_str());
            }
        }
        corpus_records.insert(corpus.corpus_id.as_str(), named);
    }
    let mut query_by_id: BTreeMap<&str, &Query> = BTreeMap::new();
    for query in &pack.queries {
        query_by_id.insert(query.query_id.as_str(), query);
    }
    let mut run_by_id: BTreeMap<&str, &QueryRun> = BTreeMap::new();
    for run in runs {
        run_by_id.insert(run.query_id.as_str(), run);
    }
    let empty_records: BTreeSet<&str> = BTreeSet::new();
    for run in runs {
        let query = match query_by_id.get(run.query_id.as_str()) {
            Some(query) => *query,
            None => continue,
        };
        let records = corpus_records
            .get(query.corpus_id.as_str())
            .unwrap_or(&empty_records);
        for repeat in &run.repeats {
            for hit in &repeat.hits {
                if !records.contains(hit.record_id.as_str()) {
                    return Err(ScorecardError::HitOutsideCorpus {
                        query_id: run.query_id.clone(),
                        record_id: hit.record_id.clone(),
                    });
                }
            }
        }
    }
    for run in runs {
        for repeat in &run.repeats {
            let mut seen = BTreeSet::new();
            for hit in &repeat.hits {
                if !seen.insert(hit.record_id.as_str()) {
                    return Err(ScorecardError::DuplicateHit {
                        query_id: run.query_id.clone(),
                        record_id: hit.record_id.clone(),
                    });
                }
            }
        }
    }
    let repeat_count = runs.first().map_or(0, |first| first.repeats.len());
    let budget = usize::try_from(header.budget_rows).unwrap_or(usize::MAX);
    let mut sum_ndcg = 0.0;
    let mut sum_mrr = 0.0;
    let mut sum_recall_5 = 0.0;
    let mut sum_recall_20 = 0.0;
    let mut sum_recall_budget = 0.0;
    let mut graded_count = 0usize;
    let mut true_positive = 0usize;
    let mut false_positive = 0usize;
    let mut false_negative = 0usize;
    let mut per_category: BTreeMap<String, CategoryMetrics> = BTreeMap::new();
    let mut per_query: Vec<QueryScore> = Vec::new();
    for query in &pack.queries {
        let run = match run_by_id.get(query.query_id.as_str()) {
            Some(run) => *run,
            None => continue,
        };
        let first = match run.repeats.first() {
            Some(first) => first,
            None => continue,
        };
        let returned = first.hits.len() as u32;
        let ranked_digest = if pack.slice == Slice::Search {
            let mut rows: Vec<serde_json::Value> = Vec::with_capacity(first.hits.len());
            for hit in &first.hits {
                rows.push(serde_json::Value::Array(vec![
                    serde_json::Value::from(hit.record_id.as_str()),
                    serde_json::Value::from(hit.score_bits),
                ]));
            }
            let value = serde_json::Value::Array(rows);
            let canonical = serde_json_canonicalizer::to_vec(&value)
                .map_err(|error| ScorecardError::Canonical(error.to_string()))?;
            Some(sha256_hex(&canonical))
        } else {
            None
        };
        if query.expect_empty {
            if first.hits.is_empty() {
                true_positive += 1;
            } else {
                false_negative += 1;
            }
            if pack.slice != Slice::Sealed {
                per_query.push(QueryScore {
                    query_id: query.query_id.clone(),
                    category: query.category.clone(),
                    expect_empty: true,
                    returned,
                    ndcg_at_10: None,
                    mrr: None,
                    recall_at_5: None,
                    recall_at_20: None,
                    recall_at_budget: None,
                    ranked_digest,
                });
            }
            continue;
        }
        if first.hits.is_empty() {
            false_positive += 1;
        }
        let mut ranked: Vec<&str> = Vec::with_capacity(first.hits.len());
        for hit in &first.hits {
            ranked.push(hit.record_id.as_str());
        }
        let ndcg = ndcg_at(&ranked, &query.qrels, 10);
        let mrr = reciprocal_rank(&ranked, &query.qrels);
        let recall_5 = recall_at(&ranked, &query.qrels, 5);
        let recall_20 = recall_at(&ranked, &query.qrels, 20);
        let recall_budget = recall_at(&ranked, &query.qrels, budget);
        sum_ndcg += ndcg;
        sum_mrr += mrr;
        sum_recall_5 += recall_5;
        sum_recall_20 += recall_20;
        sum_recall_budget += recall_budget;
        graded_count += 1;
        let entry = per_category
            .entry(query.category.clone())
            .or_insert(CategoryMetrics {
                queries: 0,
                ndcg_at_10: 0.0,
                mrr: 0.0,
                recall_at_5: 0.0,
                recall_at_20: 0.0,
                recall_at_budget: 0.0,
            });
        entry.queries += 1;
        entry.ndcg_at_10 += ndcg;
        entry.mrr += mrr;
        entry.recall_at_5 += recall_5;
        entry.recall_at_20 += recall_20;
        entry.recall_at_budget += recall_budget;
        if pack.slice != Slice::Sealed {
            per_query.push(QueryScore {
                query_id: query.query_id.clone(),
                category: query.category.clone(),
                expect_empty: false,
                returned,
                ndcg_at_10: Some(ndcg),
                mrr: Some(mrr),
                recall_at_5: Some(recall_5),
                recall_at_20: Some(recall_20),
                recall_at_budget: Some(recall_budget),
                ranked_digest,
            });
        }
    }
    let f1 = abstention_f1(true_positive, false_positive, false_negative);
    let metrics = if graded_count == 0 {
        Metrics {
            ndcg_at_10: 0.0,
            mrr: 0.0,
            recall_at_5: 0.0,
            recall_at_20: 0.0,
            recall_at_budget: 0.0,
            abstention_f1: f1,
        }
    } else {
        let denom = graded_count as f64;
        Metrics {
            ndcg_at_10: sum_ndcg / denom,
            mrr: sum_mrr / denom,
            recall_at_5: sum_recall_5 / denom,
            recall_at_20: sum_recall_20 / denom,
            recall_at_budget: sum_recall_budget / denom,
            abstention_f1: f1,
        }
    };
    for entry in per_category.values_mut() {
        let denom = f64::from(entry.queries);
        entry.ndcg_at_10 /= denom;
        entry.mrr /= denom;
        entry.recall_at_5 /= denom;
        entry.recall_at_20 /= denom;
        entry.recall_at_budget /= denom;
    }
    let mut per_category_min: BTreeMap<String, CategoryMin> = BTreeMap::new();
    if !per_category.is_empty() {
        for name in RANKED_METRICS {
            let mut best_category = "";
            let mut best_value = f64::INFINITY;
            let mut is_first = true;
            for (category, sums) in &per_category {
                let value = category_value(sums, name);
                if is_first || value < best_value {
                    best_category = category.as_str();
                    best_value = value;
                    is_first = false;
                }
            }
            per_category_min.insert(
                name.to_owned(),
                CategoryMin {
                    category: best_category.to_owned(),
                    value: best_value,
                },
            );
        }
    }
    let mut all_us: Vec<u64> = Vec::new();
    for run in runs {
        for repeat in &run.repeats {
            all_us.push(repeat.search_us);
        }
    }
    all_us.sort_unstable();
    let search_p50_us = nearest_rank(&all_us, 50).unwrap_or(0);
    let search_p95_us = nearest_rank(&all_us, 95).unwrap_or(0);
    let aa_p95_spread_us = if repeat_count >= 2 {
        let mut p95s: Vec<u64> = Vec::with_capacity(repeat_count);
        for index in 0..repeat_count {
            let mut samples: Vec<u64> = Vec::with_capacity(runs.len());
            for run in runs {
                if let Some(repeat) = run.repeats.get(index) {
                    samples.push(repeat.search_us);
                }
            }
            samples.sort_unstable();
            if let Some(value) = nearest_rank(&samples, 95) {
                p95s.push(value);
            }
        }
        if p95s.len() == repeat_count {
            let max = p95s.iter().copied().max().unwrap_or(0);
            let min = p95s.iter().copied().min().unwrap_or(0);
            Some(max.saturating_sub(min))
        } else {
            None
        }
    } else {
        None
    };
    let latency = Latency {
        search_p50_us,
        search_p95_us,
        aa_p95_spread_us,
    };
    let mut repeat_digest_equal = true;
    for run in runs {
        let first_hits = match run.repeats.first() {
            Some(first) => &first.hits,
            None => continue,
        };
        for repeat in run.repeats.iter().skip(1) {
            if repeat.hits != *first_hits {
                repeat_digest_equal = false;
                break;
            }
        }
        if !repeat_digest_equal {
            break;
        }
    }
    Ok(Scorecard {
        contract: SCORECARD_CONTRACT.to_owned(),
        engine_commit: header.engine_commit.clone(),
        params_digest: header.params_digest.clone(),
        pack_id: pack.pack_id.clone(),
        revision: pack.revision.clone(),
        pack_digest: pack_digest.to_owned(),
        slice: pack.slice,
        model_id,
        budget_rows: header.budget_rows,
        repeats: repeat_count as u32,
        query_count: pack.queries.len() as u32,
        metrics,
        per_category,
        per_category_min,
        latency,
        repeat_digest_equal,
        per_query,
    })
}

/// Write one scorecard: the pretty JSON plus a trailing newline.
pub fn write_scorecard(path: &Path, scorecard: &Scorecard) -> Result<(), ScorecardError> {
    let mut bytes = serde_json::to_vec_pretty(scorecard)?;
    bytes.push(b'\n');
    std::fs::write(path, bytes).map_err(|source| ScorecardError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

/// Load one scorecard; the contract must equal [`SCORECARD_CONTRACT`].
///
/// Compare loaded scorecards with a tolerance: the workspace's `serde_json`
/// has no `float_roundtrip` feature, so its parser may return a 17-digit
/// float 1 ULP off.
pub fn load_scorecard(path: &Path) -> Result<Scorecard, ScorecardError> {
    let bytes = std::fs::read(path).map_err(|source| ScorecardError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let scorecard: Scorecard = serde_json::from_slice(&bytes)?;
    if scorecard.contract != SCORECARD_CONTRACT {
        return Err(ScorecardError::WrongContract {
            found: scorecard.contract,
        });
    }
    Ok(scorecard)
}

/// One ranked metric of a category, by [`RANKED_METRICS`] name.
fn category_value(metrics: &CategoryMetrics, name: &str) -> f64 {
    match name {
        "ndcg_at_10" => metrics.ndcg_at_10,
        "mrr" => metrics.mrr,
        "recall_at_5" => metrics.recall_at_5,
        "recall_at_20" => metrics.recall_at_20,
        _ => metrics.recall_at_budget,
    }
}

/// True for 64 lowercase hex digits.
fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}
