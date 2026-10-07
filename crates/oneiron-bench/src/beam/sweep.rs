//! The budget sweep and its results rows (`oneiron-bench.results-row.v1`).
//!
//! Every approach runs at every budget in the sweep, so a chart can plot
//! accuracy against budget with one line per approach. The full-context
//! reader runs at every budget too, even where the whole history fits: the
//! context-rot row (Hong, Troynikov and Huber, Chroma 2025). The row schema is
//! fixed in /Users/olety/Desktop/temp/ctx-bench-20261006/results-row-schema.md.
//! Every row also states the `secrets` setting its vaults ran with (ARCH-0042,
//! secret scan on bench vaults).
use super::report_model::{RunContractRecord, ScoreReport};
use super::{BeamError, BeamResult};
use oneiron::policy_model::SecretScanMode;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub(super) const RESULTS_ROW_SCHEMA: &str = "oneiron-bench.results-row.v1";
pub(super) const FULL_CONTEXT_APPROACH: &str = "full-context";
/// Stand-in budget for `full` where a number is required: far above any
/// history the bench ingests, so nothing is windowed below the reader.
pub(super) const FULL_BUDGET_TOKENS: usize = 1 << 30;

/// The context-rot reference every card with a full-context row carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Reference {
    pub(super) authors: &'static str,
    pub(super) title: &'static str,
    pub(super) publisher: &'static str,
    pub(super) date: &'static str,
    pub(super) url: &'static str,
}
pub(super) const CONTEXT_ROT: Reference = Reference {
    authors: "Kelly Hong, Anton Troynikov, Jeff Huber",
    title: "Context Rot: How Increasing Input Tokens Impacts LLM Performance",
    publisher: "Chroma Technical Report",
    date: "2025-07-14",
    url: "https://www.trychroma.com/research/context-rot",
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum BudgetLabel {
    Tokens(usize),
    Full,
}
impl BudgetLabel {
    pub(super) fn label(self) -> String {
        match self {
            Self::Tokens(tokens) => tokens.to_string(),
            Self::Full => "full".to_owned(),
        }
    }

    pub(super) const fn tokens(self) -> Option<usize> {
        match self {
            Self::Tokens(tokens) => Some(tokens),
            Self::Full => None,
        }
    }
}

/// `4096,8192,16384,32768,65536,full`: ascending, distinct, `full` last.
pub(super) fn parse_budgets(spec: &str) -> BeamResult<Vec<BudgetLabel>> {
    let mut budgets = Vec::new();
    for part in spec
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let budget = if part.eq_ignore_ascii_case("full") {
            BudgetLabel::Full
        } else {
            match part.parse::<usize>() {
                Ok(tokens) if tokens > 0 => BudgetLabel::Tokens(tokens),
                _ => {
                    return Err(sweep_error(format!(
                        "budget `{part}` is not a positive token count or `full`"
                    )));
                }
            }
        };
        budgets.push(budget);
    }
    budgets.sort();
    budgets.dedup();
    if budgets.is_empty() {
        return Err(sweep_error("--budget needs at least one budget".into()));
    }
    Ok(budgets)
}

/// `--secret-scan on|off`: the `secrets` switch every base vault gets before
/// ingest.
pub(super) fn parse_secret_scan(spec: &str) -> BeamResult<SecretScanMode> {
    match spec {
        "on" => Ok(SecretScanMode::On),
        "off" => Ok(SecretScanMode::Off),
        other => Err(sweep_error(format!(
            "--secret-scan `{other}` is not `on` or `off`"
        ))),
    }
}

/// The row label of a `secrets` setting.
pub(super) fn secrets_label(mode: SecretScanMode) -> &'static str {
    match mode {
        SecretScanMode::On => "on",
        SecretScanMode::Off => "off",
    }
}

/// The card pin: every distinct setting the run's forks read back.
pub(super) fn secrets_pins(modes: impl IntoIterator<Item = SecretScanMode>) -> Vec<String> {
    let labels: std::collections::BTreeSet<&str> = modes.into_iter().map(secrets_label).collect();
    labels.into_iter().map(str::to_owned).collect()
}

/// A stated price table: model prices and the date they were read.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PriceConfig {
    pub(super) as_of: String,
    pub(super) source: String,
    /// The model a retrieval row's pack is priced for.
    pub(super) reader_model: String,
    pub(super) models: BTreeMap<String, ModelPrices>,
}
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ModelPrices {
    pub(super) input_per_million: f64,
    pub(super) output_per_million: f64,
}
/// The price stamp a row carries.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(super) struct PriceStamp {
    pub(super) as_of: String,
    pub(super) source: String,
    pub(super) model: String,
    pub(super) input_per_million: f64,
    pub(super) output_per_million: f64,
}
impl PriceConfig {
    pub(super) fn load(path: &Path) -> BeamResult<Self> {
        let config: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        let date_ok = config.as_of.len() == 10
            && config.as_of.bytes().enumerate().all(|(i, b)| {
                if i == 4 || i == 7 {
                    b == b'-'
                } else {
                    b.is_ascii_digit()
                }
            });
        if !date_ok || config.source.trim().is_empty() {
            return Err(sweep_error(
                "price table needs as_of (YYYY-MM-DD) and a source".into(),
            ));
        }
        if config.models.values().any(|m| {
            !m.input_per_million.is_finite()
                || !m.output_per_million.is_finite()
                || m.input_per_million < 0.0
                || m.output_per_million < 0.0
        }) {
            return Err(sweep_error("prices must be finite and non-negative".into()));
        }
        if !config.models.contains_key(&config.reader_model) {
            return Err(sweep_error(format!(
                "reader_model `{}` has no price in the table",
                config.reader_model
            )));
        }
        Ok(config)
    }

    pub(super) fn stamp(&self) -> PriceStamp {
        let prices = self.models[&self.reader_model];
        PriceStamp {
            as_of: self.as_of.clone(),
            source: self.source.clone(),
            model: self.reader_model.clone(),
            input_per_million: prices.input_per_million,
            output_per_million: prices.output_per_million,
        }
    }
}
impl PriceStamp {
    pub(super) fn usd(&self, input_tokens: f64, output_tokens: f64) -> f64 {
        (input_tokens * self.input_per_million + output_tokens * self.output_per_million)
            / 1_000_000.0
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct SweepOptions {
    /// Empty: each record's own budget.
    pub(super) budgets: Vec<BudgetLabel>,
    pub(super) prices: Option<PriceConfig>,
    pub(super) results_path: Option<PathBuf>,
    /// None: the vault's own setting (on unless switched).
    pub(super) secrets: Option<SecretScanMode>,
}

/// One question, one approach, one budget.
#[derive(Debug, Clone)]
pub(super) struct Observation {
    pub(super) approach: String,
    pub(super) approach_kind: &'static str,
    pub(super) reader_model: Option<String>,
    pub(super) budget: Option<usize>,
    pub(super) budget_label: String,
    pub(super) rot: bool,
    pub(super) groups: Vec<String>,
    /// (metric, value, the metric is 0/1)
    pub(super) metrics: Vec<(String, f64, bool)>,
    pub(super) refused: bool,
    pub(super) prompt_tokens: f64,
    pub(super) reprefill_tokens: f64,
    pub(super) output_tokens: f64,
    pub(super) judge_tokens: f64,
    pub(super) usd: Option<f64>,
    pub(super) price: Option<PriceStamp>,
    pub(super) latency_ms: Option<f64>,
    /// The `secrets` setting the question's vault read back.
    pub(super) secrets: Option<SecretScanMode>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct ResultsRow {
    pub(super) schema: &'static str,
    pub(super) producer: String,
    pub(super) run_id: String,
    pub(super) commit: Option<String>,
    pub(super) set: String,
    pub(super) set_revision: String,
    pub(super) tier: String,
    pub(super) split: String,
    pub(super) approach: String,
    pub(super) approach_kind: String,
    pub(super) reader_model: Option<String>,
    pub(super) budget: Option<usize>,
    pub(super) budget_label: String,
    pub(super) rot: bool,
    pub(super) group: String,
    pub(super) metric: String,
    pub(super) accuracy: Option<f64>,
    pub(super) n: usize,
    pub(super) refused: usize,
    pub(super) ci95_low: Option<f64>,
    pub(super) ci95_high: Option<f64>,
    pub(super) prompt_tokens_mean: f64,
    pub(super) reprefill_tokens_mean: f64,
    pub(super) output_tokens_mean: f64,
    pub(super) judge_tokens_mean: f64,
    pub(super) usd_per_1k_questions: Option<f64>,
    pub(super) price_table: Option<PriceStamp>,
    pub(super) latency_ms_p50: Option<f64>,
    pub(super) latency_ms_p95: Option<f64>,
    /// `on` or `off`: the `secrets` setting of every vault behind the row.
    pub(super) secrets: Option<SecretScanMode>,
}

/// The run-level fields every row repeats.
#[derive(Debug, Clone)]
pub(super) struct RowContext {
    pub(super) producer: String,
    pub(super) run_id: String,
    pub(super) commit: Option<String>,
    pub(super) set: String,
    pub(super) set_revision: String,
    pub(super) tier: String,
    pub(super) split: String,
}

/// `all`, then `ability:`, `trap:` and `lang:` from the record's gold labels.
pub(super) fn groups_for(record: &RunContractRecord) -> Vec<String> {
    let mut groups = vec!["all".to_owned()];
    let labels = record.gold.as_ref().and_then(|gold| gold.labels.as_ref());
    for (field, prefix) in [("ability", "ability"), ("trap", "trap"), ("lang", "lang")] {
        if let Some(value) = labels
            .and_then(|labels| labels.get(field))
            .and_then(serde_json::Value::as_str)
        {
            groups.push(format!("{prefix}:{value}"));
        }
    }
    groups
}

/// Evidence metrics for a pack: recall and all-found, for questions that
/// name evidence. A question without evidence ids scores no evidence metric.
pub(super) fn evidence_metrics(
    record: &RunContractRecord,
    pack_ids: &[String],
) -> Vec<(String, f64, bool)> {
    let Some(evidence) = record
        .gold
        .as_ref()
        .and_then(|gold| gold.evidence_ids.as_ref())
        .filter(|ids| !ids.is_empty())
    else {
        return Vec::new();
    };
    let found = evidence.iter().filter(|id| pack_ids.contains(id)).count();
    vec![
        (
            "evidence_recall".to_owned(),
            found as f64 / evidence.len() as f64,
            false,
        ),
        (
            "evidence_all_found".to_owned(),
            if found == evidence.len() { 1.0 } else { 0.0 },
            true,
        ),
    ]
}

/// The full-context reader at one budget: the newest suffix of the history
/// that fits, in history order. Returns the window's ids and its tokens.
pub(super) fn full_context_window(
    record: &RunContractRecord,
    budget: Option<usize>,
) -> (Vec<String>, u64) {
    let items = record.corpus_items();
    let limit = budget.unwrap_or(usize::MAX) as u64;
    let mut used = 0_u64;
    let mut ids = Vec::new();
    for item in items.iter().rev() {
        let tokens = oneiron::count_context_pack_tokens(&item.text) as u64;
        if used + tokens > limit {
            break;
        }
        used += tokens;
        ids.push(item.id.clone());
    }
    (ids, used)
}

/// The model-free full-context observation (retrieval runs): what the
/// window holds of the evidence, and what reading it costs.
pub(super) fn full_context_observation(
    record: &RunContractRecord,
    budget: BudgetLabel,
    price: Option<&PriceStamp>,
) -> Observation {
    let (ids, window_tokens) = full_context_window(record, budget.tokens());
    let prompt =
        (window_tokens + oneiron::count_context_pack_tokens(&record.question) as u64) as f64;
    Observation {
        approach: FULL_CONTEXT_APPROACH.to_owned(),
        approach_kind: "retrieval",
        reader_model: None,
        budget: budget.tokens(),
        budget_label: budget.label(),
        rot: true,
        groups: groups_for(record),
        metrics: evidence_metrics(record, &ids),
        refused: false,
        prompt_tokens: prompt,
        reprefill_tokens: 0.0,
        output_tokens: 0.0,
        judge_tokens: 0.0,
        usd: price.map(|stamp| stamp.usd(prompt, 0.0)),
        price: price.cloned(),
        latency_ms: None,
        secrets: None,
    }
}

/// The per-question metric values a judged row carries.
pub(super) fn judged_metrics(score: &ScoreReport, beam_columns: bool) -> Vec<(String, f64, bool)> {
    let Some(columns) = &score.beam else {
        return Vec::new();
    };
    if beam_columns {
        vec![
            (
                super::nuggets::REPLICATE_COLUMN.to_owned(),
                columns.aggregate.replicate,
                false,
            ),
            (
                super::nuggets::FIXED_COLUMN.to_owned(),
                columns.aggregate.fixed,
                false,
            ),
        ]
    } else {
        vec![("accuracy".to_owned(), columns.aggregate.fixed, false)]
    }
}

type RowKey = (
    String,
    &'static str,
    Option<String>,
    Option<usize>,
    String,
    bool,
    String,
    String,
    Option<&'static str>,
);

/// Folds observations into rows: one per approach x budget x group x metric
/// (and `secrets` setting, so vaults that ran differently never share a row).
pub(super) fn aggregate(context: &RowContext, observations: &[Observation]) -> Vec<ResultsRow> {
    let mut buckets: BTreeMap<RowKey, Vec<(&Observation, f64, bool)>> = BTreeMap::new();
    for observation in observations {
        for group in &observation.groups {
            for (metric, value, binary) in &observation.metrics {
                buckets
                    .entry((
                        observation.approach.clone(),
                        observation.approach_kind,
                        observation.reader_model.clone(),
                        observation.budget,
                        observation.budget_label.clone(),
                        observation.rot,
                        group.clone(),
                        metric.clone(),
                        observation.secrets.map(secrets_label),
                    ))
                    .or_default()
                    .push((observation, *value, *binary));
            }
        }
    }
    // Budgets sort numerically with `full` (None) last.
    let mut rows: Vec<ResultsRow> = buckets
        .into_iter()
        .map(
            |((approach, kind, reader, budget, label, rot, group, metric, _), items)| {
                let n = items.len();
                let mean = |f: &dyn Fn(&Observation) -> f64| {
                    items.iter().map(|(o, _, _)| f(o)).sum::<f64>() / n as f64
                };
                let accuracy = items.iter().map(|(_, value, _)| value).sum::<f64>() / n as f64;
                let binary = items.iter().all(|(_, _, binary)| *binary);
                let (ci95_low, ci95_high) = if binary {
                    let successes = items.iter().filter(|(_, value, _)| *value >= 0.5).count();
                    let (lo, hi) = wilson(successes, n);
                    (Some(lo), Some(hi))
                } else {
                    (None, None)
                };
                let usd: Option<Vec<f64>> = items.iter().map(|(o, _, _)| o.usd).collect();
                let mut latency: Vec<f64> =
                    items.iter().filter_map(|(o, _, _)| o.latency_ms).collect();
                latency.sort_by(f64::total_cmp);
                ResultsRow {
                    schema: RESULTS_ROW_SCHEMA,
                    producer: context.producer.clone(),
                    run_id: context.run_id.clone(),
                    commit: context.commit.clone(),
                    set: context.set.clone(),
                    set_revision: context.set_revision.clone(),
                    tier: context.tier.clone(),
                    split: context.split.clone(),
                    approach,
                    approach_kind: kind.to_owned(),
                    reader_model: reader,
                    budget,
                    budget_label: label,
                    rot,
                    group,
                    metric,
                    accuracy: Some(accuracy),
                    n,
                    refused: items.iter().filter(|(o, _, _)| o.refused).count(),
                    ci95_low,
                    ci95_high,
                    prompt_tokens_mean: mean(&|o| o.prompt_tokens),
                    reprefill_tokens_mean: mean(&|o| o.reprefill_tokens),
                    output_tokens_mean: mean(&|o| o.output_tokens),
                    judge_tokens_mean: mean(&|o| o.judge_tokens),
                    usd_per_1k_questions: usd
                        .map(|all| all.iter().sum::<f64>() / n as f64 * 1000.0),
                    price_table: items.first().and_then(|(o, _, _)| o.price.clone()),
                    latency_ms_p50: nearest_rank(&latency, 50),
                    latency_ms_p95: nearest_rank(&latency, 95),
                    secrets: items.first().and_then(|(o, _, _)| o.secrets),
                }
            },
        )
        .collect();
    rows.sort_by(|a, b| {
        (
            &a.approach,
            a.budget.is_none(),
            a.budget,
            &a.group,
            &a.metric,
        )
            .cmp(&(
                &b.approach,
                b.budget.is_none(),
                b.budget,
                &b.group,
                &b.metric,
            ))
    });
    rows
}

fn nearest_rank(sorted: &[f64], pct: usize) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = (pct * sorted.len()).div_ceil(100).max(1);
    Some(sorted[rank - 1])
}

/// Wilson 95% interval for `successes` of `n`.
pub(super) fn wilson(successes: usize, n: usize) -> (f64, f64) {
    if n == 0 {
        return (0.0, 1.0);
    }
    let z = 1.959_963_984_540_054_f64;
    let n_f = n as f64;
    let p = successes as f64 / n_f;
    let denom = 1.0 + z * z / n_f;
    let centre = p + z * z / (2.0 * n_f);
    let margin = z * ((p * (1.0 - p) + z * z / (4.0 * n_f)) / n_f).sqrt();
    (
        ((centre - margin) / denom).clamp(0.0, 1.0),
        ((centre + margin) / denom).clamp(0.0, 1.0),
    )
}

pub(super) fn write_rows(path: &Path, rows: &[ResultsRow]) -> BeamResult<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let mut out = Vec::new();
    for row in rows {
        serde_json::to_writer(&mut out, row)?;
        out.push(b'\n');
    }
    std::fs::write(path, out)?;
    Ok(())
}

fn sweep_error(reason: String) -> BeamError {
    BeamError::Comparability {
        reason: format!("budget sweep: {reason}"),
    }
}
