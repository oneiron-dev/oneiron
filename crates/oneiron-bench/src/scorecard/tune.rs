//! `scorecard tune-bm25f`: coordinate ascent over the BM25F rank profile on the search slice.
//!
//! One vault per corpus is ingested once; every grid profile scores the same
//! vaults, because profiles are scoring-only. The objective is the macro mean
//! over categories of `ndcg_at_10`, breaking ties on `recall_at_budget`.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::path::Path;

use oneiron::analyzer::AnalyzerChannel;
use oneiron_ruler::pack::{LoadedPack, Slice, load_slice};
use oneiron_ruler::scorecard::{RunHeader, build_keyword_scorecard};

use super::ScorecardFailure;
use super::keyword::{KeywordVaults, retriever_id};
use super::profile::{
    ChannelField, ResolvedProfile, channel_value, resolve_profile, with_channel_field,
};
use super::run::{check_commit, flag_u32};
use super::{parse_flags, required_flag};

/// The flags `scorecard tune-bm25f` takes.
const KNOWN_FLAGS: &[&str] = &[
    "pack-dir",
    "slice",
    "out",
    "steps-out",
    "engine-commit",
    "start",
    "budget-rows",
    "max-rounds",
    "dict-dir",
];

/// The budget rows when `--budget-rows` is omitted.
const DEFAULT_BUDGET_ROWS: u32 = 100;

/// The rounds when `--max-rounds` is omitted.
const DEFAULT_MAX_ROUNDS: u32 = 3;

/// The most rounds `--max-rounds` takes.
const MAX_ROUNDS_LIMIT: u32 = 10;

/// The weight grid (plan D5).
const WEIGHT_GRID: [f64; 9] = [0.0, 0.15, 0.25, 0.35, 0.45, 0.55, 0.7, 0.85, 1.0];

/// The length-norm grid (plan D5).
const B_GRID: [f64; 7] = [0.0, 0.15, 0.3, 0.45, 0.6, 0.75, 0.9];

/// One tunable knob: a channel's weight or length norm over its grid.
struct TunableParam {
    /// The step log name, e.g. `stem.weight`.
    name: &'static str,
    /// The channel the knob sets.
    channel: AnalyzerChannel,
    /// Whether the knob sets the weight (else the length norm).
    field: ChannelField,
    /// The grid values, in scan order.
    grid: &'static [f64],
}

/// The knobs in scan order: three weights, then three length norms. Fixed:
/// the surface weight (the anchor), the overlay length norm (inert under
/// `NoNorm`), the formula, and k1.
const TUNABLES: [TunableParam; 6] = [
    TunableParam {
        name: "stem.weight",
        channel: AnalyzerChannel::Stem,
        field: ChannelField::Weight,
        grid: &WEIGHT_GRID,
    },
    TunableParam {
        name: "normalized_overlay.weight",
        channel: AnalyzerChannel::NormalizedOverlay,
        field: ChannelField::Weight,
        grid: &WEIGHT_GRID,
    },
    TunableParam {
        name: "cjk_ngram.weight",
        channel: AnalyzerChannel::CjkNgram,
        field: ChannelField::Weight,
        grid: &WEIGHT_GRID,
    },
    TunableParam {
        name: "surface.b",
        channel: AnalyzerChannel::Surface,
        field: ChannelField::B,
        grid: &B_GRID,
    },
    TunableParam {
        name: "stem.b",
        channel: AnalyzerChannel::Stem,
        field: ChannelField::B,
        grid: &B_GRID,
    },
    TunableParam {
        name: "cjk_ngram.b",
        channel: AnalyzerChannel::CjkNgram,
        field: ChannelField::B,
        grid: &B_GRID,
    },
];

/// One profile's objective: the macro means and the per-category pairs.
#[derive(Clone, Debug)]
struct Evaluation {
    /// The profile digest.
    digest: String,
    /// The macro mean of `ndcg_at_10` over categories.
    macro_ndcg: f64,
    /// The macro mean of `recall_at_budget` over categories.
    macro_recall: f64,
    /// The per-category (`ndcg_at_10`, `recall_at_budget`) pairs.
    per_category: BTreeMap<String, (f64, f64)>,
}

/// One tuning run: the vaults, the slice, and the memoised evaluations.
struct Tuner<'a> {
    /// The keyword vaults, ingested once.
    vaults: &'a KeywordVaults,
    /// The loaded search slice.
    loaded: &'a LoadedPack,
    /// The engine commit the header carries.
    engine_commit: &'a str,
    /// The retriever the grading names.
    retriever: &'static str,
    /// The rows each query may return.
    limit: usize,
    /// The rows the header carries.
    budget_rows: u32,
    /// The evaluations so far, by profile digest.
    memo: BTreeMap<String, Evaluation>,
}

impl Tuner<'_> {
    /// Run one profile (repeats 1) and grade it; a memoised profile is never run twice.
    fn evaluate(&mut self, profile: &ResolvedProfile) -> Result<Evaluation, ScorecardFailure> {
        if let Some(known) = self.memo.get(&profile.digest) {
            return Ok(known.clone());
        }
        let runs = self.vaults.run(self.loaded, profile, self.limit, 1)?;
        let header = RunHeader {
            engine_commit: self.engine_commit.to_owned(),
            params_digest: profile.digest.clone(),
            budget_rows: self.budget_rows,
        };
        let scorecard = build_keyword_scorecard(
            &self.loaded.slice,
            &self.loaded.pack_digest,
            &header,
            &runs,
            self.retriever,
        )
        .map_err(|error| ScorecardFailure::Run(error.to_string()))?;
        let mut per_category = BTreeMap::new();
        let mut sum_ndcg = 0.0;
        let mut sum_recall = 0.0;
        for (category, metrics) in &scorecard.per_category {
            sum_ndcg += metrics.ndcg_at_10;
            sum_recall += metrics.recall_at_budget;
            per_category.insert(
                category.clone(),
                (metrics.ndcg_at_10, metrics.recall_at_budget),
            );
        }
        let count = scorecard.per_category.len();
        let (macro_ndcg, macro_recall) = if count == 0 {
            (0.0, 0.0)
        } else {
            let denom = count as f64;
            (sum_ndcg / denom, sum_recall / denom)
        };
        let evaluation = Evaluation {
            digest: profile.digest.clone(),
            macro_ndcg,
            macro_recall,
            per_category,
        };
        self.memo.insert(profile.digest.clone(), evaluation.clone());
        Ok(evaluation)
    }
}

/// Tune the rank profile on the search slice, and report the summary.
pub(crate) fn run(args: &[String]) -> Result<serde_json::Value, ScorecardFailure> {
    let flags = parse_flags(args, KNOWN_FLAGS)?;
    let slice_name = required_flag(&flags, "slice")?;
    if slice_name != "search" {
        return Err(ScorecardFailure::Input(
            "tune-bm25f reads only the search slice".to_owned(),
        ));
    }
    let engine_commit = required_flag(&flags, "engine-commit")?;
    check_commit(engine_commit)?;
    let pack_dir = required_flag(&flags, "pack-dir")?;
    let out = required_flag(&flags, "out")?;
    let steps_out = required_flag(&flags, "steps-out")?;
    let budget_rows = flag_u32(
        flags.get("budget-rows").map(String::as_str),
        "budget-rows",
        DEFAULT_BUDGET_ROWS,
        1,
        u32::MAX,
    )?;
    let max_rounds = flag_u32(
        flags.get("max-rounds").map(String::as_str),
        "max-rounds",
        DEFAULT_MAX_ROUNDS,
        1,
        MAX_ROUNDS_LIMIT,
    )?;
    let loaded = load_slice(Path::new(pack_dir), Slice::Search)
        .map_err(|error| ScorecardFailure::Input(error.to_string()))?;
    let start = resolve_profile(flags.get("start").map(String::as_str))?;
    let dict_dir = flags.get("dict-dir").map(|dir| Path::new(dir.as_str()));
    let vaults = KeywordVaults::open(&loaded, dict_dir)?;
    let limit = usize::try_from(budget_rows).unwrap_or(usize::MAX);
    let mut tuner = Tuner {
        vaults: &vaults,
        loaded: &loaded,
        engine_commit,
        retriever: retriever_id(dict_dir),
        limit,
        budget_rows,
        memo: BTreeMap::new(),
    };
    let start_eval = tuner.evaluate(&start)?;
    let mut current = start;
    let mut current_eval = start_eval.clone();
    let mut steps: Vec<serde_json::Value> = Vec::new();
    let mut rounds: u32 = 0;
    for round in 1..=max_rounds {
        rounds = round;
        let mut changed = false;
        for tunable in &TUNABLES {
            let (next, next_eval, moved) = scan_parameter(
                &mut tuner,
                &current,
                &current_eval,
                tunable,
                round,
                &mut steps,
            )?;
            if moved {
                changed = true;
                current = next;
                current_eval = next_eval;
            }
        }
        if !changed {
            break;
        }
    }
    let evaluations = tuner.memo.len();
    let mut out_bytes = serde_json::to_vec_pretty(&current.resolved)
        .map_err(|error| ScorecardFailure::Run(format!("profile encode failed: {error}")))?;
    out_bytes.push(b'\n');
    let steps_value = serde_json::Value::Array(steps);
    let mut steps_bytes = serde_json::to_vec_pretty(&steps_value)
        .map_err(|error| ScorecardFailure::Run(format!("steps encode failed: {error}")))?;
    steps_bytes.push(b'\n');
    std::fs::write(out, out_bytes)
        .map_err(|error| ScorecardFailure::Run(format!("profile write failed: {error}")))?;
    std::fs::write(steps_out, steps_bytes)
        .map_err(|error| ScorecardFailure::Run(format!("steps write failed: {error}")))?;
    Ok(serde_json::json!({
        "slice": "search",
        "pack_id": loaded.slice.pack_id,
        "pack_digest": loaded.pack_digest,
        "retriever": tuner.retriever,
        "rounds": rounds,
        "evaluations": evaluations,
        "start": {
            "profile_digest": start_eval.digest,
            "macro_ndcg_at_10": start_eval.macro_ndcg,
            "macro_recall_at_budget": start_eval.macro_recall,
        },
        "best": {
            "profile_digest": current_eval.digest,
            "macro_ndcg_at_10": current_eval.macro_ndcg,
            "macro_recall_at_budget": current_eval.macro_recall,
            "profile": current.resolved,
        },
        "out": out,
        "steps_out": steps_out,
    }))
}

/// One parameter scan: every grid value at the current others, keeping a strictly better best.
fn scan_parameter(
    tuner: &mut Tuner<'_>,
    current: &ResolvedProfile,
    current_eval: &Evaluation,
    tunable: &TunableParam,
    round: u32,
    steps: &mut Vec<serde_json::Value>,
) -> Result<(ResolvedProfile, Evaluation, bool), ScorecardFailure> {
    let mut tried: Vec<(f64, ResolvedProfile, Evaluation)> = Vec::with_capacity(tunable.grid.len());
    for value in tunable.grid {
        let candidate = with_channel_field(current, tunable.channel, tunable.field, *value)?;
        let eval = tuner.evaluate(&candidate)?;
        tried.push((*value, candidate, eval));
    }
    let mut best_index: Option<usize> = None;
    let mut best_eval = current_eval;
    for (index, (_, _, eval)) in tried.iter().enumerate() {
        if is_better(eval, best_eval) {
            best_index = Some(index);
            best_eval = eval;
        }
    }
    let final_value = match best_index {
        Some(index) => tried[index].0,
        None => channel_value(current, tunable.channel, tunable.field)?,
    };
    for (value, _, eval) in &tried {
        steps.push(serde_json::json!({
            "round": round,
            "parameter": tunable.name,
            "value": *value,
            "profile_digest": eval.digest,
            "macro_ndcg_at_10": eval.macro_ndcg,
            "macro_recall_at_budget": eval.macro_recall,
            "per_category": category_pairs(&eval.per_category),
            "chosen": value.total_cmp(&final_value) == Ordering::Equal,
        }));
    }
    match best_index {
        Some(index) => {
            let (_, profile, eval) = tried.swap_remove(index);
            Ok((profile, eval, true))
        }
        None => Ok((current.clone(), current_eval.clone(), false)),
    }
}

/// True when the candidate beats the best: higher macro nDCG, then higher macro recall.
fn is_better(candidate: &Evaluation, best: &Evaluation) -> bool {
    match candidate.macro_ndcg.total_cmp(&best.macro_ndcg) {
        Ordering::Greater => true,
        Ordering::Equal => {
            candidate.macro_recall.total_cmp(&best.macro_recall) == Ordering::Greater
        }
        Ordering::Less => false,
    }
}

/// The steps-out JSON of per-category pairs: each category to its two means.
fn category_pairs(pairs: &BTreeMap<String, (f64, f64)>) -> serde_json::Value {
    let mut map = serde_json::Map::with_capacity(pairs.len());
    for (category, (ndcg, recall)) in pairs {
        map.insert(
            category.clone(),
            serde_json::json!({"ndcg_at_10": *ndcg, "recall_at_budget": *recall}),
        );
    }
    serde_json::Value::Object(map)
}
