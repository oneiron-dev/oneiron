//! The run card and the result folder (plan section 7).
//!
//! Every run.jsonl run carries a card: what ran (commit, set, tier, dataset
//! revision and hashes, cleaning manifest, split, seeds), how it was scored
//! (scorer, judge and answerer pins, prompt hashes, tokenizer, pack budget),
//! what it cost, and its exactness receipts. When the manifest names
//! `outputs.resultsRoot`, the run also writes
//! `<resultsRoot>/<commit>/<set>/<tier>/<split>/` and never overwrites one.
use super::exactness::ExactnessReport;
use super::load::{RunJsonlEntry, sha256_hex};
use super::model::RunManifest;
use super::report_model::{
    BeamReport, ContractCleaning, ContractCleaningAction, ContractSplit, ScorerReport,
};
use super::{BeamError, BeamResult};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub(super) const CARD_VERSION: &str = "oneiron-bench.run-card.v1";

/// What the card needs from each selected record, captured before ingest.
#[derive(Debug, Clone)]
pub(super) struct RecordSummary {
    pub(super) dataset_id: String,
    pub(super) dataset_revision: String,
    pub(super) split: Option<ContractSplit>,
    pub(super) cleaning: Option<ContractCleaning>,
    pub(super) budget: usize,
    pub(super) corpus: Option<(String, String)>,
    pub(super) question_time: Option<u64>,
}

impl RecordSummary {
    pub(super) fn of(entries: &[RunJsonlEntry]) -> Vec<Self> {
        entries
            .iter()
            .map(|entry| {
                let record = &entry.record;
                Self {
                    dataset_id: record.dataset.id.clone(),
                    dataset_revision: record.dataset.revision.clone(),
                    split: record.split,
                    cleaning: record.cleaning.clone(),
                    budget: record.budget.limit,
                    corpus: record
                        .corpus_ref
                        .as_ref()
                        .map(|r| (r.corpus_id.clone(), r.sha256.clone())),
                    question_time: record.question_time,
                }
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RunCard {
    pub(super) card_version: &'static str,
    pub(super) identity: CardIdentity,
    pub(super) pins: CardPins,
    pub(super) cost: Vec<CardArmCost>,
    pub(super) exactness: CardExactness,
    pub(super) comparability: Vec<CardComparability>,
    /// Works the run's design leans on (the context-rot row cites Chroma).
    pub(super) references: Vec<super::sweep::Reference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) result_dir: Option<PathBuf>,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CardIdentity {
    /// The commit that produced the run; names the result folder.
    pub(super) commit: Option<String>,
    pub(super) commit_source: String,
    /// Whether the build tree had uncommitted changes; `None` is unknown.
    pub(super) build_dirty: Option<bool>,
    pub(super) build_dirty_source: String,
    pub(super) set: String,
    pub(super) tier: String,
    pub(super) dataset_revision: String,
    pub(super) run_jsonl_sha256: String,
    pub(super) corpora: Vec<CardCorpus>,
    pub(super) cleaning: Vec<CardCleaning>,
    pub(super) split: CardSplit,
    /// External sets have no seeds; generated arms list theirs.
    pub(super) seeds: Vec<u64>,
    pub(super) questions: usize,
    pub(super) questions_with_question_time: usize,
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub(super) struct CardCorpus {
    pub(super) corpus_id: String,
    pub(super) sha256: String,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CardCleaning {
    pub(super) manifest_id: String,
    pub(super) sha256: String,
    pub(super) kept: usize,
    pub(super) relabelled: usize,
    pub(super) excluded: usize,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CardSplit {
    /// `dev`, `heldout`, `full` (both) or `undeclared` (v1 records).
    pub(super) label: String,
    pub(super) rule_id: &'static str,
    pub(super) salt_sha256: String,
    pub(super) dev_percent: u64,
    pub(super) dev_questions: usize,
    pub(super) heldout_questions: usize,
    pub(super) undeclared_questions: usize,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CardPins {
    pub(super) scorer: ScorerReport,
    pub(super) judges: Vec<CardJudge>,
    pub(super) answerers: Vec<CardAnswerer>,
    pub(super) tokenizer: String,
    pub(super) pack_budgets: Vec<usize>,
    /// The budget sweep: labels, `full`, or `record` (each record's own).
    pub(super) budget_sweep: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CardJudge {
    pub(super) role: String,
    pub(super) judge_pin: String,
    pub(super) vote_count: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) prompt_sha256: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CardAnswerer {
    pub(super) arm: String,
    pub(super) model_pin: String,
    pub(super) prompt_sha256: String,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CardArmCost {
    pub(super) arm: String,
    pub(super) questions: usize,
    /// Questions this arm refused (the reader could not resolve a temporal phrase).
    pub(super) refused: usize,
    /// Serialized context-pack tokens; absent where the arm reports no pack.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) pack_tokens: Option<u64>,
    pub(super) query_input_tokens: u64,
    pub(super) query_output_tokens: u64,
    pub(super) reprefill_tokens: u64,
    pub(super) judge_input_tokens: u64,
    pub(super) offline_input_tokens_amortized: u64,
    pub(super) elapsed_us_p50: u64,
    pub(super) elapsed_us_p95: u64,
    pub(super) cost_usd: f64,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CardExactness {
    pub(super) items_checked: usize,
    pub(super) mismatches: usize,
    pub(super) evidence_ids_checked: usize,
    pub(super) evidence_ids_unresolved: usize,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CardComparability {
    pub(super) competitor_id: String,
    pub(super) provenance: String,
    pub(super) independent: bool,
    pub(super) regime: String,
    pub(super) disposition: String,
}

/// Inputs every card builder shares.
pub(super) struct CardInputs<'a> {
    pub(super) manifest: &'a RunManifest,
    pub(super) run_jsonl: &'a Path,
    pub(super) records: &'a [RecordSummary],
    pub(super) scorer: &'a ScorerReport,
    pub(super) exactness: &'a ExactnessReport,
    pub(super) judges: Vec<CardJudge>,
    pub(super) answerers: Vec<CardAnswerer>,
    pub(super) cost: Vec<CardArmCost>,
    pub(super) budgets: Vec<String>,
    pub(super) references: Vec<super::sweep::Reference>,
}

pub(super) fn build_card(inputs: CardInputs<'_>) -> BeamResult<RunCard> {
    let CardInputs {
        manifest,
        run_jsonl,
        records,
        scorer,
        exactness,
        judges,
        answerers,
        cost,
        budgets,
        references,
    } = inputs;
    let first = records
        .first()
        .ok_or_else(|| card_error("a run card needs at least one record"))?;
    let revisions: BTreeSet<&str> = records
        .iter()
        .map(|r| r.dataset_revision.as_str())
        .collect();
    if revisions.len() != 1 {
        return Err(card_error("a run card covers exactly one dataset revision"));
    }
    let build = crate::perf::git_sha::build_git_sha();
    let (commit, commit_source) = match build.sha {
        Some(sha) => (Some(sha), build.source),
        None => {
            let checkout = crate::perf::git_sha::source_checkout_git_sha();
            (
                checkout.sha,
                format!(
                    "source checkout HEAD ({}); no build-embedded sha: {}",
                    checkout.source, build.source
                ),
            )
        }
    };
    let dirty = crate::perf::git_sha::build_tree_dirty();
    let corpora: BTreeSet<CardCorpus> = records
        .iter()
        .filter_map(|r| r.corpus.clone())
        .map(|(corpus_id, sha256)| CardCorpus { corpus_id, sha256 })
        .collect();
    let mut cleaning: BTreeMap<(String, String), CardCleaning> = BTreeMap::new();
    for record in records {
        let Some(c) = &record.cleaning else { continue };
        let row = cleaning
            .entry((c.manifest_id.clone(), c.sha256.clone()))
            .or_insert_with(|| CardCleaning {
                manifest_id: c.manifest_id.clone(),
                sha256: c.sha256.clone(),
                kept: 0,
                relabelled: 0,
                excluded: 0,
            });
        match c.action {
            ContractCleaningAction::Kept => row.kept += 1,
            ContractCleaningAction::Relabelled => row.relabelled += 1,
            ContractCleaningAction::Excluded => row.excluded += 1,
        }
    }
    let count = |split| records.iter().filter(|r| r.split == split).count();
    let (dev, heldout, undeclared) = (
        count(Some(ContractSplit::Dev)),
        count(Some(ContractSplit::Heldout)),
        count(None),
    );
    let label = match (dev > 0, heldout > 0, undeclared > 0) {
        (_, _, true) => "undeclared",
        (true, true, false) => "full",
        (true, false, false) => "dev",
        (false, true, false) => "heldout",
        (false, false, false) => "undeclared",
    };
    let tiers: BTreeSet<String> = manifest
        .competitors
        .iter()
        .filter_map(|c| c.card.as_ref().map(|card| card.axes.tier.row.clone()))
        .collect();
    let tier = match tiers.len() {
        1 => tiers.into_iter().next().unwrap_or_default(),
        0 => first.dataset_id.clone(),
        _ => "mixed".to_owned(),
    };
    let comparability = manifest
        .competitors
        .iter()
        .filter_map(|c| {
            c.card.as_ref().map(|card| CardComparability {
                competitor_id: c.competitor_id.clone(),
                provenance: card.axes.provenance.source.clone(),
                independent: card.axes.provenance.independent,
                regime: format!("{:?}", card.axes.regime).to_lowercase(),
                disposition: format!("{:?}", card.axes.disposition()),
            })
        })
        .collect();
    let pack_budgets: BTreeSet<usize> = records.iter().map(|r| r.budget).collect();
    Ok(RunCard {
        card_version: CARD_VERSION,
        identity: CardIdentity {
            commit,
            commit_source,
            build_dirty: dirty.dirty,
            build_dirty_source: dirty.source,
            set: first.dataset_id.clone(),
            tier,
            dataset_revision: first.dataset_revision.clone(),
            run_jsonl_sha256: sha256_hex(&std::fs::read(run_jsonl)?),
            corpora: corpora.into_iter().collect(),
            cleaning: cleaning.into_values().collect(),
            split: CardSplit {
                label: label.to_owned(),
                rule_id: super::split::SPLIT_RULE_ID,
                salt_sha256: sha256_hex(super::split::SPLIT_SALT.as_bytes()),
                dev_percent: super::split::dev_percent(&first.dataset_id),
                dev_questions: dev,
                heldout_questions: heldout,
                undeclared_questions: undeclared,
            },
            seeds: Vec::new(),
            questions: records.len(),
            questions_with_question_time: records
                .iter()
                .filter(|r| r.question_time.is_some())
                .count(),
        },
        pins: CardPins {
            scorer: scorer.clone(),
            judges,
            answerers,
            tokenizer: oneiron::DEFAULT_CONTEXT_PACK_TOKENIZER_ID.to_owned(),
            pack_budgets: pack_budgets.into_iter().collect(),
            budget_sweep: budgets,
        },
        cost,
        exactness: CardExactness {
            items_checked: exactness.items_checked,
            mismatches: exactness.mismatches.len(),
            evidence_ids_checked: exactness.evidence_ids_checked,
            evidence_ids_unresolved: exactness.evidence_ids_unresolved.len(),
        },
        comparability,
        references,
        result_dir: None,
    })
}

/// Judges named by the manifest's competitor cards (fixture judges for a
/// retrieval-only run; the measured run lists its live pin instead).
pub(super) fn manifest_judges(manifest: &RunManifest) -> Vec<CardJudge> {
    manifest
        .competitors
        .iter()
        .filter_map(|c| {
            c.card.as_ref().map(|card| CardJudge {
                role: format!("competitor:{}", c.competitor_id),
                judge_pin: format!("{}@{}", card.judge.judge_id, card.judge.version),
                vote_count: card.judge.vote_count,
                prompt_sha256: card
                    .judge
                    .answer_prompt
                    .as_ref()
                    .map(|pin| pin.sha256.clone()),
            })
        })
        .collect()
}

/// Per-competitor cost columns over a `beam run` report.
pub(super) fn report_arm_costs(report: &BeamReport) -> Vec<CardArmCost> {
    let mut by_arm: BTreeMap<String, Vec<&super::report_model::CompetitorReport>> = BTreeMap::new();
    for case in &report.cases {
        for row in case
            .competitors
            .iter()
            .chain(&case.appendix)
            .chain(&case.dropped)
        {
            by_arm
                .entry(row.competitor_id.clone())
                .or_default()
                .push(row);
        }
    }
    by_arm
        .into_iter()
        .map(|(arm, rows)| {
            let elapsed: Vec<u64> = rows.iter().map(|r| r.costs.query.elapsed_us).collect();
            let refused = report
                .cases
                .iter()
                .flat_map(|case| &case.arms)
                .filter(|arm_report| {
                    rows.first().is_some_and(|row| row.arm == arm_report.arm)
                        && matches!(
                            &arm_report.outcome,
                            super::report_model::ArmOutcome::NotReady { not_ready }
                                if not_ready.component == super::arms::TEMPORAL_READER_COMPONENT
                        )
                })
                .count();
            CardArmCost {
                arm,
                questions: rows.len(),
                refused,
                pack_tokens: Some(rows.iter().map(|r| r.costs.query.output_tokens).sum()),
                query_input_tokens: rows.iter().map(|r| r.costs.query.input_tokens).sum(),
                query_output_tokens: rows.iter().map(|r| r.costs.query.output_tokens).sum(),
                reprefill_tokens: rows.iter().map(|r| r.costs.query.reprefill_tokens).sum(),
                judge_input_tokens: rows.iter().map(|r| r.costs.judge.input_tokens).sum(),
                offline_input_tokens_amortized: rows
                    .iter()
                    .map(|r| r.costs.offline.input_tokens)
                    .sum(),
                elapsed_us_p50: percentile(&elapsed, 50),
                elapsed_us_p95: percentile(&elapsed, 95),
                cost_usd: rows.iter().map(|r| r.costs.total_cost_usd).sum(),
            }
        })
        .collect()
}

/// Nearest-rank percentile; 0 for no samples.
pub(super) fn percentile(samples: &[u64], pct: usize) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let rank = (pct * sorted.len()).div_ceil(100).max(1);
    sorted[rank - 1]
}

/// `<root>/<commit>/<set>/<tier>/<split>`; `-dirty` marks a dirty build and
/// `unknown-commit` a run no commit describes.
pub(super) fn result_dir(root: &Path, card: &RunCard) -> PathBuf {
    let commit = match (&card.identity.commit, card.identity.build_dirty) {
        (Some(sha), Some(true)) => format!("{sha}-dirty"),
        (Some(sha), _) => sha.clone(),
        (None, _) => "unknown-commit".to_owned(),
    };
    root.join(commit)
        .join(folder_safe(&card.identity.set))
        .join(folder_safe(&card.identity.tier))
        .join(folder_safe(&card.identity.split.label))
}

fn folder_safe(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    if cleaned.is_empty() || cleaned.chars().all(|c| c == '.') {
        "unnamed".to_owned()
    } else {
        cleaned
    }
}

/// Writes card.json, report.json, packs.jsonl, results.jsonl, cost.json,
/// exactness.json, split.json and cleaning.json. Refuses a folder that already holds a card:
/// a published result is never overwritten or rescored.
pub(super) fn write_result_folder(
    dir: &Path,
    card: &RunCard,
    report: &impl Serialize,
    exactness: &ExactnessReport,
    packs_jsonl: Option<&Path>,
    results: &[super::sweep::ResultsRow],
) -> BeamResult<()> {
    if dir.join("card.json").exists() {
        return Err(card_error(&format!(
            "result folder {} already holds a card; results are never overwritten",
            dir.display()
        )));
    }
    std::fs::create_dir_all(dir)?;
    write_json(dir, "report.json", report)?;
    write_json(dir, "cost.json", &card.cost)?;
    write_json(dir, "exactness.json", exactness)?;
    write_json(dir, "split.json", &card.identity.split)?;
    write_json(dir, "cleaning.json", &card.identity.cleaning)?;
    if let Some(packs) = packs_jsonl
        && packs.exists()
    {
        std::fs::copy(packs, dir.join("packs.jsonl"))?;
    }
    if !results.is_empty() {
        super::sweep::write_rows(&dir.join("results.jsonl"), results)?;
    }
    // The card goes last: its presence marks a complete folder.
    write_json(dir, "card.json", card)
}

fn write_json<T: Serialize + ?Sized>(dir: &Path, name: &str, value: &T) -> BeamResult<()> {
    std::fs::write(dir.join(name), serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn card_error(reason: &str) -> BeamError {
    BeamError::Comparability {
        reason: format!("run card: {reason}"),
    }
}
