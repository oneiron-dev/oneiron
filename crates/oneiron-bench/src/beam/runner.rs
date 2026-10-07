//! Subcommand run entry points and orchestration.

use super::arms::adapter_for;
use super::card::{
    CardInputs, RecordSummary, build_card, manifest_judges, report_arm_costs, result_dir,
    write_result_folder,
};
use super::exactness::{ExactnessReport, verify_loaded_corpus};
use super::fork::BaseVault;
use super::load::{
    RunJsonlEntry, contract_context_pack_record, contract_corpus_digest, contract_vault_shape,
    load_dataset, load_jsonl_group, resolve_corpus_refs, resolve_manifest_paths,
    select_run_jsonl_records, write_contract_pack_rows,
};
use super::model::{ArmKind, BeamFixture, DatasetSource, FixtureCase, RunManifest, SchemaHeader};
use super::ppr_vad::ppr_vad_sweep_report;
use super::report::cost_breakdown;
use super::report_model::{
    BeamReport, CaseReport, CompetitorReport, ContextPackContractRecord, DatasetLoadReport,
    LoadedDataset,
};
use super::scorer::{BeamScorer, FixedBeamScorer};
use super::sweep::{
    BudgetLabel, CONTEXT_ROT, FULL_BUDGET_TOKENS, Observation, PriceConfig, PriceStamp, RowContext,
    SweepOptions, aggregate, evidence_metrics, full_context_observation, groups_for,
    secrets_label, write_rows,
};
use super::util::{beam_vault_config, invalid_manifest, report_format_label};
use super::validate::{
    validate_fixture, validate_manifest, validate_manifest_fixture_cases, validate_manifest_paths,
};
use super::{
    BEAM_128K_TOKEN_BUDGET, BUILTIN_FIXTURE_JSON, BUILTIN_MANIFEST_JSON, BeamError, BeamResult,
    SCHEMA_VERSION,
};
use oneiron::Vault;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub(super) fn print_help() {
    println!("{BEAM_HELP}");
    println!(
        "  beam community <fixture.json>  Final pipeline beta-off/on recall, diversity and latency arms"
    );
}
pub(crate) fn run_builtin_smoke() -> BeamResult<BeamReport> {
    let fixture = parse_fixture_json(BUILTIN_FIXTURE_JSON)?;
    let manifest = parse_manifest_json(BUILTIN_MANIFEST_JSON)?;
    ensure_manifest_selects_128k_case(&manifest, &fixture)?;
    run_fixture_manifest(&manifest, &fixture)
}
pub(super) const BEAM_HELP: &str = "usage: oneiron-bench beam <subcommand>\n\
                         \n\
                         subcommands:\n\
                           smoke    run the built-in BEAM 128K deterministic context-pack smoke fixture\n\
                                    aligned with ONEIRON-ARCH-0042\n\
                           measure <plan.json>  measured shared-answerer, backbone and cheap-chat arms\n\
                           judge <run.json>      production three-vote model scorer\n\
                           score-nuggets <run.json> dual-column replay and commit proof folder\n\
                           infra <measurement.json> cost-framing-only vector-DB rows\n\
                           rung-fixture attach and locality-transition conformance\n\
                           tiers <graduation.json> no-regression scale ladder\n\
                           fixture-protocol <fixture.json> known-span retrieval evaluation\n\
                           edit-path-pack <dir>   materialize five edit-task sandboxes\n\
                           edit-path <attempts.json>   score tests and contracts per arm\n\
                           run <manifest> [--budget 4096,8192,...,full] [--prices <file>] [--results <file>]\n\
                               [--secret-scan on|off]\n\
                                    run a BEAM manifest; fixture datasets load dataset.path JSON\n\
                                    relative to the manifest; emit declared packs.jsonl outputs;\n\
                                    a budget sweep runs every arm at every budget and writes\n\
                                    results rows (oneiron-bench.results-row.v1); --secret-scan\n\
                                    sets each base vault's secrets switch before ingest, and\n\
                                    every row states the setting its vault read back\n\
                           trace-export\n\
                                    export RetrievalTrace records to JSONL by fork hash (ONE-1311)\n\
                           corpus-export / corpus-replay\n\
                                    export turn-indexed runs and replay their packs and traces\n\
                           verify-corpus <manifest>\n\
                                    ingest each corpus once and fail unless every item reads\n\
                                    back byte-exact (sha256) and every gold evidence id resolves";
pub(crate) fn run_manifest_path(path: &Path) -> BeamResult<BeamReport> {
    run_manifest_path_with(path, &SweepOptions::default())
}
pub(crate) fn run_manifest_path_with(path: &Path, sweep: &SweepOptions) -> BeamResult<BeamReport> {
    let manifest_json = std::fs::read_to_string(path)?;
    let mut manifest = parse_manifest_json(&manifest_json)?;
    resolve_manifest_paths(&mut manifest, path);
    let fixture = match &manifest.dataset {
        DatasetSource::Fixture {
            path: Some(path), ..
        } => Some(parse_fixture_json(&std::fs::read_to_string(path)?)?),
        _ => None,
    };
    run_manifest_with(&manifest, fixture.as_ref(), sweep)
}
pub(super) fn ensure_manifest_selects_128k_case(
    manifest: &RunManifest,
    fixture: &BeamFixture,
) -> BeamResult<()> {
    let cases_by_id: BTreeMap<&str, &FixtureCase> = fixture
        .cases
        .iter()
        .map(|case| (case.case_id.as_str(), case))
        .collect();

    if manifest.case_ids.iter().any(|case_id| {
        cases_by_id
            .get(case_id.as_str())
            .is_some_and(|case| case.token_budget == BEAM_128K_TOKEN_BUDGET)
    }) {
        return Ok(());
    }

    Err(invalid_manifest(
        manifest,
        "built-in BEAM smoke manifest must select a 128K token-budget case",
    ))
}
pub(crate) fn parse_fixture_json(json: &str) -> BeamResult<BeamFixture> {
    let fixture: BeamFixture = serde_json::from_str(json)?;
    validate_fixture(&fixture)?;
    Ok(fixture)
}
pub(crate) fn parse_manifest_json(json: &str) -> BeamResult<RunManifest> {
    let header: SchemaHeader = serde_json::from_str(json)?;
    if header.schema_version != SCHEMA_VERSION {
        return Err(BeamError::UnsupportedSchemaVersion {
            expected: SCHEMA_VERSION,
            actual: header.schema_version,
        });
    }
    let manifest: RunManifest = serde_json::from_str(json)?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}
pub(crate) fn run_fixture_manifest(
    manifest: &RunManifest,
    fixture: &BeamFixture,
) -> BeamResult<BeamReport> {
    run_manifest(manifest, Some(fixture))
}
pub(super) fn run_manifest(
    manifest: &RunManifest,
    fixture: Option<&BeamFixture>,
) -> BeamResult<BeamReport> {
    run_manifest_with(manifest, fixture, &SweepOptions::default())
}
pub(super) fn run_manifest_with(
    manifest: &RunManifest,
    fixture: Option<&BeamFixture>,
    sweep: &SweepOptions,
) -> BeamResult<BeamReport> {
    validate_manifest(manifest)?;
    validate_manifest_paths(manifest)?;
    if let (DatasetSource::Fixture { .. }, Some(fixture)) = (&manifest.dataset, fixture) {
        validate_manifest_fixture_cases(manifest, fixture)?;
    }

    if matches!(manifest.dataset, DatasetSource::Jsonl { .. }) {
        return run_jsonl_manifest_isolated(manifest, sweep);
    } else if !sweep.budgets.is_empty() {
        return Err(invalid_manifest(
            manifest,
            "a budget sweep needs a run.jsonl dataset",
        ));
    }

    let tempdir = tempfile::tempdir()?;
    let vault = Vault::open(tempdir.path(), beam_vault_config())?;
    let mut loaded = load_dataset(&vault, manifest, fixture)?;
    if manifest.arms.contains(&ArmKind::PprVadSweep) {
        loaded.ppr_vad_fixture = fixture.cloned();
    }
    let (cases, pack_rows) = run_loaded_cases(&vault, manifest, &loaded)?;
    let scorer = FixedBeamScorer;
    let report_format = report_format_label(manifest.report.format).to_owned();

    if let Some(outputs) = &manifest.outputs {
        write_contract_pack_rows(&outputs.packs_jsonl, &pack_rows)?;
    }

    Ok(BeamReport {
        schema_version: SCHEMA_VERSION,
        run_id: manifest.run_id.clone(),
        fixture_id: loaded.fixture_id,
        fixture_description: loaded.fixture_description,
        dataset: loaded.report,
        scorer: scorer.metadata(),
        report_format,
        ppr_vad_sweep: ppr_vad_sweep_report(&cases),
        cases,
        exactness: None,
        card: None,
        results: Vec::new(),
    })
}
/// One base vault per corpus key, one fork per question. A shared corpus
/// (`corpus_ref`) is ingested once for all its questions; an inline corpus is
/// its own key, so v1 runs keep one ingest per question.
pub(super) fn run_jsonl_manifest_isolated(
    manifest: &RunManifest,
    sweep: &SweepOptions,
) -> BeamResult<BeamReport> {
    let scorer = FixedBeamScorer;
    let report_format = report_format_label(manifest.report.format).to_owned();
    let DatasetSource::Jsonl {
        path,
        arm_id,
        limit,
        expected_min_results,
        ..
    } = &manifest.dataset
    else {
        return Err(invalid_manifest(
            manifest,
            "isolated runs need a jsonl dataset",
        ));
    };
    let entries = select_run_jsonl_records(manifest, path, arm_id.as_deref())?;
    let summaries = RecordSummary::of(&entries);
    let mut dataset_report: Option<DatasetLoadReport> = None;
    let mut fixture_id: Option<String> = None;
    let mut fixture_description: Option<String> = None;
    let mut cases_by_id: BTreeMap<String, Vec<CaseReport>> = BTreeMap::new();
    let mut rows_by_id: BTreeMap<String, Vec<ContextPackContractRecord>> = BTreeMap::new();
    let mut offline_runs = Vec::new();
    let mut exactness = ExactnessReport::default();
    // None: each record's own budget. A sweep runs every point on the same
    // fork: packs are reads, and the fork is this question's alone.
    let budgets: Vec<Option<BudgetLabel>> = if sweep.budgets.is_empty() {
        vec![None]
    } else {
        sweep.budgets.iter().copied().map(Some).collect()
    };
    let price = sweep.prices.as_ref().map(PriceConfig::stamp);
    let mut observations = Vec::new();
    let mut secrets_seen = BTreeSet::new();

    for (corpus_identity, mut group) in group_by_corpus(entries) {
        resolve_corpus_refs(path, &mut group)?;
        let group_ids: BTreeSet<String> = group
            .iter()
            .map(|entry| entry.record.question_id.clone())
            .collect();
        let case_ids: Vec<String> = manifest
            .case_ids
            .iter()
            .filter(|id| group_ids.contains(*id))
            .cloned()
            .collect();
        let shape = contract_vault_shape(manifest, path, &group)?;
        let (base, (loaded, group_exactness)) =
            BaseVault::build(corpus_identity, shape.config(), sweep.secrets, |vault| {
                let loaded = load_jsonl_group(
                    vault,
                    &shape,
                    &case_ids,
                    path,
                    group,
                    *limit,
                    *expected_min_results,
                )?;
                // Exactness runs on the base before any fork: a mismatch stops the
                // run here, before a single question is answered.
                let report = verify_loaded_corpus(vault, &loaded)?.into_result()?;
                Ok((loaded, report))
            })?;
        exactness.merge(group_exactness);
        offline_runs.push(loaded.offline.clone());

        match &mut dataset_report {
            Some(report) => {
                if report.dataset_id != loaded.report.dataset_id {
                    return Err(invalid_manifest(
                        manifest,
                        "jsonl selected cases must resolve to one dataset id",
                    ));
                }
                report.records_loaded += loaded.report.records_loaded;
                report.text_fields_indexed += loaded.report.text_fields_indexed;
                report.pending_vectors += loaded.report.pending_vectors;
                report.base_vaults += 1;
            }
            None => {
                dataset_report = Some(loaded.report.clone());
                fixture_id = Some(loaded.fixture_id.clone());
                fixture_description = Some(loaded.fixture_description.clone());
            }
        }

        for case_id in &case_ids {
            let fork = base.fork(case_id)?;
            secrets_seen.insert(secrets_label(fork.secrets));
            if let Some(report) = &mut dataset_report {
                report.forks += 1;
            }
            let mut single_case_manifest = manifest.clone();
            single_case_manifest.case_ids = vec![case_id.clone()];
            let record = loaded
                .contract_records
                .get(case_id)
                .ok_or_else(|| invalid_manifest(manifest, "case lost its record"))?;
            for budget in &budgets {
                let tokens = budget.map(|label| label.tokens().unwrap_or(FULL_BUDGET_TOKENS));
                let (case_reports, rows) =
                    run_loaded_cases_at(&fork.vault, &single_case_manifest, &loaded, tokens)?;
                for mut case in case_reports {
                    case.fork_key = Some(fork.fork_key.clone());
                    case.budget_label = budget.map(BudgetLabel::label);
                    let label =
                        budget.map_or_else(|| BudgetLabel::Tokens(case.token_budget), |b| b);
                    let question_observations = retrieval_observations(
                        &case,
                        record,
                        &loaded,
                        label,
                        price.as_ref(),
                    )
                    .into_iter()
                    .chain([full_context_observation(record, label, price.as_ref())]);
                    observations.extend(question_observations.map(|mut observation| {
                        observation.secrets = Some(fork.secrets);
                        observation
                    }));
                    cases_by_id
                        .entry(case.case_id.clone())
                        .or_default()
                        .push(case);
                }
                rows_by_id.entry(case_id.clone()).or_default().extend(rows);
            }
        }
    }

    // Report and packs.jsonl keep manifest order, whatever the corpus grouping.
    let mut cases = Vec::with_capacity(manifest.case_ids.len());
    let mut pack_rows = Vec::new();
    for case_id in &manifest.case_ids {
        if let Some(mut swept) = cases_by_id.remove(case_id) {
            cases.append(&mut swept);
        }
        if let Some(mut rows) = rows_by_id.remove(case_id) {
            pack_rows.append(&mut rows);
        }
    }

    let mut offline = super::model_usage::sum_costs(&offline_runs)?;
    let n = manifest.case_ids.len().max(1) as u64;
    offline.input_tokens = offline.input_tokens.div_ceil(n);
    offline.output_tokens = offline.output_tokens.div_ceil(n);
    offline.target_tokens = offline.target_tokens.div_ceil(n);
    offline.reprefill_tokens = offline.reprefill_tokens.div_ceil(n);
    offline.elapsed_us = offline.elapsed_us.div_ceil(n);
    offline.cost_usd /= n as f64;
    for case in &mut cases {
        case.offline_amortized_cost = offline.clone();
        for competitor in case
            .competitors
            .iter_mut()
            .chain(&mut case.appendix)
            .chain(&mut case.dropped)
        {
            competitor.costs.offline = offline.clone();
            competitor.costs.total_cost_usd = competitor.costs.query.cost_usd
                + offline.cost_usd
                + competitor.costs.judge.cost_usd;
        }
    }

    if let Some(outputs) = &manifest.outputs {
        write_contract_pack_rows(&outputs.packs_jsonl, &pack_rows)?;
    }

    let mut report = BeamReport {
        schema_version: SCHEMA_VERSION,
        run_id: manifest.run_id.clone(),
        fixture_id: fixture_id.unwrap_or_else(|| "jsonl".to_owned()),
        fixture_description: fixture_description
            .unwrap_or_else(|| "oneiron-eval run.jsonl".to_owned()),
        dataset: dataset_report.expect("validated manifest has at least one case"),
        scorer: scorer.metadata(),
        report_format,
        ppr_vad_sweep: ppr_vad_sweep_report(&cases),
        cases,
        exactness: None,
        card: None,
        results: Vec::new(),
    };
    let mut card = build_card(CardInputs {
        manifest,
        run_jsonl: path,
        records: &summaries,
        scorer: &report.scorer,
        exactness: &exactness,
        judges: manifest_judges(manifest),
        answerers: Vec::new(),
        cost: report_arm_costs(&report),
        budgets: budgets
            .iter()
            .map(|budget| budget.map_or_else(|| "record".to_owned(), BudgetLabel::label))
            .collect(),
        references: vec![CONTEXT_ROT],
    })?;
    card.pins.secrets = secrets_seen.into_iter().map(str::to_owned).collect();
    let results_root = manifest
        .outputs
        .as_ref()
        .and_then(|outputs| outputs.results_root.as_deref());
    if let Some(root) = results_root {
        card.result_dir = Some(result_dir(root, &card));
    }
    report.results = aggregate(
        &RowContext {
            producer: "oneiron-bench beam run".to_owned(),
            run_id: manifest.run_id.clone(),
            commit: card.identity.commit.clone(),
            set: card.identity.set.clone(),
            set_revision: card.identity.dataset_revision.clone(),
            tier: card.identity.tier.clone(),
            split: card.identity.split.label.clone(),
        },
        &observations,
    );
    if let Some(path) = &sweep.results_path {
        write_rows(path, &report.results)?;
    }
    report.card = Some(card);
    report.exactness = Some(exactness);
    if let (Some(card), Some(exactness)) = (&report.card, &report.exactness)
        && let Some(dir) = &card.result_dir
    {
        write_result_folder(
            dir,
            card,
            &report,
            exactness,
            manifest.outputs.as_ref().map(|o| o.packs_jsonl.as_path()),
            &report.results,
        )?;
    }
    Ok(report)
}
/// Selected records grouped by vault unit, in first-appearance order. Each
/// group carries its corpus identity: the corpus_ref sha256, or the inline
/// corpus digest for a v1-style per-question corpus.
pub(super) fn group_by_corpus(entries: Vec<RunJsonlEntry>) -> Vec<(String, Vec<RunJsonlEntry>)> {
    let mut order: Vec<String> = Vec::new();
    let mut groups: BTreeMap<String, (String, Vec<RunJsonlEntry>)> = BTreeMap::new();
    for entry in entries {
        let key = entry.record.corpus_key();
        let identity = entry.record.corpus_ref.as_ref().map_or_else(
            || contract_corpus_digest(&entry.record),
            |corpus_ref| format!("{}:sha256:{}", corpus_ref.corpus_id, corpus_ref.sha256),
        );
        groups
            .entry(key.clone())
            .or_insert_with(|| {
                order.push(key.clone());
                (identity, Vec::new())
            })
            .1
            .push(entry);
    }
    order
        .into_iter()
        .filter_map(|key| groups.remove(&key))
        .collect()
}
pub(super) fn run_loaded_cases(
    vault: &Vault,
    manifest: &RunManifest,
    loaded: &LoadedDataset,
) -> BeamResult<(Vec<CaseReport>, Vec<ContextPackContractRecord>)> {
    run_loaded_cases_at(vault, manifest, loaded, None)
}
/// [`run_loaded_cases`] with every case's token budget replaced by `budget`
/// (one point of a budget sweep).
pub(super) fn run_loaded_cases_at(
    vault: &Vault,
    manifest: &RunManifest,
    loaded: &LoadedDataset,
    budget: Option<usize>,
) -> BeamResult<(Vec<CaseReport>, Vec<ContextPackContractRecord>)> {
    let scorer = FixedBeamScorer;
    let cases_by_id: BTreeMap<&str, &FixtureCase> = loaded
        .cases
        .iter()
        .map(|case| (case.case_id.as_str(), case))
        .collect();

    let mut cases = Vec::with_capacity(manifest.case_ids.len());
    let mut pack_rows = Vec::new();
    for case_id in &manifest.case_ids {
        let case = cases_by_id
            .get(case_id.as_str())
            .ok_or_else(|| BeamError::MissingCase {
                fixture_id: loaded.fixture_id.clone(),
                case_id: case_id.clone(),
            })?;
        let mut swept = (*case).clone();
        if let Some(budget) = budget {
            swept.token_budget = budget;
        }
        let case = &swept;
        let mut arms = Vec::with_capacity(manifest.competitors.len());
        let mut competitors = Vec::with_capacity(manifest.competitors.len());
        for competitor in &manifest.competitors {
            let card = competitor
                .card
                .as_ref()
                .ok_or_else(|| BeamError::UncardedCompetitor {
                    run_id: manifest.run_id.clone(),
                    competitor_id: competitor.competitor_id.clone(),
                })?;
            if card.axes.retrieval_k != case.limit {
                return Err(invalid_manifest(
                    manifest,
                    "card retrieval_k differs from the case runtime limit",
                ));
            }
            let arm_report = adapter_for(competitor.arm).run(vault, loaded, case)?;
            if let Some(row) =
                contract_context_pack_record(manifest, loaded, case, competitor, &arm_report)?
            {
                pack_rows.push(row);
            }
            let scoring = scorer.score(case, competitor, &arm_report);
            arms.push(arm_report);
            let mut costs = cost_breakdown(case, arms.last().expect("arm just pushed"));
            costs.offline = amortized_load(loaded, manifest.case_ids.len());
            costs.total_cost_usd =
                costs.query.cost_usd + costs.offline.cost_usd + costs.judge.cost_usd;
            competitors.push(CompetitorReport {
                citation_disposition: card.axes.disposition(),
                competitor_id: competitor.competitor_id.clone(),
                arm: competitor.arm,
                card: card.clone(),
                costs,
                scoring,
            });
        }
        let (competitors, appendix, dropped) = partition_competitors(competitors);
        cases.push(CaseReport {
            case_id: case.case_id.clone(),
            query: case.query.clone(),
            limit: case.limit,
            token_budget: case.token_budget,
            expected_min_results: case.expected_min_results,
            fixture_class: case.fixture_class,
            fork_key: None,
            budget_label: budget.map(|tokens| tokens.to_string()),
            offline_amortized_cost: amortized_load(loaded, manifest.case_ids.len()),
            arms,
            competitors,
            appendix,
            dropped,
        });
    }

    Ok((cases, pack_rows))
}

fn partition_competitors(
    rows: Vec<CompetitorReport>,
) -> (
    Vec<CompetitorReport>,
    Vec<CompetitorReport>,
    Vec<CompetitorReport>,
) {
    use super::comparability::CitationDisposition;
    let (mut main, mut appendix, mut dropped) = (Vec::new(), Vec::new(), Vec::new());
    for row in rows {
        match row.citation_disposition {
            CitationDisposition::Cite | CitationDisposition::CiteWithCaveat => main.push(row),
            CitationDisposition::WalledAppendix => appendix.push(row),
            CitationDisposition::Dropped => dropped.push(row),
        }
    }
    (main, appendix, dropped)
}

fn amortized_load(
    loaded: &LoadedDataset,
    questions: usize,
) -> super::report_model::CostComponentReport {
    let mut cost = loaded.offline.clone();
    let n = questions.max(1) as u64;
    cost.input_tokens = cost.input_tokens.div_ceil(n);
    cost.elapsed_us = cost.elapsed_us.div_ceil(n);
    cost.output_tokens = cost.output_tokens.div_ceil(n);
    cost.target_tokens = cost.target_tokens.div_ceil(n);
    cost.reprefill_tokens = cost.reprefill_tokens.div_ceil(n);
    cost.cost_usd /= n as f64;
    cost
}

/// One observation per completed or refused retrieval arm of a case.
fn retrieval_observations(
    case: &CaseReport,
    record: &super::report_model::RunContractRecord,
    loaded: &LoadedDataset,
    budget: BudgetLabel,
    price: Option<&PriceStamp>,
) -> Vec<Observation> {
    use super::report_model::ArmOutcome;
    let question_tokens = oneiron::count_context_pack_tokens(&record.question) as f64;
    case.arms
        .iter()
        .filter_map(|arm| {
            let approach = match arm.arm {
                ArmKind::Deterministic => "oneiron-deterministic",
                ArmKind::VanillaRag => "vanilla-rag",
                _ => return None,
            };
            let (ids, prompt, latency, refused) = match &arm.outcome {
                ArmOutcome::Completed { context_pack } => {
                    let ids: Vec<String> = context_pack
                        .results
                        .iter()
                        .chain(&context_pack.neighbors)
                        .map(|entity| {
                            loaded
                                .source_id_by_entity_id
                                .get(&entity.id)
                                .cloned()
                                .unwrap_or_else(|| entity.id.clone())
                        })
                        .collect();
                    (
                        ids,
                        question_tokens + context_pack.serialized_tokens as f64,
                        Some(context_pack.query_cost.elapsed_us as f64 / 1000.0),
                        false,
                    )
                }
                ArmOutcome::NotReady { .. } => (Vec::new(), question_tokens, None, true),
                ArmOutcome::RetrievalSweep { .. } => return None,
            };
            Some(Observation {
                approach: approach.to_owned(),
                approach_kind: "retrieval",
                reader_model: None,
                budget: budget.tokens(),
                budget_label: budget.label(),
                rot: false,
                groups: groups_for(record),
                metrics: evidence_metrics(record, &ids),
                refused,
                prompt_tokens: prompt,
                reprefill_tokens: 0.0,
                output_tokens: 0.0,
                judge_tokens: 0.0,
                usd: price.map(|stamp| stamp.usd(prompt, 0.0)),
                price: price.cloned(),
                latency_ms: latency,
                secrets: None,
            })
        })
        .collect()
}
