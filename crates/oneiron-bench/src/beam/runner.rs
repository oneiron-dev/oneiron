//! Subcommand run entry points and orchestration.

use super::arms::adapter_for;
use super::load::{
    contract_context_pack_record, load_dataset, resolve_manifest_paths, write_contract_pack_rows,
};
use super::model::{ArmKind, BeamFixture, DatasetSource, FixtureCase, RunManifest, SchemaHeader};
use super::ppr_vad::ppr_vad_sweep_report;
use super::report::{cost_breakdown, cost_component_from_input};
use super::report_model::{
    BeamReport, CaseReport, CompetitorReport, ContextPackContractRecord, DatasetLoadReport,
    LoadedDataset,
};
use super::scorer::{BeamScorer, FixedBeamScorer};
use super::util::{beam_vault_config, invalid_manifest, report_format_label};
use super::validate::{
    validate_fixture, validate_manifest, validate_manifest_fixture_cases, validate_manifest_paths,
};
use super::{
    BEAM_128K_TOKEN_BUDGET, BUILTIN_FIXTURE_JSON, BUILTIN_MANIFEST_JSON, BeamError, BeamResult,
    SCHEMA_VERSION,
};
use oneiron::Vault;
use std::collections::BTreeMap;
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
                           run <manifest>\n\
                                    run a BEAM manifest; fixture datasets load dataset.path JSON\n\
                                    relative to the manifest; emit declared packs.jsonl outputs\n\
                           trace-export\n\
                                    export RetrievalTrace records to JSONL by fork hash (ONE-1311)";
pub(crate) fn run_manifest_path(path: &Path) -> BeamResult<BeamReport> {
    let manifest_json = std::fs::read_to_string(path)?;
    let mut manifest = parse_manifest_json(&manifest_json)?;
    resolve_manifest_paths(&mut manifest, path);
    let fixture = match &manifest.dataset {
        DatasetSource::Fixture {
            path: Some(path), ..
        } => Some(parse_fixture_json(&std::fs::read_to_string(path)?)?),
        _ => None,
    };
    run_manifest(&manifest, fixture.as_ref())
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
    validate_manifest(manifest)?;
    validate_manifest_paths(manifest)?;
    if let (DatasetSource::Fixture { .. }, Some(fixture)) = (&manifest.dataset, fixture) {
        validate_manifest_fixture_cases(manifest, fixture)?;
    }

    if matches!(manifest.dataset, DatasetSource::Jsonl { .. }) {
        return run_jsonl_manifest_isolated(manifest);
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
    })
}
pub(super) fn run_jsonl_manifest_isolated(manifest: &RunManifest) -> BeamResult<BeamReport> {
    let scorer = FixedBeamScorer;
    let report_format = report_format_label(manifest.report.format).to_owned();
    let mut dataset_report: Option<DatasetLoadReport> = None;
    let mut fixture_id: Option<String> = None;
    let mut fixture_description: Option<String> = None;
    let mut cases = Vec::with_capacity(manifest.case_ids.len());
    let mut pack_rows = Vec::new();

    for case_id in &manifest.case_ids {
        let tempdir = tempfile::tempdir()?;
        let vault = Vault::open(tempdir.path(), beam_vault_config())?;
        let mut single_case_manifest = manifest.clone();
        single_case_manifest.case_ids = vec![case_id.clone()];
        let loaded = load_dataset(&vault, &single_case_manifest, None)?;

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
            }
            None => {
                dataset_report = Some(loaded.report.clone());
                fixture_id = Some(loaded.fixture_id.clone());
                fixture_description = Some(loaded.fixture_description.clone());
            }
        }

        let (mut case_reports, mut rows) =
            run_loaded_cases(&vault, &single_case_manifest, &loaded)?;
        cases.append(&mut case_reports);
        pack_rows.append(&mut rows);
    }

    if let Some(outputs) = &manifest.outputs {
        write_contract_pack_rows(&outputs.packs_jsonl, &pack_rows)?;
    }

    Ok(BeamReport {
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
    })
}
pub(super) fn run_loaded_cases(
    vault: &Vault,
    manifest: &RunManifest,
    loaded: &LoadedDataset,
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
            let arm_report = adapter_for(competitor.arm).run(vault, loaded, case)?;
            if let Some(row) =
                contract_context_pack_record(manifest, loaded, case, competitor, &arm_report)?
            {
                pack_rows.push(row);
            }
            let scoring = scorer.score(case, competitor, &arm_report);
            arms.push(arm_report);
            let costs = cost_breakdown(case, arms.last().expect("arm just pushed"));
            competitors.push(CompetitorReport {
                competitor_id: competitor.competitor_id.clone(),
                arm: competitor.arm,
                card: card.clone(),
                costs,
                scoring,
            });
        }
        cases.push(CaseReport {
            case_id: case.case_id.clone(),
            query: case.query.clone(),
            limit: case.limit,
            token_budget: case.token_budget,
            expected_min_results: case.expected_min_results,
            fixture_class: case.fixture_class,
            offline_amortized_cost: cost_component_from_input(&case.offline_amortized_cost),
            arms,
            competitors,
        });
    }

    Ok((cases, pack_rows))
}
