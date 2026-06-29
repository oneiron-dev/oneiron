//! BEAM scaffold for EVAL-001.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::PathBuf;
use std::process::ExitCode;

use oneiron::{
    ContextPack, ContextPackBuilder, EmptyReason, EntityId, FieldProfile, PackFormat, Signal,
    TimeRange, Vault, VaultConfig,
};
use serde::{Deserialize, Serialize};

pub(crate) const BEAM_128K_TOKEN_BUDGET: usize = 128 * 1024;

const SCHEMA_VERSION: u32 = 1;
const BEAM_CONTEXT_PACK_FORMAT: PackFormat = PackFormat::Yaml;
const BUILTIN_FIXTURE_JSON: &str = include_str!("../fixtures/beam_128k_smoke.fixture.json");
const BUILTIN_MANIFEST_JSON: &str = include_str!("../fixtures/beam_128k_smoke.run.json");

type BeamResult<T> = Result<T, BeamError>;

#[derive(Debug, thiserror::Error)]
pub(crate) enum BeamError {
    #[error("unsupported BEAM schema version {actual}; expected {expected}")]
    UnsupportedSchemaVersion { expected: u32, actual: u32 },
    #[error("invalid BEAM fixture `{fixture_id}`: {reason}")]
    InvalidFixture { fixture_id: String, reason: String },
    #[error("invalid BEAM run manifest `{run_id}`: {reason}")]
    InvalidManifest { run_id: String, reason: String },
    #[error("invalid entity id `{id}`: {source}")]
    InvalidEntityId { id: String, source: oneiron::Error },
    #[error("fixture `{fixture_id}` does not match manifest dataset `{manifest_fixture_id}`")]
    FixtureMismatch {
        fixture_id: String,
        manifest_fixture_id: String,
    },
    #[error("manifest case `{case_id}` was not found in fixture `{fixture_id}`")]
    MissingCase { fixture_id: String, case_id: String },
    #[error("dataset loader is not ready: {0}")]
    DatasetNotReady(NotReadyState),
    #[error(
        "deterministic arm returned {actual} results for case `{case_id}`; expected at least {expected}"
    )]
    DeterministicExpectation {
        case_id: String,
        expected: usize,
        actual: usize,
    },
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("messagepack encode error: {0}")]
    MessagePackEncode(#[from] rmp_serde::encode::Error),
    #[error("oneiron engine error: {0}")]
    Oneiron(#[from] oneiron::Error),
    #[error("budgeted deterministic context pack serialization was not UTF-8: {0}")]
    BudgetedContextPackUtf8(#[from] std::str::Utf8Error),
    #[error("temporary vault error: {0}")]
    TempVault(#[from] std::io::Error),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BeamFixture {
    schema_version: u32,
    fixture_id: String,
    description: String,
    records: Vec<FixtureRecord>,
    cases: Vec<FixtureCase>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FixtureRecord {
    id: String,
    entity_type: u8,
    occurred: FixtureTimeRange,
    learned_at: u64,
    #[serde(default = "empty_fields")]
    fields: serde_json::Value,
    #[serde(default)]
    text: Vec<TextField>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FixtureTimeRange {
    start: u64,
    end: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TextField {
    field: String,
    value: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FixtureCase {
    case_id: String,
    query: String,
    limit: usize,
    token_budget: usize,
    expected_min_results: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RunManifest {
    schema_version: u32,
    run_id: String,
    dataset: DatasetSource,
    case_ids: Vec<String>,
    arms: Vec<ArmKind>,
    report: ReportConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum DatasetSource {
    Fixture { fixture_id: String },
    Jsonl { path: PathBuf },
    Miracl { dataset: String },
    MrTydi { dataset: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ArmKind {
    Deterministic,
    Agentic,
    Chat,
}

impl ArmKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Deterministic => "deterministic",
            Self::Agentic => "agentic",
            Self::Chat => "chat",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReportConfig {
    format: ReportFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReportFormat {
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NotReadyState {
    component: String,
    reason: String,
    retryable: bool,
}

impl std::fmt::Display for NotReadyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} not ready: {}", self.component, self.reason)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BeamReport {
    schema_version: u32,
    run_id: String,
    fixture_id: String,
    fixture_description: String,
    dataset: DatasetLoadReport,
    report_format: String,
    cases: Vec<CaseReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct DatasetLoadReport {
    dataset_id: String,
    source_kind: String,
    records_loaded: usize,
    text_fields_indexed: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CaseReport {
    case_id: String,
    query: String,
    limit: usize,
    token_budget: usize,
    expected_min_results: usize,
    arms: Vec<ArmReport>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ArmReport {
    arm: ArmKind,
    outcome: ArmOutcome,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(
    tag = "status",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum ArmOutcome {
    Completed { context_pack: ContextPackReport },
    NotReady { not_ready: NotReadyState },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ContextPackReport {
    token_budget: usize,
    limit: usize,
    serialized_format: String,
    serialized_bytes: usize,
    result_count: usize,
    neighbor_count: usize,
    results: Vec<ContextEntityReport>,
    neighbors: Vec<ContextEntityReport>,
    stats: PackStatsReport,
    empty: Option<EmptyContextReport>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ContextEntityReport {
    id: String,
    short_id: String,
    entity_type: u8,
    score: f32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct PackStatsReport {
    candidates_considered: usize,
    signals_used: Vec<String>,
    query_time_us: u64,
    entities_hydrated: usize,
    neighbors_hydrated: usize,
    cosine_ghosts_dampened: usize,
    claims_suppressed: usize,
    items_truncated: usize,
    items_dropped: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct EmptyContextReport {
    reason: String,
    total_in_scope: usize,
    hint: String,
}

trait BeamArmAdapter {
    fn kind(&self) -> ArmKind;
    fn run(&self, vault: &Vault, case: &FixtureCase) -> BeamResult<ArmReport>;
}

struct DeterministicContextPackArm;

impl BeamArmAdapter for DeterministicContextPackArm {
    fn kind(&self) -> ArmKind {
        ArmKind::Deterministic
    }

    fn run(&self, vault: &Vault, case: &FixtureCase) -> BeamResult<ArmReport> {
        let pack = run_deterministic_context_pack(vault, case)?;
        let report = context_pack_report(&pack, case);

        if report.result_count < case.expected_min_results {
            return Err(BeamError::DeterministicExpectation {
                case_id: case.case_id.clone(),
                expected: case.expected_min_results,
                actual: report.result_count,
            });
        }

        Ok(ArmReport {
            arm: self.kind(),
            outcome: ArmOutcome::Completed {
                context_pack: report,
            },
        })
    }
}

struct NotReadyArm {
    kind: ArmKind,
}

impl BeamArmAdapter for NotReadyArm {
    fn kind(&self) -> ArmKind {
        self.kind
    }

    fn run(&self, _vault: &Vault, _case: &FixtureCase) -> BeamResult<ArmReport> {
        Ok(ArmReport {
            arm: self.kind,
            outcome: ArmOutcome::NotReady {
                not_ready: arm_not_ready(self.kind),
            },
        })
    }
}

pub(crate) fn run(args: &[String]) -> ExitCode {
    match args {
        [] => {
            print_help();
            ExitCode::SUCCESS
        }
        [sub] if sub == "smoke" => match run_builtin_smoke()
            .and_then(|report| serde_json::to_string_pretty(&report).map_err(BeamError::from))
        {
            Ok(report_json) => {
                println!("{report_json}");
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("BEAM smoke failed: {err}");
                ExitCode::FAILURE
            }
        },
        [sub] => {
            eprintln!("unknown BEAM subcommand: {sub}");
            print_help();
            ExitCode::FAILURE
        }
        other => {
            eprintln!("unknown BEAM invocation: {other:?}");
            print_help();
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!("{BEAM_HELP}");
}

pub(crate) fn run_builtin_smoke() -> BeamResult<BeamReport> {
    let fixture = parse_fixture_json(BUILTIN_FIXTURE_JSON)?;
    let manifest = parse_manifest_json(BUILTIN_MANIFEST_JSON)?;
    ensure_manifest_selects_128k_case(&manifest, &fixture)?;
    run_fixture_manifest(&manifest, &fixture)
}

const BEAM_HELP: &str = "usage: oneiron-bench beam <subcommand>\n\
                         \n\
                         subcommands:\n\
                           smoke    run the built-in BEAM 128K deterministic context-pack smoke fixture\n\
                                    aligned with ONEIRON-ARCH-0042";

fn ensure_manifest_selects_128k_case(
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
    let manifest: RunManifest = serde_json::from_str(json)?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

pub(crate) fn run_fixture_manifest(
    manifest: &RunManifest,
    fixture: &BeamFixture,
) -> BeamResult<BeamReport> {
    let tempdir = tempfile::tempdir()?;
    let vault = Vault::open(tempdir.path(), beam_vault_config())?;
    let dataset = load_dataset(&vault, manifest, fixture)?;
    let cases_by_id: BTreeMap<&str, &FixtureCase> = fixture
        .cases
        .iter()
        .map(|case| (case.case_id.as_str(), case))
        .collect();
    let report_format = report_format_label(manifest.report.format).to_owned();

    let mut cases = Vec::with_capacity(manifest.case_ids.len());
    for case_id in &manifest.case_ids {
        let case = cases_by_id
            .get(case_id.as_str())
            .ok_or_else(|| BeamError::MissingCase {
                fixture_id: fixture.fixture_id.clone(),
                case_id: case_id.clone(),
            })?;
        let mut arms = Vec::with_capacity(manifest.arms.len());
        for arm in &manifest.arms {
            arms.push(adapter_for(*arm).run(&vault, case)?);
        }
        cases.push(CaseReport {
            case_id: case.case_id.clone(),
            query: case.query.clone(),
            limit: case.limit,
            token_budget: case.token_budget,
            expected_min_results: case.expected_min_results,
            arms,
        });
    }

    Ok(BeamReport {
        schema_version: SCHEMA_VERSION,
        run_id: manifest.run_id.clone(),
        fixture_id: fixture.fixture_id.clone(),
        fixture_description: fixture.description.clone(),
        dataset,
        report_format,
        cases,
    })
}

fn validate_fixture(fixture: &BeamFixture) -> BeamResult<()> {
    if fixture.schema_version != SCHEMA_VERSION {
        return Err(BeamError::UnsupportedSchemaVersion {
            expected: SCHEMA_VERSION,
            actual: fixture.schema_version,
        });
    }
    if fixture.records.is_empty() {
        return Err(invalid_fixture(
            fixture,
            "fixture must contain at least one record",
        ));
    }
    if fixture.cases.is_empty() {
        return Err(invalid_fixture(
            fixture,
            "fixture must contain at least one case",
        ));
    }

    let mut record_ids = BTreeSet::new();
    for record in &fixture.records {
        EntityId::from_hex(&record.id).map_err(|source| BeamError::InvalidEntityId {
            id: record.id.clone(),
            source,
        })?;
        if !record_ids.insert(record.id.as_str()) {
            return Err(invalid_fixture(fixture, "record ids must be unique"));
        }
        if record.occurred.start > record.occurred.end {
            return Err(invalid_fixture(
                fixture,
                "record occurred.start must be <= occurred.end",
            ));
        }
        let field_object = record
            .fields
            .as_object()
            .ok_or_else(|| invalid_fixture(fixture, "record fields must be a JSON object"))?;
        if record.text.iter().any(|field| field.field.is_empty()) {
            return Err(invalid_fixture(
                fixture,
                "text field names must not be empty",
            ));
        }
        if record
            .text
            .iter()
            .any(|field| !field_object.contains_key(field.field.as_str()))
        {
            return Err(invalid_fixture(
                fixture,
                "text fields must reference keys present in record.fields",
            ));
        }
    }

    let mut case_ids = BTreeSet::new();
    for case in &fixture.cases {
        if !case_ids.insert(case.case_id.as_str()) {
            return Err(invalid_fixture(fixture, "case ids must be unique"));
        }
        if case.query.trim().is_empty() {
            return Err(invalid_fixture(fixture, "case query must not be empty"));
        }
        if case.limit == 0 {
            return Err(invalid_fixture(fixture, "case limit must be positive"));
        }
        if case.token_budget == 0 {
            return Err(invalid_fixture(
                fixture,
                "case token budget must be positive",
            ));
        }
        if case.expected_min_results > case.limit {
            return Err(invalid_fixture(
                fixture,
                "expected_min_results must be <= limit",
            ));
        }
    }

    Ok(())
}

fn validate_manifest(manifest: &RunManifest) -> BeamResult<()> {
    if manifest.schema_version != SCHEMA_VERSION {
        return Err(BeamError::UnsupportedSchemaVersion {
            expected: SCHEMA_VERSION,
            actual: manifest.schema_version,
        });
    }
    if manifest.case_ids.is_empty() {
        return Err(invalid_manifest(
            manifest,
            "manifest must request at least one case",
        ));
    }
    if manifest.arms.is_empty() {
        return Err(invalid_manifest(
            manifest,
            "manifest must request at least one arm",
        ));
    }

    let mut case_ids = BTreeSet::new();
    for case_id in &manifest.case_ids {
        if case_id.trim().is_empty() {
            return Err(invalid_manifest(manifest, "case ids must not be empty"));
        }
        if !case_ids.insert(case_id.as_str()) {
            return Err(invalid_manifest(
                manifest,
                "manifest case ids must be unique",
            ));
        }
    }

    let mut arms = BTreeSet::new();
    for arm in &manifest.arms {
        if !arms.insert(arm.as_str()) {
            return Err(invalid_manifest(manifest, "manifest arms must be unique"));
        }
    }

    Ok(())
}

fn load_dataset(
    vault: &Vault,
    manifest: &RunManifest,
    fixture: &BeamFixture,
) -> BeamResult<DatasetLoadReport> {
    match &manifest.dataset {
        DatasetSource::Fixture { fixture_id } => {
            if fixture_id != &fixture.fixture_id {
                return Err(BeamError::FixtureMismatch {
                    fixture_id: fixture.fixture_id.clone(),
                    manifest_fixture_id: fixture_id.clone(),
                });
            }
            load_fixture_dataset(vault, fixture)
        }
        source => Err(BeamError::DatasetNotReady(dataset_not_ready(source))),
    }
}

fn load_fixture_dataset(vault: &Vault, fixture: &BeamFixture) -> BeamResult<DatasetLoadReport> {
    let mut batch = vault.batch();
    let mut text_fields_indexed = 0;
    for record in &fixture.records {
        let id = EntityId::from_hex(&record.id).map_err(|source| BeamError::InvalidEntityId {
            id: record.id.clone(),
            source,
        })?;
        let payload = rmp_serde::to_vec_named(&record.fields)?;
        batch = batch.put(
            &id,
            record.entity_type,
            TimeRange {
                start: record.occurred.start,
                end: record.occurred.end,
            },
            record.learned_at,
            &payload,
        );
        if !record.text.is_empty() {
            let fields: Vec<(&str, &str)> = record
                .text
                .iter()
                .map(|field| (field.field.as_str(), field.value.as_str()))
                .collect();
            text_fields_indexed += fields.len();
            batch = batch.text(&id, &fields);
        }
    }
    batch.commit()?;

    Ok(DatasetLoadReport {
        dataset_id: fixture.fixture_id.clone(),
        source_kind: "fixture".to_owned(),
        records_loaded: fixture.records.len(),
        text_fields_indexed,
    })
}

fn adapter_for(kind: ArmKind) -> Box<dyn BeamArmAdapter> {
    match kind {
        ArmKind::Deterministic => Box::new(DeterministicContextPackArm),
        ArmKind::Agentic | ArmKind::Chat => Box::new(NotReadyArm { kind }),
    }
}

fn configured_context_pack_builder<'a>(
    vault: &'a Vault,
    case: &FixtureCase,
) -> ContextPackBuilder<'a> {
    vault
        .context_pack()
        .search_text(&case.query, case.limit)
        .field_profile(FieldProfile::Standard)
        .format(BEAM_CONTEXT_PACK_FORMAT)
        .merge_neighbors(false)
        .include_stats(true)
        .token_budget(case.token_budget)
}

struct BudgetedContextPack {
    raw: ContextPack,
    serialized: Vec<u8>,
    serialized_ids: SerializedContextPackIds,
}

#[derive(Default)]
struct SerializedContextPackIds {
    results: HashSet<String>,
    neighbors: HashSet<String>,
}

#[derive(Clone, Copy)]
enum SerializedContextPackSection {
    Results,
    Neighbors,
}

struct ActiveSerializedContextPackSection {
    section: SerializedContextPackSection,
    section_indent: usize,
    group_indent: Option<usize>,
}

fn run_deterministic_context_pack(
    vault: &Vault,
    case: &FixtureCase,
) -> BeamResult<BudgetedContextPack> {
    let pack = configured_context_pack_builder(vault, case).run()?;
    let serialized = configured_context_pack_builder(vault, case).run_serialized()?;
    let serialized_text = std::str::from_utf8(&serialized)?;
    let serialized_ids = serialized_context_pack_ids(serialized_text);

    Ok(BudgetedContextPack {
        raw: pack,
        serialized,
        serialized_ids,
    })
}

fn context_pack_report(pack: &BudgetedContextPack, case: &FixtureCase) -> ContextPackReport {
    let results = context_entity_reports_for_ids(&pack.raw.results, &pack.serialized_ids.results);
    let neighbors =
        context_entity_reports_for_ids(&pack.raw.neighbors, &pack.serialized_ids.neighbors);
    let result_count = results.len();
    let neighbor_count = neighbors.len();
    let dropped_by_budget = pack
        .raw
        .results
        .len()
        .saturating_add(pack.raw.neighbors.len())
        .saturating_sub(result_count.saturating_add(neighbor_count));

    ContextPackReport {
        token_budget: case.token_budget,
        limit: case.limit,
        serialized_format: pack_format_label(BEAM_CONTEXT_PACK_FORMAT).to_owned(),
        serialized_bytes: pack.serialized.len(),
        result_count,
        neighbor_count,
        results,
        neighbors,
        stats: PackStatsReport {
            candidates_considered: pack.raw.stats.candidates_considered,
            signals_used: pack
                .raw
                .stats
                .signals_used
                .iter()
                .copied()
                .map(signal_label)
                .map(str::to_owned)
                .collect(),
            query_time_us: pack.raw.stats.query_time_us,
            entities_hydrated: result_count,
            neighbors_hydrated: neighbor_count,
            cosine_ghosts_dampened: pack.raw.stats.cosine_ghosts_dampened,
            claims_suppressed: pack.raw.stats.claims_suppressed,
            items_truncated: pack.raw.stats.items_truncated.count,
            items_dropped: pack
                .raw
                .stats
                .items_dropped
                .count
                .saturating_add(dropped_by_budget),
        },
        empty: pack.raw.empty.as_ref().map(|empty| EmptyContextReport {
            reason: empty_reason_label(empty.reason).to_owned(),
            total_in_scope: empty.total_in_scope,
            hint: empty.hint.clone(),
        }),
    }
}

fn context_entity_reports_for_ids(
    entities: &[oneiron::ContextEntity],
    serialized_ids: &HashSet<String>,
) -> Vec<ContextEntityReport> {
    entities
        .iter()
        .filter(|entity| serialized_ids.contains(&serialized_context_entity_id(entity)))
        .map(context_entity_report)
        .collect()
}

fn context_entity_report(entity: &oneiron::ContextEntity) -> ContextEntityReport {
    ContextEntityReport {
        id: entity.id.to_hex(),
        short_id: entity.short_id.clone(),
        entity_type: entity.entity_type,
        score: entity.score,
    }
}

fn serialized_context_pack_ids(serialized: &str) -> SerializedContextPackIds {
    let mut ids = SerializedContextPackIds::default();
    let mut active_section: Option<ActiveSerializedContextPackSection> = None;

    for line in serialized.lines() {
        let trimmed_start = line.trim_start();
        let trimmed = trimmed_start.trim_end();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - trimmed_start.len();

        if indent == 0 {
            active_section = match trimmed {
                "results:" => Some(ActiveSerializedContextPackSection {
                    section: SerializedContextPackSection::Results,
                    section_indent: indent,
                    group_indent: None,
                }),
                "neighbors:" => Some(ActiveSerializedContextPackSection {
                    section: SerializedContextPackSection::Neighbors,
                    section_indent: indent,
                    group_indent: None,
                }),
                _ => None,
            };
            continue;
        }

        let Some(section) = active_section.as_mut() else {
            continue;
        };
        if indent <= section.section_indent {
            active_section = None;
            continue;
        }
        if section
            .group_indent
            .is_some_and(|group_indent| indent <= group_indent)
        {
            section.group_indent = None;
        }

        if indent == section.section_indent + 2
            && trimmed.ends_with(':')
            && !trimmed.starts_with("- ")
        {
            section.group_indent = Some(indent);
            continue;
        }

        let expected_row_indent = section
            .group_indent
            .map_or(section.section_indent + 2, |group_indent| group_indent + 2);
        if indent != expected_row_indent {
            continue;
        }

        if let Some(raw_id) = trimmed.strip_prefix("- id: ") {
            let id = generated_yaml_scalar(raw_id);
            match section.section {
                SerializedContextPackSection::Results => {
                    ids.results.insert(id);
                }
                SerializedContextPackSection::Neighbors => {
                    ids.neighbors.insert(id);
                }
            }
        }
    }

    ids
}

fn generated_yaml_scalar(raw: &str) -> String {
    let trimmed = raw.trim();
    trimmed
        .strip_prefix('"')
        .and_then(|quoted| quoted.strip_suffix('"'))
        .unwrap_or(trimmed)
        .replace("\\\"", "\"")
        .replace("\\\\", "\\")
}

fn serialized_context_entity_id(entity: &oneiron::ContextEntity) -> String {
    let short_id = if entity.short_id.is_empty() {
        entity.id.to_hex()
    } else {
        entity.short_id.clone()
    };
    format!("{}:{:02x}", short_id, entity.content_hash)
}

fn arm_not_ready(kind: ArmKind) -> NotReadyState {
    NotReadyState {
        component: format!("{} arm", kind.as_str()),
        reason: "adapter intentionally not implemented in EVAL-001 scaffold".to_owned(),
        retryable: false,
    }
}

fn dataset_not_ready(source: &DatasetSource) -> NotReadyState {
    NotReadyState {
        component: "dataset loader".to_owned(),
        reason: format!(
            "{} datasets are declared in the schema but not implemented in EVAL-001",
            dataset_source_description(source)
        ),
        retryable: false,
    }
}

fn beam_vault_config() -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 32 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.max_readers = 16;
    cfg
}

fn invalid_fixture(fixture: &BeamFixture, reason: impl Into<String>) -> BeamError {
    BeamError::InvalidFixture {
        fixture_id: fixture.fixture_id.clone(),
        reason: reason.into(),
    }
}

fn invalid_manifest(manifest: &RunManifest, reason: impl Into<String>) -> BeamError {
    BeamError::InvalidManifest {
        run_id: manifest.run_id.clone(),
        reason: reason.into(),
    }
}

fn empty_fields() -> serde_json::Value {
    serde_json::json!({})
}

fn dataset_source_description(source: &DatasetSource) -> String {
    match source {
        DatasetSource::Fixture { fixture_id } => format!("fixture `{fixture_id}`"),
        DatasetSource::Jsonl { path } => format!("jsonl `{}`", path.display()),
        DatasetSource::Miracl { dataset } => format!("miracl `{dataset}`"),
        DatasetSource::MrTydi { dataset } => format!("mr_tydi `{dataset}`"),
    }
}

fn report_format_label(format: ReportFormat) -> &'static str {
    match format {
        ReportFormat::Json => "json",
    }
}

fn pack_format_label(format: PackFormat) -> &'static str {
    match format {
        PackFormat::Json => "json",
        PackFormat::Yaml => "yaml",
        PackFormat::Toon => "toon",
        PackFormat::Markdown => "markdown",
        PackFormat::Plaintext => "plaintext",
        _ => "unknown",
    }
}

fn signal_label(signal: Signal) -> &'static str {
    match signal {
        Signal::Vector => "vector",
        Signal::Text => "text",
        Signal::Phonetic => "phonetic",
        Signal::Temporal => "temporal",
        Signal::Ppr => "ppr",
        _ => "unknown",
    }
}

fn empty_reason_label(reason: EmptyReason) -> &'static str {
    match reason {
        EmptyReason::FilterMatchedNone => "filter_matched_none",
        EmptyReason::NoData => "no_data",
        EmptyReason::AllActivated => "all_activated",
        EmptyReason::BelowThreshold => "below_threshold",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_fixture_and_manifest_accepts_beam_128k_smoke_schema() {
        let fixture = parse_fixture_json(BUILTIN_FIXTURE_JSON).expect("fixture parses");
        let manifest = parse_manifest_json(BUILTIN_MANIFEST_JSON).expect("manifest parses");

        assert_eq!(fixture.fixture_id, "beam-128k-smoke");
        assert_eq!(fixture.cases[0].token_budget, BEAM_128K_TOKEN_BUDGET);
        ensure_manifest_selects_128k_case(&manifest, &fixture)
            .expect("manifest selects the 128K smoke case");
        assert_eq!(
            manifest.arms,
            vec![ArmKind::Deterministic, ArmKind::Agentic, ArmKind::Chat]
        );
    }

    #[test]
    fn fixture_validation_requires_fields_object() {
        let mut fixture_json: serde_json::Value =
            serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
        fixture_json["records"][0]["fields"] = serde_json::json!(["body"]);
        let err = parse_fixture_json(&fixture_json.to_string())
            .expect_err("fixture fields must be object");

        assert!(
            err.to_string()
                .contains("record fields must be a JSON object")
        );
    }

    #[test]
    fn fixture_validation_rejects_text_field_missing_from_fields() {
        let mut fixture_json: serde_json::Value =
            serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
        fixture_json["records"][0]["text"][0]["field"] = serde_json::json!("missing");
        let err = parse_fixture_json(&fixture_json.to_string())
            .expect_err("text field must reference stored field");

        assert!(
            err.to_string()
                .contains("text fields must reference keys present in record.fields")
        );
    }

    #[test]
    fn manifest_validation_rejects_duplicate_arms() {
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(BUILTIN_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["arms"] = serde_json::json!(["deterministic", "deterministic"]);
        let err = parse_manifest_json(&manifest_json.to_string())
            .expect_err("duplicate arms must be rejected");

        assert!(err.to_string().contains("manifest arms must be unique"));
    }

    #[test]
    fn deterministic_arm_exercises_serialized_128k_budget_path() {
        let fixture = parse_fixture_json(BUILTIN_FIXTURE_JSON).expect("fixture parses");
        let manifest = parse_manifest_json(BUILTIN_MANIFEST_JSON).expect("manifest parses");
        let tempdir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(tempdir.path(), beam_vault_config()).expect("vault opens");
        load_dataset(&vault, &manifest, &fixture).expect("fixture loads");

        let pack =
            run_deterministic_context_pack(&vault, &fixture.cases[0]).expect("deterministic run");
        let serialized_text =
            std::str::from_utf8(&pack.serialized).expect("serialized context pack is UTF-8");

        assert_eq!(fixture.cases[0].token_budget, BEAM_128K_TOKEN_BUDGET);
        assert!(pack.raw.results.len() >= fixture.cases[0].expected_min_results);
        assert!(!pack.serialized.is_empty());
        assert!(serialized_text.contains("results:"));
        assert!(
            pack.serialized_ids
                .results
                .iter()
                .any(|id| id.starts_with("sm"))
        );
    }

    #[test]
    fn serialized_context_pack_ids_ignore_nested_yaml_id_fields() {
        let serialized = r#"
results:
  memory:
    - id: result:01
      title: kept
      nested:
        - id: dropped-result:02
neighbors:
  memory:
    - id: neighbor:03
      nested:
        - id: dropped-neighbor:04
"#;

        let ids = serialized_context_pack_ids(serialized);

        assert_eq!(ids.results, HashSet::from(["result:01".to_owned()]));
        assert_eq!(ids.neighbors, HashSet::from(["neighbor:03".to_owned()]));
    }

    #[test]
    fn deterministic_arm_reports_budgeted_pack_when_token_budget_drops_rows() {
        let mut fixture = parse_fixture_json(BUILTIN_FIXTURE_JSON).expect("fixture parses");
        let manifest = parse_manifest_json(BUILTIN_MANIFEST_JSON).expect("manifest parses");
        for (offset, id) in [
            "30303030303030303030303030303030",
            "40404040404040404040404040404040",
            "50505050505050505050505050505050",
        ]
        .into_iter()
        .enumerate()
        {
            let mut record = fixture.records[0].clone();
            record.id = id.to_owned();
            record.occurred.start = 3 + offset as u64;
            record.occurred.end = 3 + offset as u64;
            record.learned_at = 3 + offset as u64;
            fixture.records.push(record);
        }
        fixture.cases[0].token_budget = 1;
        fixture.cases[0].expected_min_results = 0;
        let tempdir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(tempdir.path(), beam_vault_config()).expect("vault opens");
        load_dataset(&vault, &manifest, &fixture).expect("fixture loads");
        let raw_pack = configured_context_pack_builder(&vault, &fixture.cases[0])
            .run()
            .expect("raw context pack");

        let arm = DeterministicContextPackArm
            .run(&vault, &fixture.cases[0])
            .expect("deterministic arm reports");
        let ArmOutcome::Completed { context_pack } = arm.outcome else {
            panic!("deterministic arm should complete");
        };

        assert_eq!(context_pack.serialized_format, "yaml");
        assert!(raw_pack.results.len() > context_pack.result_count);
        assert!(context_pack.stats.items_dropped > 0);
    }

    #[test]
    fn deterministic_arm_runs_beam_128k_fixture_end_to_end() {
        let report = run_builtin_smoke().expect("BEAM smoke report");
        let deterministic = find_arm(&report, ArmKind::Deterministic);

        let ArmOutcome::Completed { context_pack } = &deterministic.outcome else {
            panic!("deterministic arm should complete");
        };
        assert_eq!(context_pack.token_budget, BEAM_128K_TOKEN_BUDGET);
        assert!(context_pack.result_count >= 1);
        assert!(
            context_pack
                .results
                .iter()
                .any(|entity| { entity.id == "10101010101010101010101010101010" })
        );
    }

    #[test]
    fn report_arm_outcome_payload_uses_camel_case_fields() {
        let report = run_builtin_smoke().expect("BEAM smoke report");
        let report_json = serde_json::to_value(&report).expect("report serializes");
        let arms = report_json["cases"][0]["arms"]
            .as_array()
            .expect("arms array");
        let deterministic = arms
            .iter()
            .find(|arm| arm["arm"] == "deterministic")
            .expect("deterministic arm");
        let agentic = arms
            .iter()
            .find(|arm| arm["arm"] == "agentic")
            .expect("agentic arm");

        assert!(deterministic["outcome"].get("contextPack").is_some());
        assert!(deterministic["outcome"].get("context_pack").is_none());
        assert!(agentic["outcome"].get("notReady").is_some());
        assert!(agentic["outcome"].get("not_ready").is_none());
    }

    #[test]
    fn built_in_128k_guard_checks_manifest_selected_cases() {
        let mut fixture = parse_fixture_json(BUILTIN_FIXTURE_JSON).expect("fixture parses");
        let mut manifest = parse_manifest_json(BUILTIN_MANIFEST_JSON).expect("manifest parses");
        fixture.cases.push(FixtureCase {
            case_id: "beam_small_budget_smoke".to_owned(),
            query: "BEAM deterministic context pack".to_owned(),
            limit: 5,
            token_budget: 4096,
            expected_min_results: 1,
        });
        manifest.case_ids = vec!["beam_small_budget_smoke".to_owned()];

        let err = ensure_manifest_selects_128k_case(&manifest, &fixture)
            .expect_err("manifest must select a 128K case");
        assert!(
            err.to_string()
                .contains("built-in BEAM smoke manifest must select a 128K token-budget case")
        );
    }

    #[test]
    fn beam_help_references_arch_0042() {
        assert!(BEAM_HELP.contains("ONEIRON-ARCH-0042"));
    }

    #[test]
    fn agentic_and_chat_arms_return_explicit_not_ready_states() {
        let report = run_builtin_smoke().expect("BEAM smoke report");
        for kind in [ArmKind::Agentic, ArmKind::Chat] {
            let arm = find_arm(&report, kind);
            let ArmOutcome::NotReady { not_ready } = &arm.outcome else {
                panic!("{} arm should be not-ready", kind.as_str());
            };
            assert_eq!(
                not_ready.reason,
                "adapter intentionally not implemented in EVAL-001 scaffold"
            );
        }
    }

    fn find_arm(report: &BeamReport, kind: ArmKind) -> &ArmReport {
        report.cases[0]
            .arms
            .iter()
            .find(|arm| arm.arm == kind)
            .expect("arm report exists")
    }
}
