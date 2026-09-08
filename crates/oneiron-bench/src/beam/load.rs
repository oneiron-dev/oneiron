//! Dataset and contract loading.

use super::model::{
    ArmKind, BeamFixture, CompetitorConfig, DatasetSource, FixtureCase, FixtureClass, RunManifest,
};
use super::report_model::{
    ArmOutcome, ArmReport, ContextPackContractRecord, ContractArm, ContractCorpusRecord,
    ContractEmbeddingState, ContractPack, ContractPackConfig, ContractPackContext,
    ContractRecordType, ContractVector, CostComponentInput, DatasetLoadReport, LoadedDataset,
    RunContractRecord,
};
use super::util::{
    dataset_not_ready, decode_base64_standard, hash_str, hex_lower, invalid_fixture,
    invalid_manifest, invalid_run_jsonl,
};
use super::{
    BEAM_CONTRACT_EMBEDDING_DIMENSIONS, BENCH_CONTRACT_ENTITY_TYPE, BeamError, BeamResult,
    EVAL_CONTRACT_VERSION, JSONL_CONTRACT_SOURCE_KIND, ONEIRON_CONTEXT_PACK_ARM_KIND,
    VANILLA_RAG_CHUNKING, VANILLA_RAG_CONFIG_VERSION, VANILLA_RAG_CONTRACT_ARM_ID,
    VANILLA_RAG_CONTRACT_ARM_KIND, VANILLA_RAG_EMBEDDER_ID, VANILLA_RAG_FUSION,
};
use oneiron::{EntityId, TimeRange, Vault};
use sha2::Digest;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::path::Path;

pub(super) fn load_dataset(
    vault: &Vault,
    manifest: &RunManifest,
    fixture: Option<&BeamFixture>,
) -> BeamResult<LoadedDataset> {
    match &manifest.dataset {
        DatasetSource::Fixture { fixture_id, .. } => {
            let Some(fixture) = fixture else {
                return Err(invalid_manifest(
                    manifest,
                    "fixture-backed manifests require a fixture document",
                ));
            };
            if fixture_id != &fixture.fixture_id {
                return Err(BeamError::FixtureMismatch {
                    fixture_id: fixture.fixture_id.clone(),
                    manifest_fixture_id: fixture_id.clone(),
                });
            }
            load_fixture_dataset(vault, fixture)
        }
        DatasetSource::Jsonl {
            path,
            arm_id,
            limit,
            expected_min_results,
        } => load_run_jsonl_dataset(
            vault,
            manifest,
            path,
            arm_id.as_deref(),
            *limit,
            *expected_min_results,
        ),
        source => Err(BeamError::DatasetNotReady(dataset_not_ready(source))),
    }
}
pub(super) fn load_fixture_dataset(
    vault: &Vault,
    fixture: &BeamFixture,
) -> BeamResult<LoadedDataset> {
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
        if let Some(embedding) = &record.embedding {
            let vector = decode_fixture_vector(fixture, "record embedding", embedding)?;
            batch = batch.vector(&id, &vector);
        }
    }
    batch.commit()?;

    let mut query_vector_by_case_id = BTreeMap::new();
    for case in &fixture.cases {
        if let Some(embedding) = &case.query_embedding {
            let vector = decode_fixture_vector(fixture, "case queryEmbedding", embedding)?;
            query_vector_by_case_id.insert(case.case_id.clone(), vector);
        }
    }

    Ok(LoadedDataset {
        ppr_vad_fixture: None,
        report: DatasetLoadReport {
            dataset_id: fixture.fixture_id.clone(),
            source_kind: "fixture".to_owned(),
            records_loaded: fixture.records.len(),
            text_fields_indexed,
            pending_vectors: 0,
        },
        fixture_id: fixture.fixture_id.clone(),
        fixture_description: fixture.description.clone(),
        cases: fixture.cases.clone(),
        contract_records: BTreeMap::new(),
        source_id_by_entity_id: BTreeMap::new(),
        query_vector_by_case_id,
    })
}
pub(super) fn load_run_jsonl_dataset(
    vault: &Vault,
    manifest: &RunManifest,
    path: &Path,
    arm_id: Option<&str>,
    limit: usize,
    expected_min_results: usize,
) -> BeamResult<LoadedDataset> {
    let records = read_run_jsonl_records(path)?;
    let selected: BTreeSet<&str> = manifest.case_ids.iter().map(String::as_str).collect();
    let mut contract_records = BTreeMap::new();
    let mut source_id_by_entity_id = BTreeMap::new();
    let mut query_vector_by_case_id = BTreeMap::new();
    let mut seen_corpus = BTreeSet::new();
    let mut cases = Vec::with_capacity(manifest.case_ids.len());
    let mut case_seen = BTreeSet::new();
    let mut batch = vault.batch();
    let mut dataset_id: Option<String> = None;
    let mut dataset_revision: Option<String> = None;
    let mut records_loaded = 0;
    let mut text_fields_indexed = 0;
    let mut pending_vectors_total = 0;

    for entry in records {
        let line = entry.line;
        let record = entry.record;
        if !selected.contains(record.question_id.as_str()) {
            continue;
        }
        if let Some(arm_id) = arm_id
            && record.arm.id != arm_id
        {
            continue;
        }
        if record.run_id != manifest.run_id {
            return Err(invalid_run_jsonl(
                path,
                line,
                format!(
                    "selected record run_id `{}` does not match manifest runId `{}`",
                    record.run_id, manifest.run_id
                ),
            ));
        }
        if record.arm.kind != ONEIRON_CONTEXT_PACK_ARM_KIND {
            return Err(invalid_run_jsonl(
                path,
                line,
                format!(
                    "selected record arm.kind `{}` is not supported by this engine path; expected `{ONEIRON_CONTEXT_PACK_ARM_KIND}`",
                    record.arm.kind
                ),
            ));
        }
        if record.budget.currency != "tokens" {
            return Err(invalid_run_jsonl(
                path,
                line,
                format!(
                    "selected record budget.currency `{}` is not supported by this engine path; expected `tokens`",
                    record.budget.currency
                ),
            ));
        }
        match (&dataset_id, &dataset_revision) {
            (None, None) => {
                dataset_id = Some(record.dataset.id.clone());
                dataset_revision = Some(record.dataset.revision.clone());
            }
            (Some(id), Some(revision))
                if id == &record.dataset.id && revision == &record.dataset.revision => {}
            _ => {
                return Err(invalid_run_jsonl(
                    path,
                    line,
                    "selected records must share one dataset id and revision",
                ));
            }
        }
        if contract_records.contains_key(record.question_id.as_str()) {
            let arm_detail = arm_id.map_or_else(
                || " without dataset.armId".to_owned(),
                |id| format!(" for armId `{id}`"),
            );
            return Err(invalid_run_jsonl(
                path,
                line,
                format!(
                    "multiple selected run records found for question_id `{}`{arm_detail}; set dataset.armId to disambiguate",
                    record.question_id
                ),
            ));
        }

        let mut pending_for_case = 0;
        match &record.query_embedding {
            Some(ContractEmbeddingState::Ready(vector)) => {
                let vector = decode_contract_vector(path, line, vector)?;
                query_vector_by_case_id.insert(record.question_id.clone(), vector);
            }
            Some(ContractEmbeddingState::Pending { .. }) => {
                pending_for_case += 1;
                pending_vectors_total += 1;
            }
            None => {}
        }
        for item in &record.corpus {
            let entity_id = contract_corpus_entity_id(&record, item)?;
            let entity_hex = entity_id.to_hex();
            source_id_by_entity_id.insert(entity_hex.clone(), item.id.clone());
            if !seen_corpus.insert((record.question_id.clone(), item.id.clone())) {
                continue;
            }
            let fields = contract_corpus_fields(item);
            let payload = rmp_serde::to_vec_named(&fields)?;
            batch = batch
                .put(
                    &entity_id,
                    BENCH_CONTRACT_ENTITY_TYPE,
                    TimeRange { start: 1, end: 1 },
                    1,
                    &payload,
                )
                .text(&entity_id, &[("txt", item.text.as_str())]);
            text_fields_indexed += 1;
            records_loaded += 1;

            match &item.embedding {
                Some(ContractEmbeddingState::Ready(vector)) => {
                    let vector = decode_contract_vector(path, line, vector)?;
                    batch = batch.vector(&entity_id, &vector);
                }
                Some(ContractEmbeddingState::Pending { .. }) => {
                    pending_for_case += 1;
                    pending_vectors_total += 1;
                }
                None => {}
            }
        }

        if case_seen.insert(record.question_id.clone()) {
            cases.push(FixtureCase {
                ppr_vad_query: None,
                case_id: record.question_id.clone(),
                query: record.question.clone(),
                limit,
                token_budget: record.budget.limit,
                expected_min_results,
                pending_vector_count: pending_for_case,
                query_embedding: None,
                fixture_class: FixtureClass::EvidenceSupported,
                temporal_search: None,
                temporal_evidence_ids: Vec::new(),
                opposing_evidence: None,
                offline_amortized_cost: CostComponentInput::default(),
            });
        }
        contract_records.insert(record.question_id.clone(), record);
    }

    batch.commit()?;

    for case_id in &manifest.case_ids {
        if !case_seen.contains(case_id.as_str()) {
            return Err(BeamError::MissingCase {
                fixture_id: dataset_id
                    .as_deref()
                    .map_or_else(|| path.display().to_string(), str::to_owned),
                case_id: case_id.clone(),
            });
        }
    }

    let dataset_id = dataset_id.unwrap_or_else(|| path.display().to_string());
    let dataset_revision = dataset_revision.unwrap_or_else(|| "unknown".to_owned());
    Ok(LoadedDataset {
        ppr_vad_fixture: None,
        report: DatasetLoadReport {
            dataset_id: dataset_id.clone(),
            source_kind: JSONL_CONTRACT_SOURCE_KIND.to_owned(),
            records_loaded,
            text_fields_indexed,
            pending_vectors: pending_vectors_total,
        },
        fixture_id: dataset_id.clone(),
        fixture_description: format!("oneiron-eval run.jsonl {dataset_id}@{dataset_revision}"),
        cases,
        contract_records,
        source_id_by_entity_id,
        query_vector_by_case_id,
    })
}
pub(super) fn resolve_manifest_paths(manifest: &mut RunManifest, manifest_path: &Path) {
    let Some(base) = manifest_path.parent() else {
        return;
    };
    if let DatasetSource::Jsonl { path, .. }
    | DatasetSource::Fixture {
        path: Some(path), ..
    } = &mut manifest.dataset
        && path.is_relative()
    {
        *path = base.join(&path);
    }
    if let Some(outputs) = &mut manifest.outputs
        && outputs.packs_jsonl.is_relative()
    {
        outputs.packs_jsonl = base.join(&outputs.packs_jsonl);
    }
}
#[derive(Debug)]
pub(super) struct RunJsonlEntry {
    pub(super) line: usize,
    pub(super) record: RunContractRecord,
}
pub(super) fn read_run_jsonl_records(path: &Path) -> BeamResult<Vec<RunJsonlEntry>> {
    let file = File::open(path)?;
    let mut records = Vec::new();
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line_number = index + 1;
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let record: RunContractRecord = serde_json::from_str(&line)
            .map_err(|source| invalid_run_jsonl(path, line_number, source.to_string()))?;
        validate_run_contract_record_at(path, line_number, &record)?;
        records.push(RunJsonlEntry {
            line: line_number,
            record,
        });
    }
    if records.is_empty() {
        return Err(invalid_run_jsonl(
            path,
            0,
            "run.jsonl must contain at least one record",
        ));
    }
    Ok(records)
}
pub(super) fn validate_run_contract_record_at(
    path: &Path,
    line: usize,
    record: &RunContractRecord,
) -> BeamResult<()> {
    if record.contract_version != EVAL_CONTRACT_VERSION {
        return Err(invalid_run_jsonl(
            path,
            line,
            format!(
                "contract_version must be `{EVAL_CONTRACT_VERSION}`, got `{}`",
                record.contract_version
            ),
        ));
    }
    if !matches!(record.record_type, ContractRecordType::Run) {
        return Err(invalid_run_jsonl(path, line, "record_type must be `run`"));
    }
    if record.run_id.trim().is_empty() {
        return Err(invalid_run_jsonl(path, line, "run_id must not be empty"));
    }
    if record.question_id.trim().is_empty() {
        return Err(invalid_run_jsonl(
            path,
            line,
            "question_id must not be empty",
        ));
    }
    if record.dataset.id.trim().is_empty() || record.dataset.revision.trim().is_empty() {
        return Err(invalid_run_jsonl(
            path,
            line,
            "dataset.id and dataset.revision must not be empty",
        ));
    }
    if record.arm.id.trim().is_empty() || record.arm.kind.trim().is_empty() {
        return Err(invalid_run_jsonl(
            path,
            line,
            "arm.id and arm.kind must not be empty",
        ));
    }
    if record.budget.currency.trim().is_empty() || record.budget.limit == 0 {
        return Err(invalid_run_jsonl(
            path,
            line,
            "budget.currency must not be empty and budget.limit must be > 0",
        ));
    }
    if record.question.trim().is_empty() {
        return Err(invalid_run_jsonl(path, line, "question must not be empty"));
    }
    if record.corpus.is_empty() {
        return Err(invalid_run_jsonl(path, line, "corpus must not be empty"));
    }
    let mut corpus_ids = BTreeSet::new();
    for item in &record.corpus {
        if item.id.trim().is_empty() || item.text.trim().is_empty() {
            return Err(invalid_run_jsonl(
                path,
                line,
                "corpus items must have non-empty id and text",
            ));
        }
        if !corpus_ids.insert(item.id.as_str()) {
            return Err(invalid_run_jsonl(
                path,
                line,
                "corpus item ids must be unique per run record",
            ));
        }
    }
    Ok(())
}
pub(super) fn contract_corpus_entity_id(
    record: &RunContractRecord,
    item: &ContractCorpusRecord,
) -> BeamResult<EntityId> {
    let mut hasher = Sha256::new();
    hash_str(&mut hasher, EVAL_CONTRACT_VERSION);
    hash_str(&mut hasher, &record.run_id);
    hash_str(&mut hasher, &record.question_id);
    hash_str(&mut hasher, &item.id);
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    EntityId::from_bytes(bytes).map_err(|source| BeamError::InvalidEntityId {
        id: item.id.clone(),
        source,
    })
}
pub(super) fn contract_corpus_fields(item: &ContractCorpusRecord) -> serde_json::Value {
    let mut fields = serde_json::Map::new();
    fields.insert(
        "txt".to_owned(),
        serde_json::Value::String(item.text.clone()),
    );
    fields.insert(
        "source_id".to_owned(),
        serde_json::Value::String(item.id.clone()),
    );
    if let Some(metadata) = &item.metadata {
        fields.insert("metadata".to_owned(), metadata.clone());
    }
    serde_json::Value::Object(fields)
}
pub(super) fn decode_contract_vector(
    path: &Path,
    line: usize,
    vector: &ContractVector,
) -> BeamResult<Vec<f32>> {
    decode_contract_vector_value(vector).map_err(|reason| invalid_run_jsonl(path, line, reason))
}
pub(super) fn decode_fixture_vector(
    fixture: &BeamFixture,
    owner: &str,
    embedding: &ContractEmbeddingState,
) -> BeamResult<Vec<f32>> {
    let ContractEmbeddingState::Ready(vector) = embedding else {
        return Err(invalid_fixture(
            fixture,
            format!("{owner} must be ready before fixture ingest"),
        ));
    };

    decode_contract_vector_value(vector)
        .map_err(|reason| invalid_fixture(fixture, format!("{owner} {reason}")))
}
pub(super) fn decode_contract_vector_value(vector: &ContractVector) -> Result<Vec<f32>, String> {
    if vector.encoding != "f32-le-base64" {
        return Err(format!(
            "vector encoding must be f32-le-base64, got `{}`",
            vector.encoding
        ));
    }
    if vector.dimensions != BEAM_CONTRACT_EMBEDDING_DIMENSIONS {
        return Err(format!(
            "vector dimensions must be {BEAM_CONTRACT_EMBEDDING_DIMENSIONS} for this engine path, got {}",
            vector.dimensions
        ));
    }
    let bytes = decode_base64_standard(&vector.data)?;
    let expected_bytes = vector
        .dimensions
        .checked_mul(4)
        .ok_or_else(|| "vector dimensions overflow byte-size calculation".to_owned())?;
    if bytes.len() != expected_bytes {
        return Err(format!(
            "vector data decoded to {} bytes, expected {expected_bytes}",
            bytes.len()
        ));
    }
    Ok(bytes
        .chunks_exact(4)
        .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect())
}
pub(super) fn contract_context_pack_record(
    manifest: &RunManifest,
    loaded: &LoadedDataset,
    case: &FixtureCase,
    competitor: &CompetitorConfig,
    arm_report: &ArmReport,
) -> BeamResult<Option<ContextPackContractRecord>> {
    if manifest.outputs.is_none() || !competitor.arm.is_completed() {
        return Ok(None);
    }
    let ArmOutcome::Completed { context_pack } = &arm_report.outcome else {
        return Ok(None);
    };
    let Some(record) = loaded.contract_records.get(case.case_id.as_str()) else {
        return Ok(None);
    };

    let mut contexts =
        Vec::with_capacity(context_pack.results.len() + context_pack.neighbors.len());
    for entity in context_pack
        .results
        .iter()
        .chain(context_pack.neighbors.iter())
    {
        let source_id = loaded
            .source_id_by_entity_id
            .get(entity.id.as_str())
            .cloned()
            .unwrap_or_else(|| entity.id.clone());
        let Some(text) = context_pack
            .budgeted_text_by_entity_id
            .get(entity.id.as_str())
            .cloned()
        else {
            return Err(invalid_manifest(
                manifest,
                format!(
                    "serialized context-pack output did not include budgeted txt for entity `{}`",
                    entity.id
                ),
            ));
        };
        contexts.push(ContractPackContext {
            id: source_id.clone(),
            text,
            score: entity.score,
            source_turn_ids: vec![source_id],
        });
    }

    Ok(Some(ContextPackContractRecord {
        contract_version: EVAL_CONTRACT_VERSION,
        record_type: ContractRecordType::ContextPack,
        run_id: record.run_id.clone(),
        question_id: record.question_id.clone(),
        dataset: record.dataset.clone(),
        arm: contract_output_arm(record, competitor.arm),
        budget: record.budget.clone(),
        question: record.question.clone(),
        pack: ContractPack {
            token_count: Some(context_pack.serialized_tokens),
            corpus_digest: contract_corpus_digest(record),
            config: contract_pack_config(competitor.arm, case),
            contexts,
        },
        gold: record.gold.clone(),
    }))
}
pub(super) fn contract_output_arm(record: &RunContractRecord, arm: ArmKind) -> ContractArm {
    match arm {
        ArmKind::Deterministic => record.arm.clone(),
        ArmKind::VanillaRag => ContractArm {
            id: VANILLA_RAG_CONTRACT_ARM_ID.to_owned(),
            kind: VANILLA_RAG_CONTRACT_ARM_KIND.to_owned(),
        },
        ArmKind::PprVadSweep | ArmKind::BackboneSolo | ArmKind::Agentic | ArmKind::Chat => {
            record.arm.clone()
        }
    }
}
pub(super) fn contract_pack_config(arm: ArmKind, case: &FixtureCase) -> Option<ContractPackConfig> {
    match arm {
        ArmKind::VanillaRag => Some(ContractPackConfig {
            kind: VANILLA_RAG_CONTRACT_ARM_KIND,
            version: VANILLA_RAG_CONFIG_VERSION,
            top_k: case.limit,
            chunking: VANILLA_RAG_CHUNKING,
            fusion: VANILLA_RAG_FUSION,
            signals: vec!["vector", "bm25f"],
            embedder_id: VANILLA_RAG_EMBEDDER_ID,
            vector_dimensions: BEAM_CONTRACT_EMBEDDING_DIMENSIONS,
            token_budget_source: "run_record.budget.limit",
            structure: "flat_l0_no_claims_no_ppr_no_graph",
        }),
        ArmKind::Deterministic
        | ArmKind::PprVadSweep
        | ArmKind::BackboneSolo
        | ArmKind::Agentic
        | ArmKind::Chat => None,
    }
}
pub(super) fn write_contract_pack_rows(
    path: &Path,
    rows: &[ContextPackContractRecord],
) -> BeamResult<()> {
    let mut file = File::create(path)?;
    for row in rows {
        serde_json::to_writer(&mut file, row)?;
        file.write_all(b"\n")?;
    }
    Ok(())
}
pub(super) fn contract_corpus_digest(record: &RunContractRecord) -> String {
    let mut hasher = Sha256::new();
    hash_str(&mut hasher, EVAL_CONTRACT_VERSION);
    hash_str(&mut hasher, &record.dataset.id);
    hash_str(&mut hasher, &record.dataset.revision);
    hash_str(&mut hasher, &record.question_id);
    for item in &record.corpus {
        hash_str(&mut hasher, &item.id);
        hash_str(&mut hasher, &item.text);
    }
    format!("sha256:{}", hex_lower(&hasher.finalize()))
}
