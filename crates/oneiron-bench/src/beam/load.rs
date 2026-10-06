//! Dataset and contract loading.

use super::model::{
    ArmKind, BeamFixture, CompetitorConfig, DatasetSource, FixtureCase, FixtureClass, RunManifest,
};
use super::report_model::{
    ArmOutcome, ArmReport, ContextPackContractRecord, ContractArm, ContractCorpusRecord,
    ContractCorpusRef, ContractEmbeddingState, ContractPack, ContractPackConfig,
    ContractPackContext, ContractRecordType, ContractVector, CostComponentInput, DatasetLoadReport,
    LoadedDataset, RunContractRecord, SharedCorpus,
};
use super::util::{
    dataset_not_ready, decode_base64_standard, hash_str, hex_lower, invalid_fixture,
    invalid_manifest, invalid_run_jsonl,
};
use super::{
    BEAM_CONTRACT_EMBEDDING_DIMENSIONS, BENCH_CONTRACT_ENTITY_TYPE, BeamError, BeamResult,
    EVAL_CONTRACT_VERSION, EVAL_CONTRACT_VERSION_V2, JSONL_CONTRACT_SOURCE_KIND,
    ONEIRON_CONTEXT_PACK_ARM_KIND, SHARED_CORPUS_ENTITY_DOMAIN, VANILLA_RAG_CHUNKING,
    VANILLA_RAG_CONFIG_VERSION, VANILLA_RAG_CONTRACT_ARM_ID, VANILLA_RAG_CONTRACT_ARM_KIND,
    VANILLA_RAG_EMBEDDER_ID, VANILLA_RAG_FUSION,
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
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(super) fn load_dataset(
    vault: &Vault,
    manifest: &RunManifest,
    fixture: Option<&BeamFixture>,
) -> BeamResult<LoadedDataset> {
    let started = std::time::Instant::now();
    let mut loaded = match &manifest.dataset {
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
    }?;
    finish_offline_cost(&mut loaded, fixture, started);
    Ok(loaded)
}
/// Ingests one corpus group into `vault`, timed like [`load_dataset`].
pub(super) fn load_jsonl_group(
    vault: &Vault,
    case_ids: &[String],
    path: &Path,
    entries: Vec<RunJsonlEntry>,
    limit: usize,
    expected_min_results: usize,
) -> BeamResult<LoadedDataset> {
    let started = std::time::Instant::now();
    let mut loaded =
        ingest_run_jsonl_entries(vault, case_ids, path, entries, limit, expected_min_results)?;
    finish_offline_cost(&mut loaded, None, started);
    Ok(loaded)
}
fn finish_offline_cost(
    loaded: &mut LoadedDataset,
    fixture: Option<&BeamFixture>,
    started: std::time::Instant,
) {
    let tokens = if let Some(fixture) = fixture {
        fixture
            .records
            .iter()
            .flat_map(|record| &record.text)
            .map(|field| oneiron::count_context_pack_tokens(&field.value) as u64)
            .sum()
    } else {
        let mut counted = BTreeSet::new();
        loaded
            .contract_records
            .values()
            .filter(|record| counted.insert(record.corpus_key()))
            .flat_map(RunContractRecord::corpus_items)
            .map(|row| oneiron::count_context_pack_tokens(&row.text) as u64)
            .sum()
    };
    let total_us = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
    loaded.offline_ingest_us = total_us.saturating_sub(loaded.offline_index_build_us);
    loaded.offline = super::report_model::CostComponentReport {
        token_source: super::report_model::TokenAccountingSource::TokenizerCount,
        tokenizer_id: Some(oneiron::DEFAULT_CONTEXT_PACK_TOKENIZER_ID.into()),
        input_tokens: tokens,
        output_tokens: 0,
        target_tokens: 0,
        elapsed_us: total_us,
        cost_usd: 0.0,
    };
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
    let index_started = std::time::Instant::now();
    batch.commit()?;
    let index_us = index_started
        .elapsed()
        .as_micros()
        .min(u128::from(u64::MAX)) as u64;

    let mut query_vector_by_case_id = BTreeMap::new();
    for case in &fixture.cases {
        if let Some(embedding) = &case.query_embedding {
            let vector = decode_fixture_vector(fixture, "case queryEmbedding", embedding)?;
            query_vector_by_case_id.insert(case.case_id.clone(), vector);
        }
    }

    Ok(LoadedDataset {
        offline: super::report::not_applicable_cost(),
        offline_ingest_us: 0,
        offline_index_build_us: index_us,
        ppr_vad_fixture: None,
        report: DatasetLoadReport {
            dataset_id: fixture.fixture_id.clone(),
            source_kind: "fixture".to_owned(),
            records_loaded: fixture.records.len(),
            text_fields_indexed,
            pending_vectors: 0,
            base_vaults: 1,
            forks: 0,
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
    let mut entries = select_run_jsonl_records(manifest, path, arm_id)?;
    resolve_corpus_refs(path, &mut entries)?;
    ingest_run_jsonl_entries(
        vault,
        &manifest.case_ids,
        path,
        entries,
        limit,
        expected_min_results,
    )
}
/// The manifest's records in file order, after the engine-path checks. Shared
/// corpus files are not read here; [`resolve_corpus_refs`] reads them per group.
pub(super) fn select_run_jsonl_records(
    manifest: &RunManifest,
    path: &Path,
    arm_id: Option<&str>,
) -> BeamResult<Vec<RunJsonlEntry>> {
    let records = read_run_jsonl_records(path)?;
    let selected: BTreeSet<&str> = manifest.case_ids.iter().map(String::as_str).collect();
    let mut question_seen = BTreeSet::new();
    let mut dataset_id: Option<String> = None;
    let mut dataset_revision: Option<String> = None;
    let mut chosen = Vec::new();
    for entry in records {
        let line = entry.line;
        let record = &entry.record;
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
        if !question_seen.insert(record.question_id.clone()) {
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
        chosen.push(entry);
    }
    for case_id in &manifest.case_ids {
        if !question_seen.contains(case_id) {
            return Err(BeamError::MissingCase {
                fixture_id: dataset_id
                    .as_deref()
                    .map_or_else(|| path.display().to_string(), str::to_owned),
                case_id: case_id.clone(),
            });
        }
    }
    Ok(chosen)
}
/// Reads every `corpus_ref` these entries name, once per corpus id, and
/// refuses on any sha256 mismatch. v2 records need hashed corpus items.
pub(super) fn resolve_corpus_refs(path: &Path, entries: &mut [RunJsonlEntry]) -> BeamResult<()> {
    let mut corpora: BTreeMap<String, Arc<SharedCorpus>> = BTreeMap::new();
    for entry in entries.iter_mut() {
        let Some(corpus_ref) = entry.record.corpus_ref.clone() else {
            continue;
        };
        let shared = match corpora.get(&corpus_ref.corpus_id) {
            Some(shared) => Arc::clone(shared),
            None => {
                let shared = Arc::new(load_shared_corpus(path, entry.line, &corpus_ref)?);
                corpora.insert(corpus_ref.corpus_id.clone(), Arc::clone(&shared));
                shared
            }
        };
        if entry.record.is_v2()
            && let Some(item) = shared
                .items
                .iter()
                .find(|item| item.source_sha256.is_none())
        {
            return Err(invalid_run_jsonl(
                path,
                entry.line,
                format!(
                    "contract v2 corpus `{}` item `{}` lacks source_sha256",
                    shared.corpus_ref.corpus_id, item.id
                ),
            ));
        }
        entry.record.shared_corpus = Some(shared);
    }
    Ok(())
}
/// Reads, validates and resolves every record of a run.jsonl.
#[cfg(test)]
pub(super) fn read_and_resolve_run_jsonl(path: &Path) -> BeamResult<Vec<RunJsonlEntry>> {
    let mut entries = read_run_jsonl_records(path)?;
    resolve_corpus_refs(path, &mut entries)?;
    Ok(entries)
}
/// Ingests already selected and resolved records into one vault. A shared
/// corpus is written once however many questions read it.
pub(super) fn ingest_run_jsonl_entries(
    vault: &Vault,
    case_ids: &[String],
    path: &Path,
    entries: Vec<RunJsonlEntry>,
    limit: usize,
    expected_min_results: usize,
) -> BeamResult<LoadedDataset> {
    let mut contract_records = BTreeMap::new();
    let mut source_id_by_entity_id = BTreeMap::new();
    let mut query_vector_by_case_id = BTreeMap::new();
    let mut seen_corpus = BTreeSet::new();
    let mut cases = Vec::with_capacity(case_ids.len());
    let mut case_seen = BTreeSet::new();
    let mut batch = vault.batch();
    let dataset_id = entries.first().map(|entry| entry.record.dataset.id.clone());
    let dataset_revision = entries
        .first()
        .map(|entry| entry.record.dataset.revision.clone());
    let mut records_loaded = 0;
    let mut text_fields_indexed = 0;
    let mut pending_vectors_total = 0;

    for entry in entries {
        let line = entry.line;
        let record = entry.record;
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
        let mut recorded_at = 0_u64;
        let corpus_key = record.corpus_key();
        for item in record.corpus_items() {
            let entity_id = contract_corpus_entity_id(&record, item)?;
            let entity_hex = entity_id.to_hex();
            source_id_by_entity_id.insert(entity_hex.clone(), item.id.clone());
            if !seen_corpus.insert((corpus_key.clone(), item.id.clone())) {
                if let Some(ContractEmbeddingState::Pending { .. }) = &item.embedding {
                    pending_for_case += 1;
                }
                continue;
            }
            let occurred_at = super::corpus_clock::occurred_at(item, path, line)?;
            recorded_at = recorded_at.saturating_add(1).max(occurred_at);
            let fields = contract_corpus_fields(item);
            let payload = rmp_serde::to_vec_named(&fields)?;
            batch = batch
                .put(
                    &entity_id,
                    BENCH_CONTRACT_ENTITY_TYPE,
                    TimeRange {
                        start: occurred_at,
                        end: occurred_at,
                    },
                    recorded_at,
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
                question_time: record.question_time,
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

    let index_started = std::time::Instant::now();
    batch.commit()?;
    // Optional corpus-authored statements are inputs, never gold or extracted
    // judge labels. Materialize through the ordinary claim door after sources.
    let mut stated_corpora = BTreeSet::new();
    for record in contract_records.values() {
        if !stated_corpora.insert(record.corpus_key()) {
            continue;
        }
        for item in record.corpus_items() {
            if let Some(predicate) = item
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.get("stated_claim_predicate"))
            {
                use sha2::{Digest, Sha256};
                let predicate = predicate
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| {
                        invalid_run_jsonl(path, 0, "stated_claim_predicate must be a string")
                    })?;
                let subject = contract_corpus_entity_id(record, item)?;
                let learned = vault.get_learned_at(&subject)?;
                let mut body = oneiron::ClaimBody::new(
                    predicate,
                    oneiron::ClaimSubject::Entity(subject),
                    rmpv::Value::from(item.text.clone()),
                    1.0,
                    oneiron::ClaimApprovalStatus::Auto,
                    oneiron::ClaimLifecycleStatus::Active,
                )?;
                body.source = Some(oneiron::ClaimSource::Observed);
                body.evidence = Some(rmpv::Value::Array(vec![rmpv::Value::Binary(
                    subject.as_bytes().to_vec(),
                )]));
                let digest = Sha256::digest(format!(
                    "oneiron:bench-corpus-statement:v1:{}",
                    subject.to_hex()
                ));
                let mut raw = [0_u8; 16];
                raw.copy_from_slice(&digest[..16]);
                let id = oneiron::EntityId::from_bytes(raw)?;
                let occurred = super::corpus_clock::occurred_at(item, path, 0)?;
                vault.put_claim(
                    &id,
                    &body,
                    TimeRange {
                        start: occurred,
                        end: occurred,
                    },
                    learned,
                )?;
                source_id_by_entity_id.insert(id.to_hex(), item.id.clone());
                records_loaded += 1;
            }
        }
    }

    let index_us = index_started
        .elapsed()
        .as_micros()
        .min(u128::from(u64::MAX)) as u64;
    for case_id in case_ids {
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
        offline: super::report::not_applicable_cost(),
        offline_ingest_us: 0,
        offline_index_build_us: index_us,
        ppr_vad_fixture: None,
        report: DatasetLoadReport {
            dataset_id: dataset_id.clone(),
            source_kind: JSONL_CONTRACT_SOURCE_KIND.to_owned(),
            records_loaded,
            text_fields_indexed,
            pending_vectors: pending_vectors_total,
            base_vaults: 1,
            forks: 0,
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
    let mut corpus_refs: BTreeMap<String, ContractCorpusRef> = BTreeMap::new();
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line_number = index + 1;
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let record: RunContractRecord = serde_json::from_str(&line)
            .map_err(|source| invalid_run_jsonl(path, line_number, source.to_string()))?;
        validate_run_contract_record_at(path, line_number, &record)?;
        if let Some(corpus_ref) = &record.corpus_ref {
            match corpus_refs.get(&corpus_ref.corpus_id) {
                Some(earlier) if earlier != corpus_ref => {
                    return Err(invalid_run_jsonl(
                        path,
                        line_number,
                        format!(
                            "corpus_ref `{}` names a different path or sha256 than an earlier record",
                            corpus_ref.corpus_id
                        ),
                    ));
                }
                Some(_) => {}
                None => {
                    corpus_refs.insert(corpus_ref.corpus_id.clone(), corpus_ref.clone());
                }
            }
        }
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
    if record.contract_version != EVAL_CONTRACT_VERSION
        && record.contract_version != EVAL_CONTRACT_VERSION_V2
    {
        return Err(invalid_run_jsonl(
            path,
            line,
            format!(
                "contract_version must be `{EVAL_CONTRACT_VERSION}` or `{EVAL_CONTRACT_VERSION_V2}`, got `{}`",
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
    match &record.corpus_ref {
        Some(corpus_ref) => {
            if !record.corpus.is_empty() {
                return Err(invalid_run_jsonl(
                    path,
                    line,
                    "a record carries either an inline corpus or a corpus_ref, never both",
                ));
            }
            validate_corpus_ref(path, line, corpus_ref)?;
        }
        None => {
            if record.corpus.is_empty() {
                return Err(invalid_run_jsonl(path, line, "corpus must not be empty"));
            }
            validate_corpus_items(path, line, &record.corpus, record.is_v2())?;
        }
    }
    validate_v2_fields(path, line, record)?;
    super::split::recheck_split(path, line, record)
}
/// v2 fields are optional on read for a v1 record and checked when present;
/// a v2 record must carry every one of them.
fn validate_v2_fields(path: &Path, line: usize, record: &RunContractRecord) -> BeamResult<()> {
    let v2 = record.is_v2();
    let missing = |field: &str| {
        invalid_run_jsonl(
            path,
            line,
            format!("contract v2 record must carry `{field}`"),
        )
    };
    if v2 && record.question_time.is_none() {
        return Err(missing("question_time"));
    }
    if v2 && record.split.is_none() {
        return Err(missing("split"));
    }
    match &record.cleaning {
        Some(cleaning) => {
            if cleaning.manifest_id.trim().is_empty() || !is_sha256_hex(&cleaning.sha256) {
                return Err(invalid_run_jsonl(
                    path,
                    line,
                    "cleaning needs a manifest_id and a lowercase hex sha256",
                ));
            }
        }
        None if v2 => return Err(missing("cleaning")),
        None => {}
    }
    match &record.gold {
        Some(gold) => {
            if v2 && gold.evidence_ids.is_none() {
                return Err(missing("gold.evidence_ids"));
            }
            if v2 && gold.pool.is_none() {
                return Err(missing("gold.pool"));
            }
            if let Some(ids) = &gold.evidence_ids {
                let mut seen = BTreeSet::new();
                if ids
                    .iter()
                    .any(|id| id.trim().is_empty() || !seen.insert(id))
                {
                    return Err(invalid_run_jsonl(
                        path,
                        line,
                        "gold.evidence_ids must be unique non-empty source ids",
                    ));
                }
            }
            if let Some(pool) = &gold.pool
                && pool.iter().any(|entry| entry.text.trim().is_empty())
            {
                return Err(invalid_run_jsonl(
                    path,
                    line,
                    "gold.pool entries must carry non-empty text",
                ));
            }
            if let Some(keys) = &gold.answer_keys
                && keys.keys().any(|key| key.trim().is_empty())
            {
                return Err(invalid_run_jsonl(
                    path,
                    line,
                    "gold.answer_keys names must not be empty",
                ));
            }
        }
        None if v2 => return Err(missing("gold")),
        None => {}
    }
    if v2 && record.corpus_ref.is_none() && record.corpus.is_empty() {
        return Err(missing("corpus_ref"));
    }
    Ok(())
}
fn validate_corpus_ref(path: &Path, line: usize, corpus_ref: &ContractCorpusRef) -> BeamResult<()> {
    if corpus_ref.corpus_id.trim().is_empty()
        || corpus_ref.path.as_os_str().is_empty()
        || !is_sha256_hex(&corpus_ref.sha256)
    {
        return Err(invalid_run_jsonl(
            path,
            line,
            "corpus_ref needs a corpus_id, a path and a lowercase hex sha256",
        ));
    }
    Ok(())
}
fn validate_corpus_items(
    path: &Path,
    line: usize,
    items: &[ContractCorpusRecord],
    require_source_sha256: bool,
) -> BeamResult<()> {
    let mut corpus_ids = BTreeSet::new();
    for item in items {
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
        match &item.source_sha256 {
            Some(expected) => {
                let actual = sha256_hex(item.text.as_bytes());
                if !is_sha256_hex(expected) || expected != &actual {
                    return Err(invalid_run_jsonl(
                        path,
                        line,
                        format!(
                            "corpus item `{}` source_sha256 `{expected}` does not match its text ({actual})",
                            item.id
                        ),
                    ));
                }
            }
            None if require_source_sha256 => {
                return Err(invalid_run_jsonl(
                    path,
                    line,
                    format!("contract v2 corpus item `{}` lacks source_sha256", item.id),
                ));
            }
            None => {}
        }
    }
    Ok(())
}
/// Reads a `corpus_ref` file relative to the run.jsonl directory. The file's
/// sha256 must equal the reference before a single item is parsed.
pub(super) fn load_shared_corpus(
    run_path: &Path,
    line: usize,
    corpus_ref: &ContractCorpusRef,
) -> BeamResult<SharedCorpus> {
    let resolved = resolve_corpus_path(run_path, &corpus_ref.path);
    let bytes = std::fs::read(&resolved).map_err(|error| {
        invalid_run_jsonl(
            run_path,
            line,
            format!(
                "corpus_ref `{}` file {}: {error}",
                corpus_ref.corpus_id,
                resolved.display()
            ),
        )
    })?;
    let actual = sha256_hex(&bytes);
    if actual != corpus_ref.sha256 {
        return Err(invalid_run_jsonl(
            run_path,
            line,
            format!(
                "corpus_ref `{}` sha256 mismatch: expected {}, file {} hashes to {actual}",
                corpus_ref.corpus_id,
                corpus_ref.sha256,
                resolved.display()
            ),
        ));
    }
    let text = std::str::from_utf8(&bytes).map_err(|error| {
        invalid_run_jsonl(
            run_path,
            line,
            format!(
                "corpus_ref `{}` is not UTF-8: {error}",
                corpus_ref.corpus_id
            ),
        )
    })?;
    let mut items = Vec::new();
    for (index, row) in text.lines().enumerate() {
        if row.trim().is_empty() {
            continue;
        }
        let item: ContractCorpusRecord = serde_json::from_str(row).map_err(|error| {
            invalid_run_jsonl(
                run_path,
                line,
                format!(
                    "corpus_ref `{}` line {}: {error}",
                    corpus_ref.corpus_id,
                    index + 1
                ),
            )
        })?;
        items.push(item);
    }
    if items.is_empty() {
        return Err(invalid_run_jsonl(
            run_path,
            line,
            format!("corpus_ref `{}` holds no items", corpus_ref.corpus_id),
        ));
    }
    validate_corpus_items(run_path, line, &items, false)?;
    Ok(SharedCorpus {
        corpus_ref: corpus_ref.clone(),
        items,
    })
}
pub(super) fn resolve_corpus_path(run_path: &Path, corpus_path: &Path) -> PathBuf {
    if corpus_path.is_absolute() {
        return corpus_path.to_path_buf();
    }
    run_path
        .parent()
        .map_or_else(|| corpus_path.to_path_buf(), |base| base.join(corpus_path))
}
pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}
pub(super) fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn contract_corpus_entity_id(
    record: &RunContractRecord,
    item: &ContractCorpusRecord,
) -> BeamResult<EntityId> {
    let mut hasher = Sha256::new();
    if let Some(corpus_ref) = &record.corpus_ref {
        // Shared corpus: every question on this corpus sees the same ids.
        hash_str(&mut hasher, SHARED_CORPUS_ENTITY_DOMAIN);
        hash_str(&mut hasher, &corpus_ref.corpus_id);
    } else {
        hash_str(&mut hasher, EVAL_CONTRACT_VERSION);
        hash_str(&mut hasher, &record.run_id);
        hash_str(&mut hasher, &record.question_id);
    }
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
        contract_version: if record.is_v2() {
            EVAL_CONTRACT_VERSION_V2
        } else {
            EVAL_CONTRACT_VERSION
        },
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
        question_time: record.question_time,
        corpus_ref: record.corpus_ref.clone(),
        split: record.split,
        cleaning: record.cleaning.clone(),
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
    if let Some(corpus_ref) = &record.corpus_ref {
        // The file sha256 was verified at load and commits to every byte.
        hash_str(&mut hasher, &corpus_ref.corpus_id);
        hash_str(&mut hasher, &corpus_ref.sha256);
    } else {
        for item in &record.corpus {
            hash_str(&mut hasher, &item.id);
            hash_str(&mut hasher, &item.text);
        }
    }
    format!("sha256:{}", hex_lower(&hasher.finalize()))
}
