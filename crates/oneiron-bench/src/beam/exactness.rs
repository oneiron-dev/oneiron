//! The exactness round-trip. Every corpus item read back from the vault must
//! equal its source bytes by sha256, and every gold evidence id must resolve
//! to exactly one ingested item. A mismatch fails the run; it never warns.
use super::load::{
    contract_corpus_entity_id, load_jsonl_group, resolve_corpus_refs, resolve_manifest_paths,
    select_run_jsonl_records, sha256_hex,
};
use super::model::DatasetSource;
use super::report_model::LoadedDataset;
use super::{BeamError, BeamResult};
use oneiron::Vault;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExactnessReport {
    /// Corpus items read back from a base vault and hashed.
    pub(super) items_checked: usize,
    /// Must be empty: items whose read-back bytes differ from the source.
    pub(super) mismatches: Vec<ExactnessMismatch>,
    pub(super) evidence_ids_checked: usize,
    /// Must be empty: gold evidence ids that resolve to no ingested item.
    pub(super) evidence_ids_unresolved: Vec<UnresolvedEvidence>,
    /// Must be empty: items the engine refused to ingest, with the reason.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) ingest_refused: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ExactnessMismatch {
    pub(super) corpus_key: String,
    pub(super) item_id: String,
    pub(super) expected_sha256: String,
    /// `None` when the vault returned no item at all.
    pub(super) actual_sha256: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UnresolvedEvidence {
    pub(super) question_id: String,
    pub(super) evidence_id: String,
}

impl ExactnessReport {
    pub(super) fn is_exact(&self) -> bool {
        self.mismatches.is_empty()
            && self.evidence_ids_unresolved.is_empty()
            && self.ingest_refused.is_empty()
    }

    pub(super) fn merge(&mut self, other: Self) {
        self.items_checked += other.items_checked;
        self.mismatches.extend(other.mismatches);
        self.evidence_ids_checked += other.evidence_ids_checked;
        self.evidence_ids_unresolved
            .extend(other.evidence_ids_unresolved);
        self.ingest_refused.extend(other.ingest_refused);
    }

    /// The run-failing form: `Err` unless every item and evidence id held.
    pub(super) fn into_result(self) -> BeamResult<Self> {
        if self.is_exact() {
            return Ok(self);
        }
        let first_item = self.mismatches.first().map(|m| {
            format!(
                " first item `{}` in `{}`: expected {}, read back {}",
                m.item_id,
                m.corpus_key,
                m.expected_sha256,
                m.actual_sha256.as_deref().unwrap_or("nothing")
            )
        });
        let first_evidence = self.evidence_ids_unresolved.first().map(|u| {
            format!(
                " first evidence id `{}` of `{}`",
                u.evidence_id, u.question_id
            )
        });
        let refused = (!self.ingest_refused.is_empty()).then(|| {
            format!(
                " {} items refused at ingest by the engine, first: {}",
                self.ingest_refused.len(),
                self.ingest_refused[0]
            )
        });
        Err(BeamError::Exactness(format!(
            "{} of {} corpus items differ from their source bytes, {} of {} evidence ids unresolved;{}{}{}",
            self.mismatches.len(),
            self.items_checked,
            self.evidence_ids_unresolved.len(),
            self.evidence_ids_checked,
            first_item.unwrap_or_default(),
            first_evidence.unwrap_or_default(),
            refused.unwrap_or_default()
        )))
    }
}

/// Reads every corpus item of `loaded` back from `vault` and resolves every
/// gold evidence id. Returns the report; [`ExactnessReport::into_result`]
/// turns any mismatch into a failure.
pub(super) fn verify_loaded_corpus(
    vault: &Vault,
    loaded: &LoadedDataset,
) -> BeamResult<ExactnessReport> {
    let mut report = ExactnessReport::default();
    let mut checked_corpora = BTreeSet::new();
    let mut ingested_ids: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    for record in loaded.contract_records.values() {
        let corpus_key = record.corpus_key();
        if !checked_corpora.insert(corpus_key.clone()) {
            continue;
        }
        let ids = ingested_ids.entry(corpus_key.clone()).or_default();
        for item in record.corpus_items() {
            let expected = item
                .source_sha256
                .clone()
                .unwrap_or_else(|| sha256_hex(item.text.as_bytes()));
            let entity_id = contract_corpus_entity_id(record, item)?;
            let actual = read_back_text(vault, &entity_id)?.map(|text| sha256_hex(text.as_bytes()));
            report.items_checked += 1;
            if actual.as_deref() == Some(expected.as_str()) {
                *ids.entry(item.id.clone()).or_default() += 1;
            } else {
                report.mismatches.push(ExactnessMismatch {
                    corpus_key: corpus_key.clone(),
                    item_id: item.id.clone(),
                    expected_sha256: expected,
                    actual_sha256: actual,
                });
            }
        }
    }
    for record in loaded.contract_records.values() {
        let Some(evidence_ids) = record.gold.as_ref().and_then(|g| g.evidence_ids.as_ref()) else {
            continue;
        };
        let ids = ingested_ids.get(&record.corpus_key());
        for evidence_id in evidence_ids {
            report.evidence_ids_checked += 1;
            let resolved = ids.and_then(|ids| ids.get(evidence_id)).copied() == Some(1);
            if !resolved {
                report.evidence_ids_unresolved.push(UnresolvedEvidence {
                    question_id: record.question_id.clone(),
                    evidence_id: evidence_id.clone(),
                });
            }
        }
    }
    Ok(report)
}

/// The `txt` field of an ingested corpus item, exactly as the vault stores it.
fn read_back_text(vault: &Vault, id: &oneiron::EntityId) -> BeamResult<Option<String>> {
    let Some(body) = vault.get(id)? else {
        return Ok(None);
    };
    let fields: serde_json::Value = rmp_serde::from_slice(&body).map_err(|error| {
        BeamError::Exactness(format!(
            "stored item {} does not decode: {error}",
            id.to_hex()
        ))
    })?;
    Ok(fields
        .get("txt")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned))
}

/// `oneiron-bench beam verify-corpus <manifest>`: ingests every selected
/// corpus into a base vault, as `beam run` would, and checks it without
/// running any arm. Every corpus is checked; any mismatch, unresolved
/// evidence id or refused item fails the command.
#[cfg(test)]
pub(super) fn run(manifest_path: &Path) -> BeamResult<ExactnessReport> {
    census(manifest_path)?.into_result()
}
/// The full report over every corpus, exact or not; the CLI prints it and
/// then fails unless it is exact.
pub(super) fn census(manifest_path: &Path) -> BeamResult<ExactnessReport> {
    let mut manifest =
        super::runner::parse_manifest_json(&std::fs::read_to_string(manifest_path)?)?;
    resolve_manifest_paths(&mut manifest, manifest_path);
    let DatasetSource::Jsonl {
        path,
        arm_id,
        limit,
        expected_min_results,
    } = &manifest.dataset
    else {
        return Err(BeamError::Exactness(
            "verify-corpus needs a run.jsonl manifest".into(),
        ));
    };
    let entries = select_run_jsonl_records(&manifest, path, arm_id.as_deref())?;
    let mut report = ExactnessReport::default();
    for (_, mut group) in super::runner::group_by_corpus(entries) {
        resolve_corpus_refs(path, &mut group)?;
        let case_ids: Vec<String> = group
            .iter()
            .map(|entry| entry.record.question_id.clone())
            .collect();
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), super::util::beam_vault_config())?;
        let corpus_key = group
            .first()
            .map(|entry| entry.record.corpus_key())
            .unwrap_or_default();
        match load_jsonl_group(
            &vault,
            &case_ids,
            path,
            group,
            *limit,
            *expected_min_results,
        ) {
            Ok(loaded) => report.merge(verify_loaded_corpus(&vault, &loaded)?),
            Err(BeamError::IngestRefused { items, .. }) => report
                .ingest_refused
                .extend(items.into_iter().map(|item| format!("{corpus_key} {item}"))),
            Err(error) => return Err(error),
        }
    }
    Ok(report)
}
