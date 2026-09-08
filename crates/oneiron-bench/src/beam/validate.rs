//! Fixture and manifest validators.

use super::judge::{JUDGE_VOTE_COUNT, single_judge_vote};
use super::model::{
    ArmKind, BeamFixture, CompetitorCardConfig, DatasetSource, FixtureCase, FixtureClass,
    FixtureRecord, FixtureTimeRange, OpposingEvidence, PublicParityStatus, RunManifest,
};
use super::ppr_vad::validate_ppr_vad_fixture;
use super::report::validate_cost_component;
use super::report_model::TokenAccountingSource;
use super::util::{invalid_fixture, invalid_manifest};
use super::{BEAM_COMPARATOR_VERSION, BeamError, BeamResult, SCHEMA_VERSION};
use oneiron::EntityId;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::Path;
use std::path::PathBuf;

pub(super) fn validate_fixture(fixture: &BeamFixture) -> BeamResult<()> {
    if fixture.schema_version != SCHEMA_VERSION {
        return Err(BeamError::UnsupportedSchemaVersion {
            expected: SCHEMA_VERSION,
            actual: fixture.schema_version,
        });
    }
    if fixture.cases.is_empty() {
        return Err(invalid_fixture(
            fixture,
            "fixture must contain at least one case",
        ));
    }
    if fixture.records.is_empty()
        && !fixture
            .cases
            .iter()
            .all(|case| case.fixture_class == FixtureClass::EmptyMemory)
    {
        return Err(invalid_fixture(
            fixture,
            "fixtures without records must use empty_memory abstention cases only",
        ));
    }

    let mut record_ids = BTreeSet::new();
    let mut records_by_id = BTreeMap::new();
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
        records_by_id.insert(record.id.as_str(), record);
    }

    let mut case_ids = BTreeSet::new();
    for case in &fixture.cases {
        if !case_ids.insert(case.case_id.as_str()) {
            return Err(invalid_fixture(fixture, "case ids must be unique"));
        }
        if case.query.trim().is_empty() {
            return Err(invalid_fixture(fixture, "case query must not be empty"));
        }
        if case.limit == 0 && case.fixture_class != FixtureClass::LowConfidence {
            return Err(invalid_fixture(fixture, "case limit must be positive"));
        }
        if case.fixture_class == FixtureClass::LowConfidence && case.limit != 0 {
            return Err(invalid_fixture(
                fixture,
                "low_confidence cases must set limit to 0",
            ));
        }
        if case.token_budget == 0 {
            return Err(invalid_fixture(
                fixture,
                "case token budget must be positive",
            ));
        }
        validate_cost_component("case offlineAmortizedCost", &case.offline_amortized_cost)
            .map_err(|reason| invalid_fixture(fixture, reason))?;
        if case.fixture_class.expects_abstention() && case.expected_min_results != 0 {
            return Err(invalid_fixture(
                fixture,
                "abstention fixture cases must set expected_min_results to 0",
            ));
        }
        if case.fixture_class == FixtureClass::EmptyMemory && !fixture.records.is_empty() {
            return Err(invalid_fixture(
                fixture,
                "empty_memory cases must not include fixture records",
            ));
        }
        if let Some(temporal_search) = &case.temporal_search
            && temporal_search.start > temporal_search.end
        {
            return Err(invalid_fixture(
                fixture,
                "case temporalSearch.start must be <= temporalSearch.end",
            ));
        }
        if case.fixture_class == FixtureClass::TemporalStaleness && case.temporal_search.is_none() {
            return Err(invalid_fixture(
                fixture,
                "temporal_staleness cases must declare temporalSearch",
            ));
        }
        if case.fixture_class == FixtureClass::TemporalStaleness {
            if case.temporal_evidence_ids.is_empty() {
                return Err(invalid_fixture(
                    fixture,
                    "temporal_staleness cases must declare temporalEvidenceIds",
                ));
            }
            let temporal_search = case
                .temporal_search
                .as_ref()
                .expect("temporal_staleness temporalSearch checked above");
            validate_temporal_evidence_ids(
                fixture,
                &records_by_id,
                temporal_search,
                &case.temporal_evidence_ids,
            )?;
            if case.temporal_evidence_ids.len() > case.limit {
                return Err(invalid_fixture(
                    fixture,
                    "temporalEvidenceIds count must be <= limit",
                ));
            }
        } else {
            if case.temporal_search.is_some() {
                return Err(invalid_fixture(
                    fixture,
                    "temporalSearch is only valid for temporal_staleness cases",
                ));
            }
            if !case.temporal_evidence_ids.is_empty() {
                return Err(invalid_fixture(
                    fixture,
                    "temporalEvidenceIds are only valid for temporal_staleness cases",
                ));
            }
        }
        if case.fixture_class == FixtureClass::AdversarialContradiction {
            let opposing_evidence = case.opposing_evidence.as_ref().ok_or_else(|| {
                invalid_fixture(
                    fixture,
                    "adversarial_contradiction cases must declare opposingEvidence",
                )
            })?;
            validate_opposing_evidence(fixture, &records_by_id, opposing_evidence)?;
            if opposing_evidence.record_ids.len() > case.limit {
                return Err(invalid_fixture(
                    fixture,
                    "opposingEvidence.recordIds count must be <= limit",
                ));
            }
        } else if case.opposing_evidence.is_some() {
            return Err(invalid_fixture(
                fixture,
                "opposingEvidence is only valid for adversarial_contradiction cases",
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
pub(super) fn validate_temporal_evidence_ids(
    fixture: &BeamFixture,
    records_by_id: &BTreeMap<&str, &FixtureRecord>,
    temporal_search: &FixtureTimeRange,
    temporal_evidence_ids: &[String],
) -> BeamResult<()> {
    let mut ids = BTreeSet::new();
    for id in temporal_evidence_ids {
        if !ids.insert(id.as_str()) {
            return Err(invalid_fixture(
                fixture,
                "temporalEvidenceIds must be unique",
            ));
        }
        let record = records_by_id.get(id.as_str()).ok_or_else(|| {
            invalid_fixture(
                fixture,
                "temporalEvidenceIds must reference fixture records",
            )
        })?;
        if record.occurred.end < temporal_search.start
            || record.occurred.start > temporal_search.end
        {
            return Err(invalid_fixture(
                fixture,
                "temporalEvidenceIds must reference records inside temporalSearch",
            ));
        }
    }

    Ok(())
}
pub(super) fn validate_opposing_evidence(
    fixture: &BeamFixture,
    records_by_id: &BTreeMap<&str, &FixtureRecord>,
    opposing_evidence: &OpposingEvidence,
) -> BeamResult<()> {
    if opposing_evidence.field.trim().is_empty() {
        return Err(invalid_fixture(
            fixture,
            "opposingEvidence.field must not be empty",
        ));
    }
    if opposing_evidence.record_ids.len() < 2 {
        return Err(invalid_fixture(
            fixture,
            "opposingEvidence must reference at least two records",
        ));
    }

    let mut ids = BTreeSet::new();
    let mut values = BTreeSet::new();
    for id in &opposing_evidence.record_ids {
        if !ids.insert(id.as_str()) {
            return Err(invalid_fixture(
                fixture,
                "opposingEvidence.recordIds must be unique",
            ));
        }
        let record = records_by_id.get(id.as_str()).ok_or_else(|| {
            invalid_fixture(
                fixture,
                "opposingEvidence.recordIds must reference fixture records",
            )
        })?;
        let field_value = record
            .fields
            .as_object()
            .and_then(|fields| fields.get(opposing_evidence.field.as_str()))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                invalid_fixture(
                    fixture,
                    "opposingEvidence.field must reference string values on all records",
                )
            })?;
        values.insert(field_value);
    }

    if values.len() < 2 {
        return Err(invalid_fixture(
            fixture,
            "opposingEvidence must reference records with distinct field values",
        ));
    }

    Ok(())
}
pub(super) fn validate_manifest(manifest: &RunManifest) -> BeamResult<()> {
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
    if manifest.competitors.is_empty() {
        return Err(invalid_manifest(
            manifest,
            "manifest must declare at least one competitor row",
        ));
    }
    validate_manifest_dataset(manifest)?;
    if manifest.arms.contains(&ArmKind::PprVadSweep)
        && !matches!(manifest.dataset, DatasetSource::Fixture { .. })
    {
        return Err(invalid_manifest(
            manifest,
            "ppr_vad_sweep requires a fixture dataset",
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

    let mut competitor_ids = BTreeSet::new();
    let mut competitor_arms = Vec::with_capacity(manifest.competitors.len());
    for competitor in &manifest.competitors {
        if competitor.competitor_id.trim().is_empty() {
            return Err(invalid_manifest(
                manifest,
                "competitor ids must not be empty",
            ));
        }
        if !competitor_ids.insert(competitor.competitor_id.as_str()) {
            return Err(invalid_manifest(manifest, "competitor ids must be unique"));
        }
        if competitor.card.is_none() {
            return Err(BeamError::UncardedCompetitor {
                run_id: manifest.run_id.clone(),
                competitor_id: competitor.competitor_id.clone(),
            });
        }
        if let Some(card) = &competitor.card {
            validate_competitor_card(manifest, competitor.arm, card)?;
        }
        competitor_arms.push(competitor.arm);
    }
    for competitor in &manifest.competitors {
        if let Some(card) = &competitor.card
            && !competitor_ids.contains(card.comparator.baseline_competitor_id.as_str())
        {
            return Err(invalid_manifest(
                manifest,
                "competitor card baseline ids must reference a declared competitor",
            ));
        }
    }
    if competitor_arms != manifest.arms {
        return Err(invalid_manifest(
            manifest,
            "competitor row arms must match manifest arms in order",
        ));
    }

    Ok(())
}
pub(super) fn validate_manifest_dataset(manifest: &RunManifest) -> BeamResult<()> {
    if let DatasetSource::Jsonl {
        limit,
        expected_min_results,
        ..
    } = &manifest.dataset
    {
        if *limit == 0 {
            return Err(invalid_manifest(
                manifest,
                "jsonl dataset sources must set limit > 0",
            ));
        }
        if expected_min_results > limit {
            return Err(invalid_manifest(
                manifest,
                "jsonl dataset expectedMinResults must be <= limit",
            ));
        }
    }

    Ok(())
}
pub(super) fn validate_manifest_paths(manifest: &RunManifest) -> BeamResult<()> {
    let path = match &manifest.dataset {
        DatasetSource::Jsonl { path, .. }
        | DatasetSource::Fixture {
            path: Some(path), ..
        } => path,
        _ => return Ok(()),
    };
    let Some(outputs) = &manifest.outputs else {
        return Ok(());
    };

    let input = canonical_path_for_overlap(path)?;
    let output = canonical_path_for_overlap(&outputs.packs_jsonl)?;
    if input == output {
        return Err(invalid_manifest(
            manifest,
            match &manifest.dataset {
                DatasetSource::Jsonl { .. } => {
                    "outputs.packsJsonl must not resolve to the input run.jsonl path"
                }
                _ => "outputs.packsJsonl must not resolve to the input fixture path",
            },
        ));
    }

    Ok(())
}
pub(super) fn canonical_path_for_overlap(path: &Path) -> std::io::Result<PathBuf> {
    match path.canonicalize() {
        Ok(path) => Ok(path),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let parent = parent.canonicalize()?;
            Ok(path
                .file_name()
                .map_or(parent.clone(), |file_name| parent.join(file_name)))
        }
        Err(err) => Err(err),
    }
}
pub(super) fn validate_manifest_fixture_cases(
    manifest: &RunManifest,
    fixture: &BeamFixture,
) -> BeamResult<()> {
    validate_ppr_vad_fixture(manifest, fixture)?;
    let cases_by_id: BTreeMap<&str, &FixtureCase> = fixture
        .cases
        .iter()
        .map(|case| (case.case_id.as_str(), case))
        .collect();

    for case_id in &manifest.case_ids {
        if !cases_by_id.contains_key(case_id.as_str()) {
            return Err(BeamError::MissingCase {
                fixture_id: fixture.fixture_id.clone(),
                case_id: case_id.clone(),
            });
        }
    }

    Ok(())
}
pub(super) fn validate_competitor_card(
    manifest: &RunManifest,
    arm: ArmKind,
    card: &CompetitorCardConfig,
) -> BeamResult<()> {
    if matches!(manifest.dataset, DatasetSource::Fixture { .. })
        && card.public_parity_status == PublicParityStatus::PublicParity
    {
        return Err(invalid_manifest(
            manifest,
            "fixture-backed BEAM manifests cannot claim public parity",
        ));
    }
    if card.display_name.trim().is_empty() {
        return Err(invalid_manifest(
            manifest,
            "competitor card display names must not be empty",
        ));
    }
    if card.judge.judge_id.trim().is_empty() {
        return Err(invalid_manifest(
            manifest,
            "competitor card judge ids must not be empty",
        ));
    }
    if card.judge.version.trim().is_empty() {
        return Err(invalid_manifest(
            manifest,
            "competitor card judge versions must not be empty",
        ));
    }
    // EVAL-01 defines exactly two carded judge modes: the single-vote fixed scorer, whose answer
    // prompt pin stays optional, and the LLM majority vote, which must disclose the pin regardless
    // of which call path later consumes the card.
    if usize::from(card.judge.vote_count) == JUDGE_VOTE_COUNT {
        let Some(pin) = card.judge.answer_prompt.as_ref() else {
            return Err(invalid_manifest(
                manifest,
                "majority-vote competitor cards must pin the answer prompt",
            ));
        };
        if pin.content.trim().is_empty() {
            return Err(invalid_manifest(
                manifest,
                "competitor card answer prompt pins must not be empty",
            ));
        }
        if !pin.matches_exact_text(&pin.content) {
            return Err(invalid_manifest(
                manifest,
                "competitor card answer prompt sha256 must match the pinned content",
            ));
        }
    } else if usize::from(card.judge.vote_count) != usize::from(single_judge_vote()) {
        return Err(invalid_manifest(
            manifest,
            format!("competitor card judge vote counts must be 1 or {JUDGE_VOTE_COUNT}"),
        ));
    }
    let token_accounting = card.token_accounting.as_ref();
    if token_accounting
        .is_some_and(|accounting| accounting.source == TokenAccountingSource::CharCountEstimate)
    {
        return Err(invalid_manifest(
            manifest,
            "model-scored competitor rows must not use char_count_estimate token accounting",
        ));
    }
    if arm.is_completed() {
        match token_accounting {
            Some(accounting) if accounting.source == TokenAccountingSource::TokenizerCount => {}
            Some(_) => {
                return Err(invalid_manifest(
                    manifest,
                    "completed competitor rows must declare tokenizer_count tokenAccounting",
                ));
            }
            None => {
                return Err(invalid_manifest(
                    manifest,
                    "completed competitor rows must declare tokenAccounting",
                ));
            }
        }
    }
    if card.comparator.comparator_id.trim().is_empty() {
        return Err(invalid_manifest(
            manifest,
            "competitor card comparator ids must not be empty",
        ));
    }
    if card.comparator.version != BEAM_COMPARATOR_VERSION {
        return Err(invalid_manifest(
            manifest,
            format!("competitor card comparator version must be {BEAM_COMPARATOR_VERSION}"),
        ));
    }
    if card.comparator.baseline_competitor_id.trim().is_empty() {
        return Err(invalid_manifest(
            manifest,
            "competitor card baseline competitor ids must not be empty",
        ));
    }

    Ok(())
}
