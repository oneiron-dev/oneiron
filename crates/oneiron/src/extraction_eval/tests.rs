use super::*;

#[test]
fn rejects_unsupported_metric_definition_schema_version() {
    let mut definitions: Of360MetricDefinitionSet =
        serde_json::from_str(OF360_METRIC_DEFINITIONS_JSON).expect("definitions JSON");
    definitions.schema_version = OF360_SCHEMA_VERSION + 1;

    let err = validate_metric_definitions(&definitions).expect_err("unsupported schema version");
    assert!(matches!(
        err,
        Of360EvalError::UnsupportedMetricDefinitionSchemaVersion { actual }
            if actual == OF360_SCHEMA_VERSION + 1
    ));
}

#[test]
fn updating_and_qa_score_omissions_without_hiding_denominators() {
    let mut dataset = super::of360_gold_corpus().unwrap();
    dataset.cases.truncate(1);
    dataset.owner_corpus_missing = true;
    dataset.completeness = super::Of360DatasetCompleteness::SeedSubset;
    let case = &dataset.cases[0];
    let updates: Vec<_> = case
        .gold_memory_points
        .iter()
        .filter(|m| m.is_update)
        .collect();
    let claims = updates
        .iter()
        .take(2)
        .enumerate()
        .map(|(i, m)| super::Of360ExtractedClaim {
            extraction_id: format!("e{i}"),
            text: m.claim.clone(),
            matched_gold: vec![super::Of360GoldMatch {
                memory_id: m.memory_id.clone(),
                score: if i == 0 {
                    super::Of360ExtractionScore::Full
                } else {
                    super::Of360ExtractionScore::Partial
                },
            }],
            temporal_correct: Some(true),
            overreach: false,
            dedup_key: None,
        })
        .collect();
    let run = super::Of360ExtractionRun {
        schema_version: super::OF360_SCHEMA_VERSION,
        run_id: "updating-qa".into(),
        system_id: "fixture".into(),
        dataset_id: dataset.dataset_id.clone(),
        dataset_revision: dataset.revision.clone(),
        cases: vec![super::Of360CaseExtractionOutput {
            case_id: case.case_id.clone(),
            extracted_claims: claims,
            qa_answers: vec![
                super::Of360QaAnswer {
                    question_id: case.qa[0].question_id.clone(),
                    answer: "  RUI ".into(),
                },
                super::Of360QaAnswer {
                    question_id: case.qa[1].question_id.clone(),
                    answer: "night shifts".into(),
                },
            ],
        }],
    };
    let report = super::evaluate_of360_extraction(&dataset, &run).unwrap();
    assert_eq!(
        report.metrics.updating_accuracy,
        super::Of360RateMetric::new(1.5, 3.0)
    );
    assert_eq!(
        report.metrics.qa_accuracy,
        super::Of360RateMetric::new(1.0, 3.0)
    );
    assert_eq!(
        report.metrics.omission_rate,
        super::Of360RateMetric::new(8.0, 10.0)
    );
}
