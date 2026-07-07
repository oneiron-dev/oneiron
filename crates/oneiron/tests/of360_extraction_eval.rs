use oneiron::{
    OF360_GOLD_DATASET_ID, OF360_GOLD_DATASET_REVISION, OF360_METRIC_DEFINITION_SET_ID,
    OF360_METRIC_DEFINITION_SET_REVISION, OF360_SCHEMA_VERSION, Of360CaseExtractionOutput,
    Of360EvalError, Of360ExtractedClaim, Of360ExtractionRun, Of360ExtractionScore, Of360GoldMatch,
    Of360MetricDefinitionSet, Of360RateMetric, Of360SeededSubsetConfig, evaluate_of360_extraction,
    generate_of360_seeded_gold_subset, of360_ar3_metric_tier, of360_gold_subset,
    of360_metric_definitions,
};

#[test]
fn of360_metric_definitions_round_trip() {
    let definitions = of360_metric_definitions().expect("metric definitions");
    assert_eq!(definitions.schema_version, OF360_SCHEMA_VERSION);
    assert_eq!(definitions.set_id, OF360_METRIC_DEFINITION_SET_ID);
    assert_eq!(definitions.revision, OF360_METRIC_DEFINITION_SET_REVISION);
    assert!(
        definitions
            .derivation_envelope
            .content_hash
            .starts_with("sha256:")
    );

    let json = serde_json::to_string_pretty(&definitions).expect("serialize definitions");
    let round_trip: Of360MetricDefinitionSet =
        serde_json::from_str(&json).expect("deserialize definitions");
    assert_eq!(round_trip, definitions);

    let primary_ids: Vec<&str> = definitions
        .metrics
        .iter()
        .filter(|metric| metric.primary)
        .map(|metric| metric.metric_id.as_str())
        .collect();
    assert_eq!(
        primary_ids,
        vec![
            "faithfulness_rate",
            "hallucination_rate",
            "overreach_rate",
            "temporal_correctness",
            "redundancy_rate",
        ]
    );
}

#[test]
fn of360_harness_self_test_over_gold_subset() {
    let dataset = of360_gold_subset().expect("gold subset");
    assert_eq!(dataset.schema_version, OF360_SCHEMA_VERSION);
    assert_eq!(dataset.dataset_id, OF360_GOLD_DATASET_ID);
    assert_eq!(dataset.revision, OF360_GOLD_DATASET_REVISION);
    assert!(dataset.owner_corpus_missing);
    assert_eq!(dataset.target_full_memory_points, 500);

    let run = parsed_smoke_run();
    let report = evaluate_of360_extraction(&dataset, &run).expect("eval report");
    assert_eq!(report.metric_set_id, OF360_METRIC_DEFINITION_SET_ID);
    assert_eq!(report.cases.len(), 4);
    assert_eq!(report.warnings.len(), 1);

    assert_rate(&report.metrics.halumem_recall, 6.5, 8.0, Some(0.8125));
    assert_rate(
        &report.metrics.halumem_weighted_recall,
        6.5,
        8.0,
        Some(0.8125),
    );
    assert_rate(&report.metrics.target_precision, 8.0, 10.0, Some(0.8));
    assert_rate(&report.metrics.faithfulness_rate, 8.0, 10.0, Some(0.8));
    assert_rate(&report.metrics.hallucination_rate, 2.0, 10.0, Some(0.2));
    assert_rate(&report.metrics.overreach_rate, 2.0, 10.0, Some(0.2));
    assert_rate(&report.metrics.temporal_correctness, 3.0, 4.0, Some(0.75));
    assert_rate(&report.metrics.redundancy_rate, 1.0, 10.0, Some(0.1));
    assert_rate(
        &report.metrics.halumem_f1,
        0.806_201_550_387_596_9,
        1.0,
        Some(0.806_201_550_387_596_9),
    );

    let ar3_tier = of360_ar3_metric_tier(&dataset, &run).expect("AR-3 tier");
    assert_eq!(ar3_tier.interface_version, 1);
    assert_eq!(
        ar3_tier.metric_definitions.derivation_envelope,
        report.metric_definition_envelope
    );

    let generated = generate_of360_seeded_gold_subset(Of360SeededSubsetConfig {
        seed: 42,
        max_cases: 2,
    })
    .expect("generated subset");
    assert_eq!(generated.cases.len(), 2);
    assert!(generated.owner_corpus_missing);

    let mut missing_case_run = run;
    missing_case_run.cases.pop();
    let missing_case_report =
        evaluate_of360_extraction(&dataset, &missing_case_run).expect("missing case report");
    assert_eq!(missing_case_report.cases.len(), dataset.cases.len());
    assert_rate(
        &missing_case_report.metrics.halumem_recall,
        5.5,
        8.0,
        Some(0.6875),
    );
}

#[test]
fn of360_rejects_unsupported_gold_dataset_schema_version() {
    let mut dataset = of360_gold_subset().expect("gold subset");
    dataset.schema_version = OF360_SCHEMA_VERSION + 1;

    let err =
        evaluate_of360_extraction(&dataset, &parsed_smoke_run()).expect_err("schema rejection");
    assert!(matches!(
        err,
        Of360EvalError::UnsupportedGoldDatasetSchemaVersion { actual }
            if actual == OF360_SCHEMA_VERSION + 1
    ));
}

#[test]
fn of360_rejects_unsupported_extraction_run_schema_version() {
    let dataset = of360_gold_subset().expect("gold subset");
    let mut run = parsed_smoke_run();
    run.schema_version = OF360_SCHEMA_VERSION + 1;

    let err = evaluate_of360_extraction(&dataset, &run).expect_err("schema rejection");
    assert!(matches!(
        err,
        Of360EvalError::UnsupportedExtractionRunSchemaVersion { actual }
            if actual == OF360_SCHEMA_VERSION + 1
    ));
}

#[test]
fn of360_rejects_duplicate_gold_turn_ids() {
    let mut dataset = of360_gold_subset().expect("gold subset");
    let expected_case_id = dataset.cases[0].case_id.clone();
    let expected_turn_id = dataset.cases[0].turns[0].turn_id.clone();
    let duplicate_turn = dataset.cases[0].turns[0].clone();
    dataset.cases[0].turns.push(duplicate_turn);

    let err = evaluate_of360_extraction(&dataset, &parsed_smoke_run()).expect_err("duplicate turn");
    assert!(matches!(
        err,
        Of360EvalError::DuplicateGoldTurn { case_id, turn_id }
            if case_id == expected_case_id && turn_id == expected_turn_id
    ));
}

fn assert_rate(metric: &Of360RateMetric, numerator: f64, denominator: f64, value: Option<f64>) {
    assert_float_eq(metric.numerator, numerator);
    assert_float_eq(metric.denominator, denominator);
    match (metric.value, value) {
        (Some(actual), Some(expected)) => assert_float_eq(actual, expected),
        (None, None) => {}
        other => panic!("unexpected metric value {other:?}"),
    }
}

fn assert_float_eq(actual: f64, expected: f64) {
    let delta = (actual - expected).abs();
    assert!(
        delta <= 1e-12,
        "expected {expected}, got {actual}, delta {delta}"
    );
}

fn parsed_smoke_run() -> Of360ExtractionRun {
    Of360ExtractionRun {
        schema_version: 1,
        run_id: "of360-self-test-run".to_owned(),
        system_id: "oneiron-fixture-extractor".to_owned(),
        dataset_id: OF360_GOLD_DATASET_ID.to_owned(),
        dataset_revision: OF360_GOLD_DATASET_REVISION.to_owned(),
        cases: vec![
            Of360CaseExtractionOutput {
                case_id: "of360-seed-001-preference-temporal".to_owned(),
                extracted_claims: vec![
                    extracted(
                        "of360-seed-001-e1",
                        "User moved to Kyoto in spring 2025.",
                        &[("of360-seed-001-m1", Of360ExtractionScore::Full)],
                        Some(true),
                        false,
                        Some("kyoto-move"),
                    ),
                    extracted(
                        "of360-seed-001-e2",
                        "User prefers morning train rides.",
                        &[("of360-seed-001-m2", Of360ExtractionScore::Full)],
                        None,
                        false,
                        Some("morning-trains"),
                    ),
                    extracted(
                        "of360-seed-001-e3",
                        "User works as a rail planner.",
                        &[],
                        None,
                        true,
                        Some("rail-planner"),
                    ),
                ],
            },
            Of360CaseExtractionOutput {
                case_id: "of360-seed-002-update-window".to_owned(),
                extracted_claims: vec![
                    extracted(
                        "of360-seed-002-e1",
                        "User is pescatarian from June 2026 onward.",
                        &[("of360-seed-002-m2", Of360ExtractionScore::Full)],
                        Some(true),
                        false,
                        Some("pescatarian-current"),
                    ),
                    extracted(
                        "of360-seed-002-e2",
                        "User is vegetarian.",
                        &[("of360-seed-002-m1", Of360ExtractionScore::Partial)],
                        Some(false),
                        false,
                        Some("vegetarian-stale"),
                    ),
                ],
            },
            Of360CaseExtractionOutput {
                case_id: "of360-seed-003-relationship-event".to_owned(),
                extracted_claims: vec![
                    extracted(
                        "of360-seed-003-e1",
                        "Maya is the user's sister.",
                        &[("of360-seed-003-m1", Of360ExtractionScore::Full)],
                        None,
                        false,
                        Some("maya-sister"),
                    ),
                    extracted(
                        "of360-seed-003-e2",
                        "Maya's wedding is in Denver on 2026-09-14.",
                        &[("of360-seed-003-m2", Of360ExtractionScore::Full)],
                        Some(true),
                        false,
                        Some("maya-wedding"),
                    ),
                    extracted(
                        "of360-seed-003-e3",
                        "Maya is the user's sister.",
                        &[("of360-seed-003-m1", Of360ExtractionScore::Full)],
                        None,
                        false,
                        Some("maya-sister"),
                    ),
                ],
            },
            Of360CaseExtractionOutput {
                case_id: "of360-seed-004-rejected-suggestion".to_owned(),
                extracted_claims: vec![
                    extracted(
                        "of360-seed-004-e1",
                        "User does not use Vim.",
                        &[("of360-seed-004-m1", Of360ExtractionScore::Full)],
                        None,
                        false,
                        Some("no-vim"),
                    ),
                    extracted(
                        "of360-seed-004-e2",
                        "User prefers Vim for notes.",
                        &[],
                        None,
                        true,
                        Some("vim-preference"),
                    ),
                ],
            },
        ],
    }
}

fn extracted(
    extraction_id: &str,
    text: &str,
    matches: &[(&str, Of360ExtractionScore)],
    temporal_correct: Option<bool>,
    overreach: bool,
    dedup_key: Option<&str>,
) -> Of360ExtractedClaim {
    Of360ExtractedClaim {
        extraction_id: extraction_id.to_owned(),
        text: text.to_owned(),
        matched_gold: matches
            .iter()
            .map(|(memory_id, score)| Of360GoldMatch {
                memory_id: (*memory_id).to_owned(),
                score: *score,
            })
            .collect(),
        temporal_correct,
        overreach,
        dedup_key: dedup_key.map(str::to_owned),
    }
}
