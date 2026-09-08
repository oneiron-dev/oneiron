//! Gate tests.

#[cfg(test)]
pub(crate) mod tests {
    use super::super::tests_community_eval004::tests::{
        empty_pack_stats_report, eval004_deterministic_competitor, eval004_record_json, gate_case,
        minimal_context_pack_report, minimal_context_pack_report_with_result_ids,
        minimal_context_pack_report_with_temporal_result_ids,
    };
    use super::super::*;
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;

    #[test]
    fn empty_memory_fixture_rejects_nonempty_vault() {
        let mut fixture_json: serde_json::Value =
            serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
        fixture_json["cases"][0]["expectedMinResults"] = serde_json::json!(0);
        fixture_json["cases"][0]["fixtureClass"] = serde_json::json!("empty_memory");

        let err = parse_fixture_json(&fixture_json.to_string())
            .expect_err("empty_memory cases must not carry records");

        assert!(
            err.to_string()
                .contains("empty_memory cases must not include fixture records")
        );
    }

    #[test]
    fn contradiction_fixture_requires_distinct_opposing_values() {
        let mut fixture_json: serde_json::Value =
            serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
        fixture_json["fixtureId"] = serde_json::json!("eval004-consistent-not-contradiction");
        fixture_json["records"] = serde_json::json!([
            eval004_record_json(
                "30303030303030303030303030303030",
                10,
                "Atlas launch date is March 1.",
            ),
            eval004_record_json(
                "40404040404040404040404040404040",
                11,
                "Atlas launch date is March 1.",
            ),
        ]);
        fixture_json["cases"][0]["caseId"] =
            serde_json::json!("eval004-consistent-not-contradiction");
        fixture_json["cases"][0]["query"] = serde_json::json!("What is the Atlas launch date?");
        fixture_json["cases"][0]["expectedMinResults"] = serde_json::json!(0);
        fixture_json["cases"][0]["fixtureClass"] = serde_json::json!("adversarial_contradiction");
        fixture_json["cases"][0]["opposingEvidence"] = serde_json::json!({
            "field": "txt",
            "recordIds": [
                "30303030303030303030303030303030",
                "40404040404040404040404040404040",
            ],
        });

        let err = parse_fixture_json(&fixture_json.to_string())
            .expect_err("consistent records must not validate as contradiction");

        assert!(
            err.to_string()
                .contains("opposingEvidence must reference records with distinct field values")
        );
    }

    #[test]
    fn temporal_staleness_fixture_requires_evidence_inside_temporal_search() {
        let mut fixture_json: serde_json::Value =
            serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
        fixture_json["fixtureId"] = serde_json::json!("eval004-temporal-out-of-range");
        fixture_json["records"] = serde_json::json!([eval004_record_json(
            "50505050505050505050505050505050",
            10,
            "Old Nimbus pricing was 10 credits.",
        )]);
        fixture_json["cases"][0]["caseId"] = serde_json::json!("eval004-temporal-out-of-range");
        fixture_json["cases"][0]["query"] = serde_json::json!("Nimbus pricing");
        fixture_json["cases"][0]["expectedMinResults"] = serde_json::json!(0);
        fixture_json["cases"][0]["fixtureClass"] = serde_json::json!("temporal_staleness");
        fixture_json["cases"][0]["temporalSearch"] = serde_json::json!({
            "start": 0,
            "end": 1,
        });
        fixture_json["cases"][0]["temporalEvidenceIds"] =
            serde_json::json!(["50505050505050505050505050505050"]);

        let err = parse_fixture_json(&fixture_json.to_string())
            .expect_err("temporal evidence must be inside the temporal search range");

        assert!(
            err.to_string()
                .contains("temporalEvidenceIds must reference records inside temporalSearch")
        );
    }

    #[test]
    fn fixture_rejects_temporal_search_on_non_temporal_cases() {
        let mut fixture_json: serde_json::Value =
            serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
        fixture_json["cases"][0]["temporalSearch"] = serde_json::json!({
            "start": 0,
            "end": 1,
        });

        let err = parse_fixture_json(&fixture_json.to_string())
            .expect_err("non-temporal cases must not carry temporalSearch");

        assert!(
            err.to_string()
                .contains("temporalSearch is only valid for temporal_staleness cases")
        );
    }

    #[test]
    fn low_confidence_fixture_requires_zero_publication_limit() {
        let mut fixture_json: serde_json::Value =
            serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
        fixture_json["cases"][0]["expectedMinResults"] = serde_json::json!(0);
        fixture_json["cases"][0]["fixtureClass"] = serde_json::json!("low_confidence");
        fixture_json["cases"][0]["limit"] = serde_json::json!(1);

        let err = parse_fixture_json(&fixture_json.to_string())
            .expect_err("low-confidence fixtures must publish zero results");

        assert!(
            err.to_string()
                .contains("low_confidence cases must set limit to 0")
        );
    }

    #[test]
    fn contradiction_fixture_rejects_more_required_evidence_than_limit() {
        let mut fixture_json: serde_json::Value =
            serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
        fixture_json["fixtureId"] = serde_json::json!("eval004-contradiction-over-limit");
        fixture_json["records"] = serde_json::json!([
            eval004_record_json(
                "30303030303030303030303030303030",
                10,
                "Atlas launch date is March 1.",
            ),
            eval004_record_json(
                "40404040404040404040404040404040",
                11,
                "Atlas launch date is April 1.",
            ),
        ]);
        fixture_json["cases"][0]["caseId"] = serde_json::json!("eval004-contradiction-over-limit");
        fixture_json["cases"][0]["query"] = serde_json::json!("What is the Atlas launch date?");
        fixture_json["cases"][0]["limit"] = serde_json::json!(1);
        fixture_json["cases"][0]["expectedMinResults"] = serde_json::json!(0);
        fixture_json["cases"][0]["fixtureClass"] = serde_json::json!("adversarial_contradiction");
        fixture_json["cases"][0]["opposingEvidence"] = serde_json::json!({
            "field": "txt",
            "recordIds": [
                "30303030303030303030303030303030",
                "40404040404040404040404040404040",
            ],
        });

        let err = parse_fixture_json(&fixture_json.to_string())
            .expect_err("required opposing evidence must fit within limit");

        assert!(
            err.to_string()
                .contains("opposingEvidence.recordIds count must be <= limit")
        );
    }

    #[test]
    fn temporal_fixture_rejects_more_required_evidence_than_limit() {
        let mut fixture_json: serde_json::Value =
            serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
        fixture_json["fixtureId"] = serde_json::json!("eval004-temporal-over-limit");
        fixture_json["records"] = serde_json::json!([
            eval004_record_json(
                "50505050505050505050505050505050",
                1,
                "Old Nimbus pricing was 10 credits.",
            ),
            eval004_record_json(
                "60606060606060606060606060606060",
                1,
                "Old Nimbus pricing was 12 credits.",
            ),
        ]);
        fixture_json["cases"][0]["caseId"] = serde_json::json!("eval004-temporal-over-limit");
        fixture_json["cases"][0]["query"] = serde_json::json!("Nimbus pricing");
        fixture_json["cases"][0]["limit"] = serde_json::json!(1);
        fixture_json["cases"][0]["expectedMinResults"] = serde_json::json!(0);
        fixture_json["cases"][0]["fixtureClass"] = serde_json::json!("temporal_staleness");
        fixture_json["cases"][0]["temporalSearch"] = serde_json::json!({
            "start": 0,
            "end": 1,
        });
        fixture_json["cases"][0]["temporalEvidenceIds"] = serde_json::json!([
            "50505050505050505050505050505050",
            "60606060606060606060606060606060",
        ]);

        let err = parse_fixture_json(&fixture_json.to_string())
            .expect_err("required temporal evidence must fit within limit");

        assert!(
            err.to_string()
                .contains("temporalEvidenceIds count must be <= limit")
        );
    }

    #[test]
    fn empty_memory_gate_requires_explicit_no_data_empty_report() {
        let mut context_pack = minimal_context_pack_report(0, &[], None);
        let case = gate_case(FixtureClass::EmptyMemory);

        let (passed, detail) = abstention_gate_status(&case, &context_pack);
        assert!(!passed);
        assert!(detail.contains("no empty report"));

        context_pack.empty = Some(EmptyContextReport {
            reason: "filter_matched_none".to_owned(),
            total_in_scope: 0,
            hint: "query matched no records".to_owned(),
        });
        let (passed, detail) = abstention_gate_status(&case, &context_pack);
        assert!(!passed);
        assert!(detail.contains("filter_matched_none"));

        context_pack.empty = Some(EmptyContextReport {
            reason: "no_data".to_owned(),
            total_in_scope: 1,
            hint: "records were in scope".to_owned(),
        });
        let (passed, _detail) = abstention_gate_status(&case, &context_pack);
        assert!(!passed);

        context_pack.empty = Some(EmptyContextReport {
            reason: "no_data".to_owned(),
            total_in_scope: 0,
            hint: "empty vault".to_owned(),
        });
        let (passed, _detail) = abstention_gate_status(&case, &context_pack);
        assert!(passed);
    }

    #[test]
    fn low_confidence_gate_requires_below_threshold_empty_reason() {
        let case = gate_case(FixtureClass::LowConfidence);
        let mut context_pack = minimal_context_pack_report(
            0,
            &[],
            Some(EmptyContextReport {
                reason: "no_data".to_owned(),
                total_in_scope: 0,
                hint: "no records".to_owned(),
            }),
        );

        let (passed, detail) = abstention_gate_status(&case, &context_pack);
        assert!(!passed);
        assert!(detail.contains("empty reason=no_data"));

        context_pack.empty = Some(EmptyContextReport {
            reason: "below_threshold".to_owned(),
            total_in_scope: 0,
            hint: "out-of-scope fixture".to_owned(),
        });
        let (passed, detail) = abstention_gate_status(&case, &context_pack);
        assert!(!passed);
        assert!(detail.contains("0 in-scope records"));

        context_pack.empty = Some(EmptyContextReport {
            reason: "below_threshold".to_owned(),
            total_in_scope: 1,
            hint: "below confidence threshold".to_owned(),
        });
        let (passed, detail) = abstention_gate_status(&case, &context_pack);
        assert!(passed);
        assert!(detail.contains("1 in-scope records"));
        assert!(detail.contains("empty reason=below_threshold"));
    }

    #[test]
    fn contradiction_gate_requires_declared_opposing_result_ids() {
        let case = gate_case(FixtureClass::AdversarialContradiction);
        let context_pack = minimal_context_pack_report_with_result_ids(
            &["30303030303030303030303030303030"],
            &[],
            None,
        );

        let (passed, detail) = abstention_gate_status(&case, &context_pack);
        assert!(!passed);
        assert!(detail.contains("1/2 required opposing records"));

        let context_pack = minimal_context_pack_report_with_result_ids(
            &[
                "30303030303030303030303030303030",
                "40404040404040404040404040404040",
            ],
            &[],
            None,
        );
        let (passed, detail) = abstention_gate_status(&case, &context_pack);
        assert!(passed);
        assert!(detail.contains("2/2 required opposing records"));
    }

    #[test]
    fn temporal_staleness_gate_requires_declared_temporal_result_ids() {
        let case = gate_case(FixtureClass::TemporalStaleness);
        let context_pack = minimal_context_pack_report_with_result_ids(
            &["60606060606060606060606060606060"],
            &["temporal"],
            None,
        );

        let (passed, detail) = abstention_gate_status(&case, &context_pack);
        assert!(!passed);
        assert!(detail.contains("0/1 required temporal records"));

        let context_pack = minimal_context_pack_report_with_result_ids(
            &["50505050505050505050505050505050"],
            &[],
            None,
        );
        let context_pack = minimal_context_pack_report_with_temporal_result_ids(
            context_pack,
            &["50505050505050505050505050505050"],
        );
        let (passed, detail) = abstention_gate_status(&case, &context_pack);
        assert!(!passed);
        assert!(detail.contains("temporal signal=false"));

        let context_pack = minimal_context_pack_report_with_result_ids(
            &["50505050505050505050505050505050"],
            &["temporal"],
            None,
        );
        let context_pack = minimal_context_pack_report_with_temporal_result_ids(
            context_pack,
            &["50505050505050505050505050505050"],
        );
        let (passed, detail) = abstention_gate_status(&case, &context_pack);
        assert!(passed);
        assert!(detail.contains("1/1 required temporal records"));
        assert!(detail.contains("temporal signal=true"));
    }

    #[test]
    fn temporal_staleness_gate_rejects_text_only_expected_result() {
        let case = gate_case(FixtureClass::TemporalStaleness);
        let context_pack = minimal_context_pack_report_with_result_ids(
            &["50505050505050505050505050505050"],
            &["temporal"],
            None,
        );
        let (passed, detail) = abstention_gate_status(&case, &context_pack);
        assert!(!passed);
        assert!(detail.contains("0/1 required temporal records"));
    }

    #[test]
    fn low_confidence_gate_suppresses_score_publication() {
        let case = FixtureCase {
            ppr_vad_query: None,
            case_id: "eval004-low-confidence".to_owned(),
            query: "unsupported low confidence query".to_owned(),
            limit: 0,
            token_budget: 128,
            expected_min_results: 0,
            pending_vector_count: 0,
            query_embedding: None,
            fixture_class: FixtureClass::LowConfidence,
            temporal_search: None,
            temporal_evidence_ids: Vec::new(),
            opposing_evidence: None,
            offline_amortized_cost: CostComponentInput::default(),
        };
        let context_pack = ContextPackReport {
            token_budget: case.token_budget,
            limit: case.limit,
            serialized_format: "yaml".to_owned(),
            serialized_bytes: 0,
            serialized_tokens: 0,
            tokenizer_id: oneiron::DEFAULT_CONTEXT_PACK_TOKENIZER_ID.to_owned(),
            query_cost: CostComponentReport {
                token_source: TokenAccountingSource::TokenizerCount,
                tokenizer_id: Some(oneiron::DEFAULT_CONTEXT_PACK_TOKENIZER_ID.to_owned()),
                input_tokens: 4,
                output_tokens: 0,
                target_tokens: case.token_budget as u64,
                elapsed_us: 1,
                cost_usd: 0.0,
            },
            result_count: 0,
            neighbor_count: 0,
            results: Vec::new(),
            neighbors: Vec::new(),
            stats: empty_pack_stats_report(),
            empty: Some(EmptyContextReport {
                reason: "below_threshold".to_owned(),
                total_in_scope: 1,
                hint: "fixture confidence was below publication threshold".to_owned(),
            }),
            temporal_result_ids: BTreeSet::new(),
            budgeted_text_by_entity_id: BTreeMap::new(),
        };

        let score = FixedBeamScorer.score(
            &case,
            &eval004_deterministic_competitor(),
            &ArmReport {
                arm: ArmKind::Deterministic,
                outcome: ArmOutcome::Completed {
                    context_pack: Box::new(context_pack),
                },
            },
        );

        assert!(score.overall_score.is_none());
        assert!(
            score
                .abilities
                .iter()
                .all(|ability| ability.score.is_none())
        );
        assert_eq!(
            score
                .abilities
                .iter()
                .find(|ability| ability.ability == AbilityKind::AbstentionGate)
                .expect("abstention gate ability")
                .passed,
            Some(true)
        );
    }
}
